#include "merkle.hpp"

#include <openssl/sha.h>

#include "crypto/vm/cells/CellBuilder.h"
#include "crypto/vm/cells/CellSlice.h"
#include "crypto/vm/cells/CellWithStorage.h"
#include "crypto/vm/hash-set.h"
#include "td/utils/HashMap.h"

#include "profile.hpp"

struct MyDataCell : public vm::DataCell {
	const vm::Cell::Hash* get_hashes() const { return (const vm::Cell::Hash*) get_storage(); }
	vm::Cell* const* get_refs() const { return info_.get_refs(get_storage()); }
};

static std::vector<uint8_t> storage;
struct Node {
	union {
		const uint8_t* data;
		uint32_t storage_ind;
	};
	uint32_t mask;
	uint32_t bits;
	uint32_t n_refs;
	std::array<int, 4> refs;
	bool is_special;
	bool use_storage = false;

	uint32_t get_serialized_size() const {
		return (bits + 23) >> 3;
	}

	void serialize(uint8_t* &buff) const {
		const uint32_t len = get_serialized_size();
		buff[0] = uint8_t(n_refs + 8u * is_special + 32u * mask);
		buff[1] = uint8_t(2u * (bits>>3));
		if(bits & 0b111u) ++buff[1];
		std::memcpy(buff+2, use_storage ? &storage[storage_ind] : data, len-2);
		buff += len;
	}
};
static std::vector<Node> nodes;

td::BufferSlice serialize() {
	uint32_t ref_byte_size=1, offset_byte_size=1;
	while(nodes.size() >= (1ULL << (ref_byte_size << 3))) ++ref_byte_size;
	uint64_t data_size = 0;
	for(const Node &node : nodes) data_size += node.get_serialized_size() + node.n_refs * ref_byte_size;
	while(data_size >= (1ULL << (offset_byte_size << 3))) ++offset_byte_size;
	const uint64_t total_size = 4 + 1 + 1 + 4 * ref_byte_size + offset_byte_size + data_size;
	td::BufferSlice res(total_size);
	uint8_t* buff = (uint8_t*) res.data();
	const auto store_uint = [&](uint64_t value, uint32_t bytes) {
		uint8_t* ptr = buff += bytes;
		while(bytes--) {
			*--ptr = value & 0xff;
			value >>= 8;
		}
	};
	const auto store_ref = [&](uint64_t value) { store_uint(value, ref_byte_size); };
	const auto store_offset = [&](uint64_t value) { store_uint(value, offset_byte_size); };
	store_uint(0xb5ee9c72u, 4);
	store_uint(ref_byte_size, 1);
	store_uint(offset_byte_size, 1);
	store_ref(nodes.size());
	store_ref(1);
	store_ref(0);
	store_offset(data_size);
	store_ref(0);
	for(int i = 0; i < (int) nodes.size(); ++i) {
		const Node& node = nodes[nodes.size() - 1 - i];
		node.serialize(buff);
		for(uint32_t j = 0; j < node.n_refs; ++j)
			store_ref(nodes.size() - 1 - node.refs[j]);
	}
	return res;
}

struct MerkleProofImpl {
	explicit MerkleProofImpl(vm::CellUsageTree *usage_tree, bool from=false) : usage_tree_(usage_tree), from(from) {}

	int create_from(td::Ref<vm::Cell> cell) {
		if(from) dfs_usage_tree(cell, usage_tree_->root_id());
		try {
			return dfs(cell, cell->get_level());
		} catch (vm::CellBuilder::CellWriteError &) {
			return -1;
		} catch (vm::CellBuilder::CellCreateError &) {
			return -1;
		}
	}

	vm::HashMap<int> cells_;
	vm::HashSet visited_cells_;
	vm::CellUsageTree *usage_tree_{nullptr};
	bool from;

	void dfs_usage_tree(td::Ref<vm::Cell> cell, vm::CellUsageTree::NodeId node_id) {
		if(!usage_tree_->has_mark(node_id)) return;
		visited_cells_.emplace(cell->get_hash());

		auto rlc = cell->load_cell();
		vm::Cell::LoadedCell  lc = rlc.is_ok() ? rlc.move_as_ok() : vm::Cell::LoadedCell{};
		const MyDataCell *dc = (const MyDataCell*) lc.data_cell.get();

		const uint32_t nrefs = lc.data_cell->size_refs();
		if(!nrefs) return;

		if(lc.virt.get_level() != vm::Cell::VirtualizationParameters::max_level()) {
			const vm::Cell::SpecialType type = dc->special_type();
			if(type == vm::CellTraits::SpecialType::MerkleProof || type == vm::CellTraits::SpecialType::MerkleUpdate)
				lc.virt = vm::Cell::VirtualizationParameters(lc.virt.get_level()+1, lc.virt.get_virtualization());
		}
		vm::Cell* const* refs = dc->get_refs();
		for(uint32_t i = 0; i < nrefs; ++i)
			dfs_usage_tree(refs[i]->virtualize(lc.virt), usage_tree_->get_child(node_id, i));
	}

	int dfs(td::Ref<vm::Cell> cell, uint32_t merkle_depth) {
		const vm::Cell::Hash &hash = cell->get_hash();
		auto it = cells_.find(hash);
		if(it) return *it;

		const auto prune = [&]()->int {
			if(cell->is_loaded() && !cell->get_virtualization() && !cell->load_cell().move_as_ok().data_cell->size_refs()) {
				const int ind = (int) nodes.size();
				td::Ref<vm::DataCell> data_cell = cell->load_cell().move_as_ok().data_cell;
				Node &node = nodes.emplace_back();
				node.data = data_cell->get_data();
				node.mask = data_cell->special_type() == vm::Cell::SpecialType::PrunnedBranch ? node.data[1] : 0;
				node.bits = data_cell->get_bits();
				node.n_refs = 0;
				node.is_special = data_cell->is_special();
				cells_.emplace(hash, ind);
				return ind;
			}
			const auto level_mask = cell->get_level_mask().apply(3);
			const uint32_t level = level_mask.get_level();
			if(merkle_depth < level) throw vm::CellBuilder::CellWriteError();

			const int ind = (int) nodes.size();
			Node &node = nodes.emplace_back();
			node.use_storage = true;
			node.storage_ind = (uint32_t) storage.size();
			node.mask = level_mask.apply_or(vm::Cell::LevelMask::one_level(merkle_depth + 1)).get_mask();
			node.n_refs = 0;
			node.is_special = true;
			cells_.emplace(hash, ind);

			storage.push_back(static_cast<td::uint8>(vm::Cell::SpecialType::PrunnedBranch));
			storage.push_back(static_cast<td::uint8>(node.mask));
			for(uint32_t i = 0; i <= level; ++i) if(level_mask.is_significant(i)) {
				const std::array<uint8_t, 32> &H = cell->get_hash(i).as_array();
				storage.insert(storage.end(), H.begin(), H.end());
			}
			for(uint32_t i = 0; i <= level; ++i) if(level_mask.is_significant(i)) {
				const uint16_t D = cell->get_depth(i);
				storage.push_back(uint8_t(D>>8));
				storage.push_back(D&0xffu);
			}
			node.bits = 8u * ((uint32_t) storage.size() - node.storage_ind);

			return ind;
		};

		if(from && !visited_cells_.count(hash)) return prune();

		auto rlc = cell->load_cell();
		vm::Cell::LoadedCell  lc = rlc.is_ok() ? rlc.move_as_ok() : vm::Cell::LoadedCell{};
		const MyDataCell *dc = (const MyDataCell*) lc.data_cell.get();
		const uint32_t nrefs = lc.data_cell->size_refs();

		if(!from && !lc.tree_node.empty() && lc.tree_node.mark_path(usage_tree_)) return prune();

		const vm::Cell::SpecialType type = dc->special_type();
		if(type == vm::CellTraits::SpecialType::MerkleProof || type == vm::CellTraits::SpecialType::MerkleUpdate) {
			if(merkle_depth != vm::Cell::VirtualizationParameters::max_level()) ++ merkle_depth;
			if(lc.virt.get_level() != vm::Cell::VirtualizationParameters::max_level())
				lc.virt = vm::Cell::VirtualizationParameters(lc.virt.get_level()+1, lc.virt.get_virtualization());
		}

		vm::Cell** refs = const_cast<vm::Cell**>(dc->get_refs());
		std::array<int, 4> node_refs;
		for(uint32_t i = 0; i < nrefs; ++i)
			node_refs[i] = dfs(refs[i]->virtualize(lc.virt), merkle_depth);

		const int ind = (int) nodes.size();
		Node &node = nodes.emplace_back();
		node.data = dc->get_data();
		node.mask = 0;
		switch(type) {
		case vm::Cell::SpecialType::Ordinary: {
			for(uint32_t i = 0; i < nrefs; ++i)
				node.mask |= nodes[node_refs[i]].mask;
			break;
		}
		case vm::Cell::SpecialType::PrunnedBranch:
			node.mask = node.data[1];
			break;
		case vm::Cell::SpecialType::MerkleProof:
			node.mask = nodes[node_refs[0]].mask>>1;
			break;
		case vm::Cell::SpecialType::MerkleUpdate:
			node.mask = (nodes[node_refs[0]].mask | nodes[node_refs[1]].mask)>>1;
			break;
		default:
			break;
		}
		node.bits = dc->get_bits();
		node.n_refs = nrefs;
		for(uint32_t i = 0; i < nrefs; ++i)
			node.refs[i] = node_refs[i];
		node.is_special = dc->is_special();
		cells_.emplace(hash, ind);
		return ind;
	}
};

td::Result<td::BufferSlice> merkle_update(td::Ref<vm::Cell> prev_state_root, td::Ref<vm::Cell> state_root, vm::CellUsageTree *tree) {
	PROFILER("merkle_update");

	vm::CellBuilder cb;
	cb.store_long(static_cast<td::uint8>(vm::Cell::SpecialType::MerkleUpdate), 8);
	cb.store_bytes(prev_state_root->get_hash(0).as_slice());
	cb.store_bytes(state_root->get_hash(0).as_slice());
	cb.store_long(prev_state_root->get_depth(0), vm::Cell::depth_bytes * 8);
	cb.store_long(state_root->get_depth(0), vm::Cell::depth_bytes * 8);
	cb.store_ref(prev_state_root);
	cb.store_ref(state_root);
	td::Ref<vm::DataCell> state_update = cb.finalize(true);
	if(state_update.is_null()) return td::Status::Error("failed to generate Merkle update");

	storage.clear();
	nodes.clear();

	const int update_to = MerkleProofImpl(tree).create_from(std::move(state_root));
	if(update_to == -1) return td::Status::Error("failed to generate Merkle update");
	tree->set_use_mark_for_is_loaded(true);
	const int update_from = MerkleProofImpl(tree, true).create_from(std::move(prev_state_root));
	if(update_from == -1) return td::Status::Error("failed to generate Merkle update");

	Node &node = nodes.emplace_back();
	node.data = state_update->get_data();
	node.mask = (nodes[update_from].mask | nodes[update_to].mask)>>1;
	node.bits = state_update->get_bits();
	node.n_refs = 2;
	node.refs[0] = update_from;
	node.refs[1] = update_to;
	node.is_special = true;

	return serialize();
}