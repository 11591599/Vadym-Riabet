#include "merkle.hpp"

#include "crypto/vm/cells/CellBuilder.h"
#include "crypto/vm/cells/CellSlice.h"
#include "crypto/vm/hash-set.h"
#include "td/utils/HashMap.h"

#include "profile.hpp"

static std::vector<uint8_t> serialized_data;
using rev_u8_it = std::reverse_iterator<uint8_t*>;
static void push_uint32(uint32_t x) {
	const rev_u8_it e((uint8_t*)&x);
	serialized_data.insert(serialized_data.end(), e-4, e);
} 
static void push_uint64(uint64_t x) {
	const rev_u8_it e((uint8_t*)&x);
	serialized_data.insert(serialized_data.end(), e-8, e);
} 

struct MyDataCell : public vm::DataCell {
	vm::Cell* const* get_refs() const { return info_.get_refs(get_storage()); }

	void serialize() const {
		serialized_data.push_back(info_.d1());
		serialized_data.push_back(info_.d2());
		const uint8_t *data = get_data();
		serialized_data.insert(serialized_data.end(), data, data+((get_bits() + 7) >> 3));
	}
};

struct BOC {
	struct CellInfo {
		const MyDataCell *dc_ref;
		std::array<int, 4> ref_idx;
		CellInfo(const MyDataCell *_dc): dc_ref(_dc) {}
		CellInfo(const MyDataCell *_dc, const std::array<int, 4>& _ref_list): dc_ref(_dc), ref_idx(_ref_list) {}
	};
	std::vector<CellInfo> cells;
	vm::HashMap<int> h2i;
	int num_refs = 0;
	uint64_t data_bytes = 0;

	td::Result<int> import_cell(const vm::Cell *cell, int depth) {
		if(depth > 1024) return td::Status::Error("error while importing a cell into a bag of cells: cell depth too large");
		if(!cell) return td::Status::Error("error while importing a cell into a bag of cells: cell is null");
		const vm::Cell::Hash &hash = cell->get_hash();
		int* it = h2i.find(hash);
		if(it) return *it;
		if(cell->get_virtualization()) return td::Status::Error("error while importing a cell into a bag of cells: cell has non-zero virtualization level");
		TRY_RESULT(loaded_dc, cell->load_cell());
		const MyDataCell *dc = (const MyDataCell*) loaded_dc.data_cell.get();
		data_bytes += dc->get_serialized_size();
		const uint32_t size_refs = dc->size_refs();
		int ind;
		if(size_refs) {
			num_refs += size_refs;
			std::array<int, 4> refs;
			vm::Cell* const* dc_refs = dc->get_refs();
			for(uint32_t i = 0; i < size_refs; ++i) {
				auto r = import_cell(dc_refs[i], depth+1);
				if(r.is_error()) return r.move_as_error();
				refs[i] = r.move_as_ok();
			}
			ind = (int) cells.size();
			cells.emplace_back(dc, refs);
		} else {
			ind = (int) cells.size();
			cells.emplace_back(dc);
		}
		h2i.emplace(hash, ind);
		return ind;
	}

	td::Status import_cells(const vm::Cell *r) {
		auto res = import_cell(r, 0);
		if(res.is_error()) return res.move_as_error();
		return td::Status::OK();
	}

	td::BufferSlice serialize() {
		const uint64_t data_size = data_bytes + (uint64_t)num_refs * 4;
		serialized_data.clear();
		push_uint32(0xb5ee9c72u);
		serialized_data.push_back(4);
		serialized_data.push_back(8);
		push_uint32((uint32_t) cells.size());
		push_uint32(1);
		push_uint32(0);
		push_uint64(data_size);
		push_uint32(0);
		for(int i = 0; i < (int) cells.size(); ++i) {
			const auto& dc_info = cells[cells.size() - 1 - i];
			dc_info.dc_ref->serialize();
			const uint32_t size_refs = dc_info.dc_ref->size_refs();
			for(uint32_t j = 0; j < size_refs; ++j)
				push_uint32((uint32_t) cells.size() - 1 - dc_info.ref_idx[j]);
		}
		return td::BufferSlice((char*) serialized_data.data(), serialized_data.size());
	}
};

struct MerkleProofImpl {
	explicit MerkleProofImpl(vm::CellUsageTree *usage_tree, bool from=false) : usage_tree_(usage_tree), from(from) {}

	td::Ref<vm::Cell> create_from(td::Ref<vm::Cell> cell) {
		if(from) dfs_usage_tree(cell, usage_tree_->root_id());
		try {
			return dfs(cell, cell->get_level());
		} catch (vm::CellBuilder::CellWriteError &) {
			return {};
		} catch (vm::CellBuilder::CellCreateError &) {
			return {};
		}
	}

	vm::HashMap<const vm::Cell*> cells_;
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

	td::Ref<vm::Cell> dfs(td::Ref<vm::Cell> cell, uint32_t merkle_depth) {
		const vm::Cell::Hash &hash = cell->get_hash();
		auto it = cells_.find(hash);
		if(it) return td::Ref(*it);

		const auto prune = [&]()->td::Ref<vm::Cell> {
			if(cell->is_loaded() && !cell->get_virtualization() && !cell->load_cell().move_as_ok().data_cell->size_refs()) {
				cells_.emplace(hash, cell.get());
				return cell;
			}
			const auto level_mask = cell->get_level_mask().apply(3);
			const uint32_t level = level_mask.get_level();
			if(merkle_depth < level) throw vm::CellBuilder::CellWriteError();
			vm::CellBuilder cb;
			cb.store_long(static_cast<td::uint8>(vm::Cell::SpecialType::PrunnedBranch), 8);
			cb.store_long(level_mask.apply_or(vm::Cell::LevelMask::one_level(merkle_depth + 1)).get_mask(), 8);
			for(uint32_t i = 0; i <= level; ++i) {
				if(level_mask.is_significant(i)) {
					cb.store_bytes(cell->get_hash(i).as_slice());
				}
			}
			for(uint32_t i = 0; i <= level; ++i) {
				if (level_mask.is_significant(i)) {
					cb.store_long(cell->get_depth(i), 16);
				}
			}
			auto res = cb.finalize(true);
			cells_.emplace(hash, res.get());
			return res;
		};

		if(from && !visited_cells_.count(hash)) return prune();

		auto rlc = cell->load_cell();
		vm::Cell::LoadedCell  lc = rlc.is_ok() ? rlc.move_as_ok() : vm::Cell::LoadedCell{};
		const MyDataCell *dc = (const MyDataCell*) lc.data_cell.get();
		const uint32_t nrefs = lc.data_cell->size_refs();

		if(!from && nrefs && !lc.tree_node.empty() && lc.tree_node.mark_path(usage_tree_)) return prune();

		vm::CellBuilder cb;
		cb.store_bits(dc->get_data(), dc->get_bits());

		if(nrefs) {
			const vm::Cell::SpecialType type = dc->special_type();
			if(type == vm::CellTraits::SpecialType::MerkleProof || type == vm::CellTraits::SpecialType::MerkleUpdate) {
				if(merkle_depth != vm::Cell::VirtualizationParameters::max_level()) ++ merkle_depth;
				if(lc.virt.get_level() != vm::Cell::VirtualizationParameters::max_level())
					lc.virt = vm::Cell::VirtualizationParameters(lc.virt.get_level()+1, lc.virt.get_virtualization());
			}
			vm::Cell* const* refs = dc->get_refs();
			for(uint32_t i = 0; i < nrefs; ++i)
				cb.store_ref(dfs(refs[i]->virtualize(lc.virt), merkle_depth));
		}
		
		auto res = cb.finalize(dc->is_special());
		cells_.emplace(hash, res.get());
		return res;
	}
};

td::Result<td::BufferSlice> merkle_update(td::Ref<vm::Cell> prev_state_root, td::Ref<vm::Cell> state_root, vm::CellUsageTree *tree) {
	PROFILER("merkle_update");

	td::Ref<vm::Cell> update_to = MerkleProofImpl(tree).create_from(std::move(state_root));
	if(update_to.is_null()) return td::Status::Error("failed to generate Merkle update");
	tree->set_use_mark_for_is_loaded(true);
	td::Ref<vm::Cell> update_from = MerkleProofImpl(tree, true).create_from(std::move(prev_state_root));
	if(update_from.is_null()) return td::Status::Error("failed to generate Merkle update");

	vm::CellBuilder cb;
	cb.store_long(static_cast<td::uint8>(vm::Cell::SpecialType::MerkleUpdate), 8);
	cb.store_bytes(update_from->get_hash(0).as_slice());
	cb.store_bytes(update_to->get_hash(0).as_slice());
	cb.store_long(update_from->get_depth(0), vm::Cell::depth_bytes * 8);
	cb.store_long(update_to->get_depth(0), vm::Cell::depth_bytes * 8);
	cb.store_ref(update_from);
	cb.store_ref(update_to);
	td::Ref<vm::DataCell> state_update = cb.finalize(true);
	if(state_update.is_null()) return td::Status::Error("failed to generate Merkle update");

	BOC boc;
	TRY_STATUS(boc.import_cells(state_update.get()));
	return boc.serialize();
}