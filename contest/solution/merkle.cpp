#include "merkle.hpp"

#include <openssl/sha.h>

#include "crypto/vm/cells/CellBuilder.h"
#include "crypto/vm/cells/CellSlice.h"
#include "crypto/vm/cells/CellWithStorage.h"
#include "crypto/vm/hash-set.h"
#include "td/utils/HashMap.h"

#include "profile.hpp"


struct MyDataCell : public vm::DataCell {
	using vm::DataCell::Info;

	const vm::Cell::Hash* get_hashes() const { return (const vm::Cell::Hash*) get_storage(); }
	vm::Cell* const* get_refs() const { return info_.get_refs(get_storage()); }

	int serialize(unsigned char* buff, int buff_size) const {
		int len = get_serialized_size(false);
		if(len > buff_size) return 0;
		buff[0] = static_cast<unsigned char>(info_.d1());
		buff[1] = info_.d2();
		std::memcpy(buff + 2, get_data(), len - 2);
		return len;
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
		uint32_t ref_byte_size=1, offset_byte_size=1;
		while(cells.size() >= (1ULL << (ref_byte_size << 3))) ++ref_byte_size;
		const uint64_t data_size = data_bytes + (uint64_t)num_refs * ref_byte_size;
		while(data_size >= (1ULL << (offset_byte_size << 3))) ++offset_byte_size;
		const uint64_t total_size = 4 + 1 + 1 + 3 * ref_byte_size + offset_byte_size + ref_byte_size + data_size;
		td::BufferSlice res(total_size);
		uint8_t* buff = (uint8_t*) res.data();
		const uint8_t* buff_end = buff + total_size;
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
		store_ref(cells.size());
		store_ref(1);
		store_ref(0);
		store_offset(data_size);
		store_ref(0);
		for(int i = 0; i < (int) cells.size(); ++i) {
			const auto& dc_info = cells[cells.size() - 1 - i];
			const MyDataCell *dc = dc_info.dc_ref;
			buff += dc->serialize(buff, int(buff_end - buff));
			const uint32_t size_refs = dc_info.dc_ref->size_refs();
			for(uint32_t j = 0; j < size_refs; ++j)
				store_ref((int) cells.size() - 1 - dc_info.ref_idx[j]);
		}
		return res;
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

	struct MyBuilder {
		std::array<td::Ref<vm::Cell>, 4> refs;
		uint32_t refs_cnt = 0;
		void store_ref(td::Ref<vm::Cell> ref) {
			if(ref.is_null()) throw vm::CellBuilder::CellCreateError{};
			refs[refs_cnt++] = std::move(ref);
		}
		td::Result<td::Ref<vm::DataCell>> create(const MyDataCell* dc) {
			const uint32_t bits = dc->get_bits();
			const uint8_t* data = dc->get_data();
			if(bits > 1023u) return td::Status::Error("Too many data for a cell");
			vm::Cell::SpecialType type = vm::Cell::SpecialType::Ordinary;
			if(dc->is_special()) {
				if(bits < 8) return td::Status::Error("Not enough data for a special cell");
				type = static_cast<vm::Cell::SpecialType>(data[0]);
				if(type == vm::Cell::SpecialType::Ordinary) return td::Status::Error("Special cell has Ordinary type");
			}
			vm::Cell::LevelMask level_mask;
			td::uint32 virtualization = 0;
			switch(type) {
			case vm::Cell::SpecialType::Ordinary: {
				for(uint32_t i = 0; i < refs_cnt; ++i) {
					level_mask = level_mask.apply_or(refs[i]->get_level_mask());
					virtualization = std::max(virtualization, refs[i]->get_virtualization());
				}
				break;
			}
			case vm::Cell::SpecialType::MerkleProof: {
				if(bits != 8 + (vm::Cell::hash_bytes + vm::Cell::depth_bytes) * 8) return td::Status::Error("Not enouch data for a MerkleProof special cell");
				if(refs_cnt != 1) return td::Status::Error("Wrong references count for a MerkleProof special cell");
				if(std::memcmp(data + 1, refs[0]->get_hash(0).as_array().begin(), vm::Cell::hash_bytes))
					return td::Status::Error("Hash mismatch in a MerkleProof special cell");
				const uint16_t sd = *(const uint16_t*)(data + 1 + vm::Cell::hash_bytes);
				if(uint16_t((sd>>8)|(sd<<8)) != refs[0]->get_depth(0))
					return td::Status::Error("Depth mismatch in a MerkleProof special cell");
				level_mask = refs[0]->get_level_mask().shift_right();
				virtualization = refs[0]->get_virtualization();
				break;
			}
			case vm::Cell::SpecialType::MerkleUpdate: {
				if(bits != 8 + (vm::Cell::hash_bytes + vm::Cell::depth_bytes) * 8 * 2) return td::Status::Error("Not enouch data for a MerkleUpdate special cell");
				if(refs_cnt != 2) return td::Status::Error("Wrong references count for a MerkleUpdate special cell");
				if(std::memcmp(data + 1, refs[0]->get_hash(0).as_array().begin(), vm::Cell::hash_bytes))
					return td::Status::Error("First hash mismatch in a MerkleProof special cell");
				if(std::memcmp(data + 1 + vm::Cell::hash_bytes, refs[1]->get_hash(0).as_array().begin(), vm::Cell::hash_bytes))
					return td::Status::Error("Second hash mismatch in a MerkleProof special cell");
				const uint16_t sd0 = *(const uint16_t*)(data + 1 + 2*vm::Cell::hash_bytes);
				const uint16_t sd1 = *(const uint16_t*)(data + 3 + 2*vm::Cell::hash_bytes);
				if(uint16_t((sd0>>8)|(sd0<<8)) != refs[0]->get_depth(0))
					return td::Status::Error("First depth mismatch in a MerkleProof special cell");
				if(uint16_t((sd1>>8)|(sd1<<8)) != refs[1]->get_depth(0))
					return td::Status::Error("Second depth mismatch in a MerkleProof special cell");
				level_mask = refs[0]->get_level_mask().apply_or(refs[1]->get_level_mask()).shift_right();
				virtualization = td::max(refs[0]->get_virtualization(), refs[1]->get_virtualization());
				break;
			}
			default:
				return td::Status::Error("Unknown special cell type");
			}
			MyDataCell::Info info;
			CHECK(!virtualization);
			if(td::unlikely(virtualization > vm::Cell::max_virtualization)) return td::Status::Error("Too big virtualization");
			DCHECK(level_mask.get_level() <= vm::Cell::max_level);
			const uint32_t hash_count = level_mask.get_hashes_count();
			DCHECK(hash_count <= vm::Cell::max_level + 1);
			info.bits_ = bits;
			info.refs_count_ = refs_cnt & 7;
			info.is_special_ = dc->is_special();
			info.level_mask_ = level_mask.get_mask() & 7;
			info.hash_count_ = hash_count & 7;
			info.virtualization_ = virtualization & 7;
			std::unique_ptr<vm::DataCell> data_cell = vm::detail::CellWithUniquePtrStorage<vm::DataCell>::create(info.get_storage_size(), info);

			vm::Cell::Hash* hashes_ptr = const_cast<vm::Cell::Hash*>(reinterpret_cast<MyDataCell*>(data_cell.get())->get_hashes());
			vm::Cell** refs_ptr = (vm::Cell**) (hashes_ptr + hash_count);
			uint16_t* depth_ptr = (uint16_t*) (refs_ptr + refs_cnt);
			uint8_t* data_ptr = (uint8_t*) (depth_ptr + hash_count);

			memcpy(data_ptr, data, (bits+7)>>3);
			for(uint32_t i = 0; i < refs_cnt; ++i) refs_ptr[i] = refs[i].release();
			hashes_ptr[0] = dc->get_hash(0);
			depth_ptr[0] = dc->get_depth(0);

			uint8_t tmp[2];
			tmp[1] = info.d2();
			const uint32_t level = level_mask.get_level();
			for(uint32_t level_i = 1, hash_i = 1; level_i <= level; ++level_i) {
				if(!level_mask.is_significant(level_i)) continue;
				tmp[0] = info.d1(level_mask.apply(level_i));
				#pragma GCC diagnostic push
				#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
				SHA256_CTX sha_ctx;
				SHA256_Init(&sha_ctx);
				SHA256_Update(&sha_ctx, tmp, 2);
				SHA256_Update(&sha_ctx, hashes_ptr[hash_i - 1].as_array().begin(), vm::Cell::hash_bytes);
				const uint32_t level_i_ref = (type == vm::Cell::SpecialType::MerkleProof || type == vm::Cell::SpecialType::MerkleUpdate) ? level_i + 1 : level_i;
				uint16_t depth = 0;
				uint8_t child_depth_buf[vm::Cell::max_refs * vm::Cell::depth_bytes];
				for(uint32_t i = 0; i < refs_cnt; i++) {
					const uint16_t child_depth = refs_ptr[i]->get_depth(level_i_ref);
					child_depth_buf[(i<<1)] = (uint8_t) (child_depth>>8);
					child_depth_buf[(i<<1)+1] = (uint8_t) child_depth;
					depth = std::max(depth, child_depth);
				}
				SHA256_Update(&sha_ctx, child_depth_buf, vm::Cell::depth_bytes * refs_cnt);
				if(++depth > vm::Cell::max_depth) return td::Status::Error("Depth is too big");
				depth_ptr[hash_i] = depth;
				// children hash
				for(uint32_t i = 0; i < refs_cnt; i++)
					SHA256_Update(&sha_ctx, refs_ptr[i]->get_hash(level_i_ref).as_array().begin(), vm::Cell::hash_bytes);
				SHA256_Final(const_cast<uint8_t*>(hashes_ptr[hash_i].as_array().begin()), &sha_ctx);
				#pragma GCC diagnostic pop
				++hash_i;
			}

			return td::Ref<vm::DataCell>(data_cell.release(), td::Ref<vm::DataCell>::acquire_t{});
		}

		td::Ref<vm::DataCell> finalize(const MyDataCell* dc) {
			auto res = create(dc);
			if(res.is_error()) throw vm::CellBuilder::CellWriteError{};
			return res.move_as_ok();
		}
	};

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
			for(uint32_t i = 0; i <= level; ++i) if(level_mask.is_significant(i))
				cb.store_bytes(cell->get_hash(i).as_slice());
			for(uint32_t i = 0; i <= level; ++i) if(level_mask.is_significant(i))
				cb.store_long(cell->get_depth(i), 16);
			auto res = cb.finalize(true);
			cells_.emplace(hash, res.get());
			CHECK(cell->get_hash(0) == res->get_hash(0));
			return res;
		};

		if(from && !visited_cells_.count(hash)) return prune();

		auto rlc = cell->load_cell();
		vm::Cell::LoadedCell  lc = rlc.is_ok() ? rlc.move_as_ok() : vm::Cell::LoadedCell{};
		const MyDataCell *dc = (const MyDataCell*) lc.data_cell.get();
		const uint32_t nrefs = lc.data_cell->size_refs();

		if(!nrefs) {
			cells_.emplace(hash, cell.get());
			return cell;
		}

		if(!from && !lc.tree_node.empty() && lc.tree_node.mark_path(usage_tree_)) return prune();

		const vm::Cell::SpecialType type = dc->special_type();
		if(type == vm::CellTraits::SpecialType::MerkleProof || type == vm::CellTraits::SpecialType::MerkleUpdate) {
			if(merkle_depth != vm::Cell::VirtualizationParameters::max_level()) ++ merkle_depth;
			if(lc.virt.get_level() != vm::Cell::VirtualizationParameters::max_level())
				lc.virt = vm::Cell::VirtualizationParameters(lc.virt.get_level()+1, lc.virt.get_virtualization());
		}
		vm::Cell** refs = const_cast<vm::Cell**>(dc->get_refs());

		MyBuilder cb;
		for(uint32_t i = 0; i < nrefs; ++i)
			cb.store_ref(dfs(refs[i]->virtualize(lc.virt), merkle_depth));
		auto res = cb.finalize(dc);
		cells_.emplace(hash, res.get());
		CHECK(cell->get_hash(0) == res->get_hash(0));
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