#include "merkle.hpp"

#include "crypto/vm/cells/CellBuilder.h"
#include "crypto/vm/cells/CellSlice.h"
#include "crypto/vm/hash-set.h"
#include "td/utils/HashMap.h"

#include "profile.hpp"

struct MyDataCell : public vm::DataCell {
	vm::Cell* const* get_refs() const { return info_.get_refs(get_storage()); }
};

struct BOC {
	struct CellInfo {
		td::Ref<vm::DataCell> dc_ref;
		std::array<int, 4> ref_idx;
		CellInfo(td::Ref<vm::DataCell> _dc): dc_ref(std::move(_dc)) {}
		CellInfo(td::Ref<vm::DataCell> _dc, const std::array<int, 4>& _ref_list):
			dc_ref(std::move(_dc)), ref_idx(_ref_list) {}
	};
	std::vector<CellInfo> cells;
	vm::HashMap<int> h2i;
	int num_refs = 0;
	uint64_t data_bytes = 0;
	int ref_byte_size=1, offset_byte_size=1;

	td::Result<int> import_cell(const vm::Cell *cell, int depth) {
		if(depth > 1024) return td::Status::Error("error while importing a cell into a bag of cells: cell depth too large");
		if(!cell) return td::Status::Error("error while importing a cell into a bag of cells: cell is null");
		const vm::Cell::Hash &hash = cell->get_hash();
		int* it = h2i.find(hash);
		if(it) return *it;
		if(cell->get_virtualization()) return td::Status::Error("error while importing a cell into a bag of cells: cell has non-zero virtualization level");
		TRY_RESULT(loaded_dc, cell->load_cell());
		const vm::DataCell *dc = loaded_dc.data_cell.get();
		data_bytes += dc->get_serialized_size();
		const uint32_t size_refs = dc->size_refs();
		int ind;
		if(size_refs) {
			num_refs += size_refs;
			std::array<int, 4> refs;
			vm::Cell* const* dc_refs = ((const MyDataCell*)dc)->get_refs();
			for(uint32_t i = 0; i < size_refs; ++i) {
				auto r = import_cell(dc_refs[i], depth+1);
				if(r.is_error()) return r.move_as_error();
				refs[i] = r.move_as_ok();
			}
			ind = (int) cells.size();
			cells.emplace_back(std::move(loaded_dc.data_cell), refs);
		} else {
			ind = (int) cells.size();
			cells.emplace_back(std::move(loaded_dc.data_cell));
		}
		h2i.emplace(hash, ind);
		return ind;
	}

	td::Status import_cells(td::Ref<vm::Cell> r) {
		auto res = import_cell(r.get(), 0);
		if(res.is_error()) return res.move_as_error();
		return td::Status::OK();
	}

	td::Result<td::BufferSlice> serialize() {
		while(cells.size() >= (1ULL << (ref_byte_size << 3))) ++ref_byte_size;
		const uint64_t data_size = data_bytes + (uint64_t)num_refs * ref_byte_size;
		while(data_size >= (1ULL << (offset_byte_size << 3))) ++offset_byte_size;
		if(ref_byte_size > 4 || offset_byte_size > 8) return td::Status::Error("size of refs or offsets too big");
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
			const td::Ref<vm::DataCell>& dc = dc_info.dc_ref;
			buff += dc->serialize(buff, int(buff_end - buff), false);
			const uint32_t size_refs = dc_info.dc_ref->size_refs();
			for(uint32_t j = 0; j < size_refs; ++j)
				store_ref((int) cells.size() - 1 - dc_info.ref_idx[j]);
		}
		DCHECK(buff == buff_end);
		return res;
	}
};

struct MerkleProofImpl {
	using IsPrunnedFunction = std::function<bool(const td::Ref<vm::Cell> &)>;
	explicit MerkleProofImpl(IsPrunnedFunction is_prunned) : is_prunned_(std::move(is_prunned)) {}
	explicit MerkleProofImpl(vm::CellUsageTree *usage_tree) : usage_tree_(usage_tree) {}

	td::Ref<vm::Cell> create_from(td::Ref<vm::Cell> cell) {
		if(!is_prunned_) {
			dfs_usage_tree(cell, usage_tree_->root_id());
			is_prunned_ = [this](const td::Ref<vm::Cell> &cell) { return !visited_cells_.count(cell->get_hash()); };
		}
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
	IsPrunnedFunction is_prunned_;

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

	td::Ref<vm::Cell> dfs(td::Ref<vm::Cell> cell, int merkle_depth) {
		const vm::Cell::Hash &hash = cell->get_hash();
		auto it = cells_.find(hash);
		if(it) return td::Ref(*it);
		if(is_prunned_(cell)) {
			auto res = vm::CellBuilder::create_pruned_branch(cell, merkle_depth + 1);
			cells_.emplace(hash, res.get());
			return res;
		}

		auto rlc = cell->load_cell();
		vm::Cell::LoadedCell  lc = rlc.is_ok() ? rlc.move_as_ok() : vm::Cell::LoadedCell{};
		const MyDataCell *dc = (const MyDataCell*) lc.data_cell.get();

		vm::CellBuilder cb;
		cb.store_bits(dc->get_data(), dc->get_bits());

		const uint32_t nrefs = lc.data_cell->size_refs();
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

	td::Ref<vm::Cell> update_to = MerkleProofImpl([&](const td::Ref<vm::Cell> &cell) {
		auto loaded_cell = cell->load_cell().move_as_ok();
		if(!loaded_cell.data_cell->size_refs()) return false;
		return !loaded_cell.tree_node.empty() && loaded_cell.tree_node.mark_path(tree);
	}).create_from(std::move(state_root));
	if(update_to.is_null()) return td::Status::Error("failed to generate Merkle update");
	tree->set_use_mark_for_is_loaded(true);
	td::Ref<vm::Cell> update_from = MerkleProofImpl(tree).create_from(std::move(prev_state_root));
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
	TRY_STATUS(boc.import_cells(std::move(state_update)));
	return boc.serialize();
}