#include "merkle.hpp"

#include "crypto/vm/cells/MerkleProof.h"
#include "crypto/vm/cells/CellBuilder.h"
#include "crypto/vm/cells/CellSlice.h"
#include "crypto/vm/hash-set.h"

#include "profile.hpp"

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

	struct MyDataCell : public vm::DataCell {
		vm::Cell* const* get_refs() const { return info_.get_refs(get_storage()); }
	};

	td::Result<int> import_cell(const vm::Cell *cell, int depth) {
		if(depth > 1024) return td::Status::Error("error while importing a cell into a bag of cells: cell depth too large");
		if(!cell) return td::Status::Error("error while importing a cell into a bag of cells: cell is null");
		int* it = h2i.find(cell->get_hash());
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
		h2i.emplace(dc->get_hash(), ind);
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

td::Result<td::BufferSlice> merkle_update(td::Ref<vm::Cell> prev_state_root, td::Ref<vm::Cell> state_root, vm::CellUsageTree *tree) {
	PROFILER("merkle_update");

	td::Ref<vm::Cell> update_to = vm::MerkleProof::generate_raw(std::move(state_root), [&](const td::Ref<vm::Cell> &cell) {
	auto loaded_cell = cell->load_cell().move_as_ok();  // FIXME
	if(!loaded_cell.data_cell->size_refs()) return false;
	return !loaded_cell.tree_node.empty() && loaded_cell.tree_node.mark_path(tree);
	});
	if(update_to.is_null()) return td::Status::Error("failed to generate Merkle update");
	tree->set_use_mark_for_is_loaded(true);
	td::Ref<vm::Cell> update_from = vm::MerkleProof::generate_raw(std::move(prev_state_root), tree);
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