#include "merkle.hpp"

#include "crypto/vm/cells/MerkleProof.h"
#include "crypto/vm/cells/CellBuilder.h"
#include "crypto/vm/cells/CellSlice.h"
#include "crypto/vm/boc-writers.h"
#include "crypto/vm/boc.h"

#include "profile.hpp"

struct BOC : public vm::BagOfCells {
	void add_root(td::Ref<vm::Cell> add_root) {
		roots.emplace_back(std::move(add_root), -1);
		++root_count;
	}

	td::Result<int> import_cell(td::Ref<vm::Cell> cell, int depth) {
		if(depth > max_depth) return td::Status::Error("error while importing a cell into a bag of cells: cell depth too large");
		if(cell.is_null()) return td::Status::Error("error while importing a cell into a bag of cells: cell is null");
		auto it = cells.find(cell->get_hash());
		if(it != cells.end()) {
			auto pos = it->second;
			cell_list_[pos].should_cache = true;
			return pos;
		}
		if(cell->get_virtualization())
			return td::Status::Error("error while importing a cell into a bag of cells: cell has non-zero virtualization level");
		auto r_loaded_dc = cell->load_cell();
		if(r_loaded_dc.is_error())
			return td::Status::Error("error while importing a cell into a bag of cells: " + r_loaded_dc.move_as_error().to_string());
		auto loaded_dc = r_loaded_dc.move_as_ok();
		vm::CellSlice cs(std::move(loaded_dc));
		std::array<int, 4> refs{-1};
		unsigned sum_child_wt = 1;
		for(unsigned i = 0; i < cs.size_refs(); i++) {
			auto ref = import_cell(cs.prefetch_ref(i), depth + 1);
			if(ref.is_error()) return ref.move_as_error();
			refs[i] = ref.move_as_ok();
			sum_child_wt += cell_list_[refs[i]].wt;
			++int_refs;
		}
		DCHECK(cell_list_.size() == static_cast<std::size_t>(cell_count));
		auto dc = cs.move_as_loaded_cell().data_cell;
		auto res = cells.emplace(dc->get_hash(), cell_count);
		DCHECK(res.second);
		cell_list_.emplace_back(dc, dc->size_refs(), refs);
		CellInfo& dc_info = cell_list_.back();
		dc_info.hcnt = static_cast<unsigned char>(dc->get_level_mask().get_hashes_count());
		dc_info.wt = static_cast<unsigned char>(std::min(0xffU, sum_child_wt));
		dc_info.new_idx = -1;
		data_bytes += dc->get_serialized_size();
		return cell_count++;
	}

	td::Status import_cells() {
		for(auto& root : roots) {
			auto res = import_cell(root.cell, 0);
			if(res.is_error()) return res.move_as_error();
			root.idx = res.move_as_ok();
		}
		return td::Status::OK();
	}

	td::uint64 compute_sizes(int& r_size, int& o_size) {
		int rs = 0, os = 0;
		if(!root_count || !data_bytes) {
			r_size = o_size = 0;
			return 0;
		}
		while(cell_count >= (1LL << (rs << 3))) rs++;
		td::uint64 data_bytes_adj = data_bytes + (unsigned long long)int_refs * rs;
		td::uint64 max_offset = data_bytes_adj;
		while(max_offset >= (1ULL << (os << 3))) os++;
		if(rs > 4 || os > 8) {
			r_size = o_size = 0;
			return 0;
		}
		r_size = rs;
		o_size = os;
		return data_bytes_adj;
	}

	std::size_t estimate_serialized_size() {
		auto data_bytes_adj = compute_sizes(info.ref_byte_size, info.offset_byte_size);
		if(!data_bytes_adj) {
			info.invalidate();
			return 0;
		}
		info.valid = true;
		info.has_crc32c = false;
		info.has_index = false;
		info.has_cache_bits = false;
		info.root_count = root_count;
		info.cell_count = cell_count;
		info.absent_count = dangle_count;
		info.roots_offset = 4 + 1 + 1 + 3 * info.ref_byte_size + info.offset_byte_size;
		info.index_offset = info.roots_offset + info.root_count * info.ref_byte_size;
		info.data_offset = info.index_offset;
		info.magic = Info::boc_generic;
		info.data_size = data_bytes_adj;
		return info.total_size = info.data_offset + data_bytes_adj;
	}

	template <typename WriterT>
	td::Result<std::size_t> serialize_to_impl(WriterT& writer) {
		auto store_ref = [&](unsigned long long value) { writer.store_uint(value, info.ref_byte_size); };
		auto store_offset = [&](unsigned long long value) { writer.store_uint(value, info.offset_byte_size); };
		writer.store_uint(info.magic, 4);
		td::uint8 byte{0};
		if(info.ref_byte_size < 1 || info.ref_byte_size > 7) return 0;
		byte |= static_cast<td::uint8>(info.ref_byte_size);
		writer.store_uint(byte, 1);
		writer.store_uint(info.offset_byte_size, 1);
		store_ref(cell_count);
		store_ref(root_count);
		store_ref(0);
		store_offset(info.data_size);
		for (const auto& root_info : roots) {
			int k = cell_count - 1 - root_info.idx;
			DCHECK(k >= 0 && k < cell_count);
			store_ref(k);
		}
		DCHECK(writer.position() == info.index_offset);
		DCHECK((unsigned)cell_count == cell_list_.size());
		DCHECK(writer.position() == info.data_offset);
		size_t keep_position = writer.position();
		for (int i = 0; i < cell_count; ++i) {
			const auto& dc_info = cell_list_[cell_count - 1 - i];
			const td::Ref<vm::DataCell>& dc = dc_info.dc_ref;
			unsigned char buf[256];
			int s = dc->serialize(buf, 256, false);
			writer.store_bytes(buf, s);
			DCHECK(dc->size_refs() == dc_info.ref_num);
			for (unsigned j = 0; j < dc_info.ref_num; ++j) {
				int k = cell_count - 1 - dc_info.ref_idx[j];
				DCHECK(k > i && k < cell_count);
				store_ref(k);
			}
		}
		writer.chk();
		DCHECK(writer.position() - keep_position == info.data_size);
		DCHECK(writer.empty());
		return writer.position();
	}

	td::Result<std::size_t> serialize_to(unsigned char* buffer, std::size_t buff_size) {
		std::size_t size_est = estimate_serialized_size();
		if(!size_est || size_est > buff_size) return 0;
		vm::boc_writers::BufferWriter writer{buffer, buffer + size_est};
		return serialize_to_impl(writer);
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
	boc.add_root(std::move(state_update));
	TRY_STATUS(boc.import_cells());

	std::size_t size_est = boc.estimate_serialized_size();
	if(!size_est) return td::Status::Error("no cells to serialize to this bag of cells");
	td::BufferSlice res(size_est);
	TRY_RESULT(size, boc.serialize_to(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(res.data())), res.size()));
	if(size == res.size()) return std::move(res);
	return td::Status::Error("error while serializing a bag of cells: actual serialized size differs from estimated");
}