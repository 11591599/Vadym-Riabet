#include "deserialize.hpp"

#include "tdutils/td/utils/Span.h"
#include "tdutils/td/utils/misc.h"
#include "crypto/vm/cells/DataCell.h"
#include "crypto/vm/cells/CellBuilder.h"

struct Info {
	enum : td::uint32 { boc_idx = 0x68ff65f3, boc_idx_crc32c = 0xacc3a728, boc_generic = 0xb5ee9c72 };

	unsigned magic;
	int root_count;
	int cell_count;
	int absent_count;
	int ref_byte_size;
	int offset_byte_size;
	bool valid;
	bool has_index;
	bool has_roots{false};
	bool has_crc32c;
	bool has_cache_bits;
	unsigned long long roots_offset, index_offset, data_offset, data_size, total_size;
	Info() : magic(0), valid(false) {}
	void invalidate() { valid = false; }

	void parse_serialized_header(const td::Slice& slice) {
		invalidate();
		const unsigned char* ptr = slice.ubegin();
		magic = (unsigned)read_int(ptr, 4);
		has_crc32c = false;
		has_index = false;
		has_cache_bits = false;
		ref_byte_size = 0;
		offset_byte_size = 0;
		root_count = cell_count = absent_count = -1;
		index_offset = data_offset = data_size = total_size = 0;
		td::uint8 byte = ptr[4];
		if (magic == boc_generic) {
			has_index = (byte >> 7) % 2 == 1;
			has_crc32c = (byte >> 6) % 2 == 1;
			has_cache_bits = (byte >> 5) % 2 == 1;
		} else {
			has_index = true;
			has_crc32c = magic == boc_idx_crc32c;
		}
		ref_byte_size = byte & 7;
		offset_byte_size = ptr[5];
		roots_offset = 6 + 3 * ref_byte_size + offset_byte_size;
		ptr += 6;
		cell_count = (int)read_ref(ptr);
		root_count = (int)read_ref(ptr + ref_byte_size);
		index_offset = roots_offset;
		if(magic == boc_generic) {
			index_offset += (long long)root_count * ref_byte_size;
			has_roots = true;
		}
		data_offset = index_offset;
		if(has_index) data_offset += (long long)cell_count * offset_byte_size;
		absent_count = (int)read_ref(ptr + 2 * ref_byte_size);
		data_size = read_offset(ptr + 3 * ref_byte_size);
		valid = true;
		total_size = data_offset + data_size + (has_crc32c ? 4 : 0);
	}

	unsigned long long read_int(const unsigned char* ptr, unsigned bytes) {
		unsigned long long res = 0;
		while (bytes > 0) {
			res = (res << 8) + *ptr++;
			--bytes;
		}
		return res;
	}
	unsigned long long read_ref(const unsigned char* ptr) {
		return read_int(ptr, ref_byte_size);
	}
	unsigned long long read_offset(const unsigned char* ptr) {
		return read_int(ptr, offset_byte_size);
	}
};

struct RootInfo {
	RootInfo() = default;
	RootInfo(td::Ref<vm::Cell> cell, int idx) : cell(std::move(cell)), idx(idx) {}
	td::Ref<vm::Cell> cell;
	int idx{-1};
};

struct CellSerializationInfo {
  bool special;
  vm::Cell::LevelMask level_mask;

  bool with_hashes;
  size_t hashes_offset;
  size_t depth_offset;

  size_t data_offset;
  size_t data_len;
  bool data_with_bits;

  size_t refs_offset;
  int refs_cnt;

  size_t end_offset;

	void init(td::Slice data, int ref_byte_size) {
		init(data.ubegin()[0], data.ubegin()[1], ref_byte_size);
	}
	void init(td::uint8 d1, td::uint8 d2, int ref_byte_size) {
		refs_cnt = d1 & 7;
		level_mask = vm::Cell::LevelMask(d1 >> 5);
		special = (d1 & 8) != 0;
		with_hashes = (d1 & 16) != 0;
		hashes_offset = 2;
		auto n = level_mask.get_hashes_count();
		depth_offset = hashes_offset + (with_hashes ? n * vm::Cell::hash_bytes : 0);
		data_offset = depth_offset + (with_hashes ? n * vm::Cell::depth_bytes : 0);
		data_len = (d2 >> 1) + (d2 & 1);
		data_with_bits = (d2 & 1) != 0;
		refs_offset = data_offset + data_len;
		end_offset = refs_offset + refs_cnt * ref_byte_size;
	}
	
	int get_bits(td::Slice cell) const {
		if(data_with_bits) {
			int last = cell[data_offset + data_len - 1];
			return td::narrow_cast<int>((data_len - 1) * 8 + 7 - td::count_trailing_zeroes_non_zero32(last));
		} else {
			return td::narrow_cast<int>(data_len * 8);
		}
	}

	td::Ref<vm::DataCell> create_data_cell(td::Slice cell_slice, td::Span<td::Ref<vm::Cell>> refs) const {
		vm::CellBuilder cb;
		int bits = get_bits(cell_slice);
		cb.store_bits(cell_slice.ubegin() + data_offset, bits);
		for(int k = 0; k < refs_cnt; k++) {
			cb.store_ref(std::move(refs[k]));
		}
		auto res = cb.finalize_novm_nothrow(special).move_as_ok();
		if(with_hashes) {
			bool check_all_hashes = true;
			for(unsigned level_i = 0, level = level_mask.get_level(); check_all_hashes && level_i < level; level_i++) {
				if(!level_mask.is_significant(level_i)) {
					continue;
				}
			}
		}
		return res;
	}
};

struct BOC {
	Info info;
	std::vector<RootInfo> roots;
	std::vector<unsigned long long> custom_index;
	const unsigned char* index_ptr = nullptr;
	int cell_count;

	unsigned long long get_idx_entry_raw(int index) {
		if(index < 0) return 0;
		if (!info.has_index) {
			return custom_index.at(index);
		} else if (index < info.cell_count && index_ptr) {
			return info.read_offset(index_ptr + (long)index * info.offset_byte_size);
		} else {
			return 0;
		}
	}

	unsigned long long get_idx_entry(int index) {
		auto raw = get_idx_entry_raw(index);
		if(info.has_cache_bits) raw /= 2;
		return raw;
	}

	td::Slice get_cell_slice(int idx, td::Slice data) {
		unsigned long long offs = get_idx_entry(idx - 1);
		unsigned long long offs_end = get_idx_entry(idx);
		return data.substr(offs, td::narrow_cast<size_t>(offs_end - offs));
	}

	td::Ref<vm::DataCell> deserialize_cell(int idx, td::Slice cells_slice, td::Span<td::Ref<vm::DataCell>> cells_span, std::vector<td::uint8>* cell_should_cache) {
		td::Slice cell_slice = get_cell_slice(idx, cells_slice);
		std::array<td::Ref<vm::Cell>, 4> refs_buf;
		CellSerializationInfo cell_info;
		cell_info.init(cell_slice, info.ref_byte_size);
		auto refs = td::MutableSpan<td::Ref<vm::Cell>>(refs_buf).substr(0, cell_info.refs_cnt);
		for(int k = 0; k < cell_info.refs_cnt; k++) {
			int ref_idx = (int)info.read_ref(cell_slice.ubegin() + cell_info.refs_offset + k * info.ref_byte_size);
			refs[k] = cells_span[cell_count - ref_idx - 1];
			if(cell_should_cache) {
				auto& cnt = (*cell_should_cache)[ref_idx];
				if(cnt < 2) cnt++;
			}
		}
		return cell_info.create_data_cell(cell_slice, refs);
	}

	bool get_cache_entry(int index) {
		if (!info.has_cache_bits) {
			return true;
		}
		if (!info.has_index) {
			return true;
		}
		auto raw = get_idx_entry_raw(index);
		return raw % 2 == 1;
	}

	void deserialize(const td::Slice& data) {
		info.parse_serialized_header(data);
		cell_count = info.cell_count;
		std::vector<td::uint8> cell_should_cache;
		if(info.has_cache_bits) cell_should_cache.resize(cell_count, 0);
		roots.resize(info.root_count);
		auto* roots_ptr = data.substr(info.roots_offset).ubegin();
		for(int i = 0; i < info.root_count; i++) {
			int idx = 0;
			if(info.has_roots)
				idx = (int)info.read_ref(roots_ptr + i * info.ref_byte_size);
			roots[i].idx = info.cell_count - idx - 1;
			if(info.has_cache_bits) {
				auto& cnt = cell_should_cache[idx];
				if(cnt < 2) cnt++;
			}
		}
		if(info.has_index) {
			index_ptr = data.substr(info.index_offset).ubegin();
		} else {
			index_ptr = nullptr;
			unsigned long long cur = 0;
			custom_index.reserve(info.cell_count);
			auto cells_slice = data.substr(info.data_offset, info.data_size);
			for (int i = 0; i < info.cell_count; i++) {
				CellSerializationInfo cell_info;
				cell_info.init(cells_slice, info.ref_byte_size);
				cells_slice = cells_slice.substr(cell_info.end_offset);
				cur += cell_info.end_offset;
				custom_index.push_back(cur);
			}
		}
		auto cells_slice = data.substr(info.data_offset, info.data_size);
		std::vector<td::Ref<vm::DataCell>> cell_list;
		cell_list.reserve(cell_count);
		std::array<td::Ref<vm::Cell>, 4> refs_buf;
		for (int i = 0; i < cell_count; i++) {
			int idx = cell_count - 1 - i;
			auto r_cell = deserialize_cell(idx, cells_slice, cell_list, info.has_cache_bits ? &cell_should_cache : nullptr);
			cell_list.push_back(r_cell);
		}
		if(info.has_cache_bits) {
			for(int idx = 0; idx < cell_count; idx++) {
				get_cache_entry(idx);
			}
		}
		custom_index.clear();
		index_ptr = nullptr;
		for(auto& root_info : roots) {
			root_info.cell = cell_list[root_info.idx];
		}
		cell_list.clear();
	}
};

std::vector<td::Ref<vm::Cell>> deserialize(const td::Slice& data) {
	BOC boc;
	boc.deserialize(data);
	std::vector<td::Ref<vm::Cell>> roots(boc.roots.size());
	for(int i = 0; i < (int) roots.size(); ++i)
		roots[i] = boc.roots[i].cell;
	return roots;
}