#include "deserialize.hpp"

#include "tdutils/td/utils/Span.h"
#include "tdutils/td/utils/misc.h"
#include "crypto/vm/cells/DataCell.h"
#include "crypto/vm/cells/CellBuilder.h"

struct Info {
	enum : uint32_t { boc_idx = 0x68ff65f3, boc_idx_crc32c = 0xacc3a728, boc_generic = 0xb5ee9c72 };

	int root_count;
	int cell_count;
	int ref_byte_size;
	int offset_byte_size;
	bool has_index = true;
	bool has_cache_bits = false;
	unsigned long long roots_offset, index_offset, data_offset, data_size;

	void parse_serialized_header(const td::Slice& slice) {
		const unsigned char* ptr = slice.ubegin();
		const uint32_t magic = (unsigned)read_int(ptr, 4);
		td::uint8 byte = ptr[4];
		if(magic == boc_generic) {
			has_index = (byte >> 7) % 2 == 1;
			has_cache_bits = (byte >> 5) % 2 == 1;
		}
		ref_byte_size = byte & 7;
		offset_byte_size = ptr[5];
		roots_offset = 6 + 3 * ref_byte_size + offset_byte_size;
		ptr += 6;
		cell_count = (int)read_ref(ptr);
		root_count = (int)read_ref(ptr + ref_byte_size);
		index_offset = roots_offset;
		if(magic == boc_generic) index_offset += (long long)root_count * ref_byte_size;
		data_offset = index_offset;
		if(has_index) data_offset += (long long)cell_count * offset_byte_size;
		data_size = read_offset(ptr + 3 * ref_byte_size);
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

struct CellSerializationInfo {
	int data_offset;
	int data_len;
	int refs_offset;
	int refs_cnt;
	int end_offset;
	bool special;
	bool data_with_bits;

	void init(td::Slice data, int ref_byte_size) {
		const td::uint8 d1 = data.ubegin()[0], d2 = data.ubegin()[1];
		refs_cnt = d1 & 7;
		special = (d1 & 8) != 0;
		bool with_hashes = (d1 & 16) != 0;
		auto n = vm::Cell::LevelMask(d1 >> 5).get_hashes_count();
		data_offset = 2 + (with_hashes ? n * vm::Cell::hash_bytes : 0) + (with_hashes ? n * vm::Cell::depth_bytes : 0);
		data_len = (d2 >> 1) + (d2 & 1);
		data_with_bits = (d2 & 1) != 0;
		refs_offset = data_offset + data_len;
		end_offset = refs_offset + refs_cnt * ref_byte_size;
	}

	td::Ref<vm::DataCell> create_data_cell(td::Slice cell_slice, td::Span<td::Ref<vm::Cell>> refs) const {
		vm::CellBuilder cb;
		int bits = data_len * 8;
		if(data_with_bits) bits -= 1 + td::count_trailing_zeroes32(cell_slice[data_offset + data_len - 1]);
		cb.store_bits(cell_slice.ubegin() + data_offset, bits);
		for(int k = 0; k < refs_cnt; k++) cb.store_ref(std::move(refs[k]));
		auto res = cb.finalize_novm_nothrow(special).move_as_ok();
		return res;
	}
};

struct BOC {
	Info info;
	std::vector<unsigned long long> custom_index;
	const unsigned char* index_ptr = nullptr;

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

	std::vector<td::Ref<vm::Cell>> deserialize(const td::Slice& data) {
		info.parse_serialized_header(data);
		std::vector<int> roots_idx(info.root_count);
		auto* roots_ptr = data.substr(info.roots_offset).ubegin();
		for(int i = 0; i < info.root_count; ++i)
			roots_idx[i] = (int)info.read_ref(roots_ptr + i * info.ref_byte_size);
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
		cell_list.reserve(info.cell_count);
		std::array<td::Ref<vm::Cell>, 4> refs_buf;
		std::sort(roots_idx.begin(), roots_idx.end());
		std::vector<td::Ref<vm::Cell>> roots;
		for(int i = 0; i < info.cell_count; i++) {
			int idx = info.cell_count - 1 - i;
			const td::Slice cell_slice = get_cell_slice(idx, cells_slice);
			std::array<td::Ref<vm::Cell>, 4> refs_buf;
			CellSerializationInfo cell_info;
			cell_info.init(cell_slice, info.ref_byte_size);
			auto refs = td::MutableSpan<td::Ref<vm::Cell>>(refs_buf).substr(0, cell_info.refs_cnt);
			for(int k = 0; k < cell_info.refs_cnt; k++) {
				const int ref_idx = (int)info.read_ref(cell_slice.ubegin() + cell_info.refs_offset + k * info.ref_byte_size);
				refs[k] = cell_list[info.cell_count - ref_idx - 1];
			}
			cell_list.push_back(cell_info.create_data_cell(cell_slice, refs));
			if(!roots_idx.empty() && idx == roots_idx.back()) {
				roots_idx.pop_back();
				roots.push_back(cell_list.back());
			}
		}
		return roots;
	}
};

std::vector<td::Ref<vm::Cell>> deserialize(const td::Slice& data) {
	BOC boc;
	return boc.deserialize(data);
}