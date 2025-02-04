#pragma once

#include "cells/CellHash.h"

namespace vm {

struct HashSet {
	std::vector<int> buckets;
	std::vector<std::pair<vm::CellHash, int>> hs;

	bool emplace(const vm::CellHash &h) {
		if(buckets.empty()) buckets.assign(128, -1);
		const uint64_t b = (*(const uint64_t*) h.as_array().data()) & (buckets.size()-1);
		for(int i = buckets[b]; i != -1; i = hs[i].second)
			if(hs[i].first == h) return false;
		if(hs.size() >= buckets.size()) {
			hs.emplace_back(h, -1);
			buckets.assign(buckets.size()<<1, -1);
			const int H = (int) hs.size();
			const uint64_t m = buckets.size()-1;
			for(int i = 0; i < H; ++i) {
				const uint64_t b = (*(const uint64_t*) hs[i].first.as_array().data()) & m;
				hs[i].second = buckets[b];
				buckets[b] = i;
			}
		} else {
			hs.emplace_back(h, buckets[b]);
			buckets[b] = (int) hs.size() - 1;
		}
		return true;
	}

	bool count(const vm::CellHash &h) const {
		if(buckets.empty()) return false;
		const uint64_t b = (*(const uint64_t*) h.as_array().data()) & (buckets.size()-1);
		for(int i = buckets[b]; i != -1; i = hs[i].second)
			if(hs[i].first == h) return true;
		return false;
	}

	size_t size() const {
		return hs.size();
	}

	void clear() {
		buckets.clear();
		hs.clear();
	}
};

template<typename T>
struct HashMap {
	std::vector<int> buckets;
	std::vector<std::tuple<vm::CellHash, T, int>> hs;

	bool emplace(const vm::CellHash &h, const T &v) {
		if(buckets.empty()) buckets.assign(128, -1);
		const uint64_t b = (*(const uint64_t*) h.as_array().data()) & (buckets.size()-1);
		for(int i = buckets[b]; i != -1; i = std::get<2>(hs[i]))
			if(std::get<0>(hs[i]) == h) return false;
		if(hs.size() >= buckets.size()) {
			hs.emplace_back(h, v, -1);
			buckets.assign(buckets.size()<<1, -1);
			const int H = (int) hs.size();
			const uint64_t m = buckets.size()-1;
			for(int i = 0; i < H; ++i) {
				const uint64_t b = (*(const uint64_t*) std::get<0>(hs[i]).as_array().data()) & m;
				std::get<2>(hs[i]) = buckets[b];
				buckets[b] = i;
			}
		} else {
			hs.emplace_back(h, v, buckets[b]);
			buckets[b] = (int) hs.size() - 1;
		}
		return true;
	}

	T* find(const vm::CellHash &h) {
		if(buckets.empty()) return nullptr;
		const uint64_t b = (*(const uint64_t*) h.as_array().data()) & (buckets.size()-1);
		for(int i = buckets[b]; i != -1; i = std::get<2>(hs[i]))
			if(std::get<0>(hs[i]) == h) return &std::get<1>(hs[i]);
		return nullptr;
	}

	size_t size() const {
		return hs.size();
	}

	void clear() {
		buckets.clear();
		hs.clear();
	}
};

}