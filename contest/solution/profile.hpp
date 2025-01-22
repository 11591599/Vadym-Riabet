#pragma once

#include <algorithm>
#include <numeric>

#include "tdutils/td/utils/Timer.h"

namespace Profile {

struct Record {
	std::string name, file;
	double time = 0.;
	int calls = 0, line;
	Record(std::string name, std::string file, int line):
		name(std::forward<std::string>(name)),
		file(std::forward<std::string>(file)),
		line(line) {}
};
extern std::vector<Record> records;

struct Block {
	td::Timer timer;
	int id;
	Block(int id): timer(), id(id) {} 
	~Block() {
		Record &r = records[id];
		++ r.calls;
		r.time += timer.elapsed();
	}
};

inline void show_stats() {
	std::vector<int> inds(records.size());
	std::iota(inds.begin(), inds.end(), 0);
	std::sort(inds.begin(), inds.end(), [&](int i, int j) { return records[i].time < records[j].time; });
	constexpr int name_space = 20;
	constexpr int call_space = 8;
	constexpr int time_space = 10;
	printf("%-*s |%*s  %*s\n", name_space, "Name", call_space, "Calls", time_space, "Time");
	printf("%s\n", std::string(name_space+call_space+time_space+4, '=').c_str());
	for(int i : inds) {
		const Record &r = records[i];
		printf("%-*s |%*d  %*lf     %s:%d\n", name_space, r.name.c_str(), call_space, r.calls, time_space, r.time, r.file.c_str(), r.line);
	}
}

}

#define PROFILER_CONCAT0(x, y) x##y
#define PROFILER_CONCAT(x, y) PROFILER_CONCAT0(x,y)

#define PROFILER(name)\
	static int PROFILER_CONCAT(___profile_id___,__LINE__) = -1;\
	if(PROFILER_CONCAT(___profile_id___,__LINE__) == -1) {\
		PROFILER_CONCAT(___profile_id___,__LINE__) = (int)Profile::records.size();\
		Profile::records.emplace_back(name, __FILE__, __LINE__);\
	}\
	Profile::Block PROFILER_CONCAT(___profile_block___,__LINE__)(PROFILER_CONCAT(___profile_id___,__LINE__))
