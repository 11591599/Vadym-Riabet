#pragma once

#include "crypto/block/transaction.h"

struct MyTransaction : public block::transaction::Transaction {
	MyTransaction(const block::Account& _account, int ttype, ton::LogicalTime req_start_lt, ton::UnixTime _now, td::Ref<vm::Cell> _inmsg = {}):
		block::transaction::Transaction(_account, ttype, req_start_lt, _now, _inmsg) {}

	bool check_replace_src_addr(td::Ref<vm::CellSlice>& src_addr) const;
	bool check_rewrite_dest_addr(td::Ref<vm::CellSlice>& dest_addr, const block::ActionPhaseConfig& cfg, bool* is_mc) const;
	int try_action_send_msg(const vm::CellSlice& cs0, block::ActionPhase& ap, const block::ActionPhaseConfig& cfg, int redoing = 0);
	int try_action_reserve_currency(vm::CellSlice& cs, block::ActionPhase& ap, const block::ActionPhaseConfig& cfg);
	int try_action_change_library(vm::CellSlice& cs, block::ActionPhase& ap, const block::ActionPhaseConfig& cfg);
	td::Status check_state_limits(const block::SizeLimitsConfig& size_limits, bool update_storage_stat = true);
	void prepare_action_phase(const block::ActionPhaseConfig& cfg);
};