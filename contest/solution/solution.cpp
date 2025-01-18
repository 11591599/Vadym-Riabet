#include "solution.hpp"

#include "vm/boc.h"
#include "block-auto.h"
#include "contest-validate-query.hpp"

void run_contest_solution(ton::BlockIdExt block_id, td::BufferSlice block_data, td::BufferSlice colldated_data,
                          td::Promise<td::BufferSlice> promise) {
  td::actor::create_actor<solution::ContestValidateQuery>(
      "validate", block_id, std::move(block_data), std::move(colldated_data), std::move(promise)).release();
}
