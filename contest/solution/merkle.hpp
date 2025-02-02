#pragma once

#include "crypto/vm/cells/Cell.h"
#include "crypto/vm/cells/CellUsageTree.h"
#include "td/utils/buffer.h"
#include "td/utils/Status.h"

td::Result<td::BufferSlice> merkle_update(td::Ref<vm::Cell> prev_state_root, td::Ref<vm::Cell> state_root, vm::CellUsageTree *tree);