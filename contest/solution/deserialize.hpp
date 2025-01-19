#pragma once

#include <vector>
#include <crypto/vm/cells/Cell.h>

std::vector<td::Ref<vm::Cell>> deserialize(const td::Slice& data);