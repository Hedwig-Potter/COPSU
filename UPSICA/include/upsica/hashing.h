#pragma once

#include <cstdint>
#include <limits>
#include <vector>

namespace upsica::ds {

inline constexpr uint64_t kEmptySlot = std::numeric_limits<uint64_t>::max();

struct CuckooTable {
    std::vector<uint64_t> slots;
};

struct SimpleHashTable {
    std::vector<uint64_t> slots;
};

CuckooTable BuildCuckoo(const std::vector<uint64_t>& items, uint32_t table_size);
SimpleHashTable BuildSimple(const std::vector<uint64_t>& items, uint32_t table_size);

}  // namespace upsica::ds
