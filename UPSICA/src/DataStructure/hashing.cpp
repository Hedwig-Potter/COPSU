#include "upsica/hashing.h"

#include <algorithm>

namespace upsica::ds {

namespace {

uint64_t MixHash(uint64_t value, uint64_t seed) {
    uint64_t z = value + 0x9e3779b97f4a7c15ULL + (seed << 1);
    z ^= (z >> 30);
    z *= 0xbf58476d1ce4e5b9ULL;
    z ^= (z >> 27);
    z *= 0x94d049bb133111ebULL;
    z ^= (z >> 31);
    return z;
}

}  // namespace

CuckooTable BuildCuckoo(const std::vector<uint64_t>& items, uint32_t table_size) {
    CuckooTable table;
    table.slots.assign(table_size, kEmptySlot);
    if (table_size == 0) {
        return table;
    }

    for (uint64_t item : items) {
        uint32_t h1 = static_cast<uint32_t>(MixHash(item, 0xA5A5A5A5ULL) % table_size);
        uint32_t h2 = static_cast<uint32_t>(MixHash(item, 0x5A5A5A5AULL) % table_size);

        if (table.slots[h1] == kEmptySlot || table.slots[h1] == item) {
            table.slots[h1] = item;
            continue;
        }
        if (table.slots[h2] == kEmptySlot || table.slots[h2] == item) {
            table.slots[h2] = item;
            continue;
        }

        // Fallback: bounded linear probe.
        for (uint32_t step = 0; step < table_size; ++step) {
            uint32_t idx = static_cast<uint32_t>((h1 + step) % table_size);
            if (table.slots[idx] == kEmptySlot || table.slots[idx] == item) {
                table.slots[idx] = item;
                break;
            }
        }
    }

    return table;
}

SimpleHashTable BuildSimple(const std::vector<uint64_t>& items, uint32_t table_size) {
    SimpleHashTable table;
    table.slots.assign(table_size, kEmptySlot);
    if (table_size == 0) {
        return table;
    }

    for (uint64_t item : items) {
        uint32_t base = static_cast<uint32_t>(MixHash(item, 0x1234ULL) % table_size);
        for (uint32_t step = 0; step < table_size; ++step) {
            uint32_t idx = static_cast<uint32_t>((base + step) % table_size);
            if (table.slots[idx] == kEmptySlot || table.slots[idx] == item) {
                table.slots[idx] = item;
                break;
            }
        }
    }

    return table;
}

}  // namespace upsica::ds
