#include "upsica/vbf.h"

#include <cstddef>

namespace {

uint64_t Mix(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

}  // namespace

namespace upsica::ds {

VirtualBloomFilter::VirtualBloomFilter(uint32_t slots, uint32_t kv) : slots_(slots), kv_(kv) {}

std::vector<uint32_t> VirtualBloomFilter::Encode(const std::vector<uint8_t>& element) const {
    std::vector<uint32_t> indices;
    indices.reserve(kv_);

    if (slots_ == 0) {
        return indices;
    }

    uint64_t seed = 0;
    for (uint8_t b : element) {
        seed = Mix(seed ^ static_cast<uint64_t>(b));
    }

    for (uint32_t i = 0; i < kv_; ++i) {
        uint64_t h = Mix(seed ^ (0xA5A5A5A5ULL + i * 0x9e3779b97f4a7c15ULL));
        indices.push_back(static_cast<uint32_t>(h % slots_));
    }
    return indices;
}

}  // namespace upsica::ds
