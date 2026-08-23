#pragma once

#include <cstdint>
#include <vector>

namespace upsica::ds {

class VirtualBloomFilter {
public:
    VirtualBloomFilter(uint32_t slots, uint32_t kv);

    std::vector<uint64_t> Encode64(const std::vector<uint8_t>& element) const;

private:
    uint32_t slots_;
    uint32_t kv_;
};

}  // namespace upsica::ds
