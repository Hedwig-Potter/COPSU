#include "upsica/vbf.h"

#include <cstddef>
#include <stdexcept>

#include <openssl/evp.h>

namespace upsica::ds {

VirtualBloomFilter::VirtualBloomFilter(uint32_t slots, uint32_t kv) : slots_(slots), kv_(kv) {}

std::vector<uint64_t> VirtualBloomFilter::Encode64(const std::vector<uint8_t>& element) const {
    std::vector<uint64_t> values;
    values.reserve(kv_);
    if (slots_ == 0 || slots_ > 63) return values;
    const uint64_t mask = (uint64_t{1} << slots_) - 1;
    for (uint32_t i = 0; i < kv_; ++i) {
        std::vector<uint8_t> domain_input = element;
        domain_input.push_back(static_cast<uint8_t>(i));
        domain_input.push_back(static_cast<uint8_t>(i >> 8));
        domain_input.push_back(static_cast<uint8_t>(i >> 16));
        domain_input.push_back(static_cast<uint8_t>(i >> 24));
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_size = 0;
        if (EVP_Digest(domain_input.data(), domain_input.size(), digest,
                       &digest_size, EVP_sha256(), nullptr) != 1 || digest_size < 8) {
            throw std::runtime_error("SHA-256 VBF encoding failed");
        }
        uint64_t value = 0;
        for (size_t byte = 0; byte < 8; ++byte) {
            value |= static_cast<uint64_t>(digest[byte]) << (8 * byte);
        }
        values.push_back(value & mask);
    }
    return values;
}

}  // namespace upsica::ds
