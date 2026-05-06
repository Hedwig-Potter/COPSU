#ifndef CWPSU_BCS_OSN_H
#define CWPSU_BCS_OSN_H

#include <cstdint>
#include <string>
#include <vector>

namespace bcs {

struct PermuteShareOutput {
    std::vector<uint64_t> server_share;
    std::vector<uint64_t> client_share;
    uint64_t comm_bytes = 0;
    uint64_t comm_ms = 0;
    uint64_t server_compute_ms = 0;
    uint64_t client_compute_ms = 0;
};

PermuteShareOutput permute_share_bits(const std::vector<uint64_t>& bits,
                                      const std::vector<uint32_t>& permutation,
                                      int ot_type = 1,
                                      const std::string& cache_base = "");

} // namespace bcs

#endif // CWPSU_BCS_OSN_H
