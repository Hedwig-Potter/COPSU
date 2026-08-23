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

struct PartyShareOutput {
    std::vector<uint64_t> share;
    uint64_t comm_bytes = 0;
    uint64_t compute_ms = 0;
    uint64_t compute_us = 0;
};

// Split-process OSN API. The permutation holder runs the sender endpoint and
// learns only its output share. The value holder runs the receiver endpoint
// and learns only the complementary share.
PartyShareOutput permute_share_sender(const std::vector<uint32_t>& permutation,
                                      const std::string& endpoint,
                                      int ot_type = 1,
                                      const std::string& cache_base = "");

PartyShareOutput permute_share_receiver(const std::vector<uint64_t>& values,
                                        const std::string& endpoint,
                                        int ot_type = 1);

// Arithmetic sharing over Z_modulus: sender_share[i] + receiver_share[i]
// equals the permuted input modulo modulus.
PartyShareOutput permute_share_sender_arithmetic(
    const std::vector<uint32_t>& permutation, const std::string& endpoint,
    uint64_t modulus, int ot_type = 1, const std::string& cache_base = "");

PartyShareOutput permute_share_receiver_arithmetic(
    const std::vector<uint64_t>& values, const std::string& endpoint,
    uint64_t modulus, int ot_type = 1);

PermuteShareOutput permute_share_bits(const std::vector<uint64_t>& bits,
                                      const std::vector<uint32_t>& permutation,
                                      int ot_type = 1,
                                      const std::string& cache_base = "");

} // namespace bcs

#endif // CWPSU_BCS_OSN_H
