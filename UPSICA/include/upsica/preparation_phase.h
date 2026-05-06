#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "upsica/fhe_wrapper.h"
#include "upsica/dh_oprf.h"
#include "upsica/polynomial_links.h"

namespace upsica::protocol {

struct ProtocolConfig {
    uint32_t bin_count = 64;
    uint32_t fhe_poly_modulus_degree = 8192;
    uint32_t fhe_plain_modulus_bits = 20;
    uint32_t alpha_sub_bins = 4;
    uint32_t cuckoo_hash_num = 3;
    uint32_t cuckoo_max_kicks = 128;
    uint64_t dummy_seed = 0xC0FFEEULL;
    bool enable_polynomial_links = true;
};

struct SenderBinPolynomials {
    uint32_t sender_points = 0;
    std::vector<uint32_t> sub_bin_points;
};

struct PackedPolynomialCoefficients {
    // coeffs_by_degree[d].slots[bin] is the coefficient for x^d of that bin polynomial.
    std::vector<upsica::crypto::Plaintext> coeffs_by_degree;
    uint32_t max_degree = 0;
};

struct PreparationOutput {
    ProtocolConfig config;
    uint32_t slot_count = 0;
    uint64_t plain_modulus = 0;
    std::string oprf_secret_key_hex;
    std::vector<uint64_t> sender_oprf_values; // sender x1 values (mod t)
    std::vector<SenderBinPolynomials> bin_polynomials;
    uint32_t alpha_sub_bins = 1;

    // Slot==Bin packed coefficients for SIMD evaluation.
    std::vector<PackedPolynomialCoefficients> packed_root_coeffs_by_subbin;
    std::vector<PackedPolynomialCoefficients> packed_link2_coeffs_by_subbin;
    std::vector<PackedPolynomialCoefficients> packed_link3_coeffs_by_subbin;
};

PreparationOutput RunPreparation(const std::vector<uint64_t>& sender_set, const ProtocolConfig& config = {});

}  // namespace upsica::protocol
