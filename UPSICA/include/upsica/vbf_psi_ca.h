#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "upsica/dh_oprf.h"
#include "upsica/fhe_wrapper.h"
#include "upsica/polynomial_links.h"

namespace upsica::protocol {

using ItemBytes = std::vector<uint8_t>;

struct VbfPsiCaConfig {
    uint32_t kv = 2;
    uint32_t vbf_item_bits = 46;
    uint32_t slice_bits = 19;
    uint32_t bin_count = 16384;
    uint32_t alpha_sub_bins = 4;
    uint32_t hash_function_count = 3;
    uint32_t cuckoo_max_kicks = 500;
    uint32_t poly_modulus_degree = 8192;
    uint32_t plain_modulus_bits = 20;
};

struct VbfSubItem {
    uint64_t value = 0;
    uint32_t original_token = 0;
    uint32_t vbf_index = 0;
};

struct SlicePolynomial {
    std::vector<uint64_t> coefficients;
};

struct SenderVbfPreparation {
    VbfPsiCaConfig config;
    uint64_t plain_modulus = 0;
    uint32_t slice_count = 0;
    // Sender-only state. Neither field is serialized to the receiver.
    std::string oprf_secret_key_hex;
    // [bin][sub-bin][slice]
    std::vector<std::vector<std::vector<SlicePolynomial>>> polynomials;
    std::vector<std::vector<uint32_t>> sub_bin_sizes;
    uint32_t maximum_sub_bin_degree = 0;
    double oprf_keygen_ms = 0;
};

struct ReceiverOprfBatch {
    std::vector<uint8_t> blind_factor;
    std::vector<crypto::OprfMessage> blinded_inputs;
};

struct CuckooVbfEntry {
    bool real = false;
    uint64_t sub_item = 0;
    uint32_t token_index = 0;
    uint32_t vbf_index = 0;
    std::vector<uint64_t> slices;
};

struct ReceiverVbfState {
    VbfPsiCaConfig config;
    std::vector<CuckooVbfEntry> table;
    // [anonymous token][VBF index] -> cuckoo bin
    std::vector<std::vector<uint32_t>> token_bins;
    uint32_t token_count = 0;
};

struct EncryptedVbfQuery {
    crypto::FheEvaluationKeys evaluation_keys;
    uint32_t slot_count = 0;
    uint32_t chunk_count = 0;
    uint32_t maximum_power = 0;
    uint32_t slice_count = 0;
    // [slice][chunk][power-1]
    std::vector<std::vector<std::vector<crypto::Ciphertext>>> encrypted_powers;
};

struct EncryptedVbfResponse {
    uint32_t chunk_count = 0;
    uint32_t slice_count = 0;
    uint32_t alpha_sub_bins = 0;
    // [sub-bin][slice][chunk]
    std::vector<std::vector<std::vector<crypto::Ciphertext>>> evaluations;
};

std::vector<uint32_t> SharedCandidateBins(uint64_t sub_item,
                                          uint32_t bin_count,
                                          uint32_t hash_count = 3);
std::vector<uint64_t> SliceVbfSubItem(uint64_t value,
                                      uint32_t value_bits,
                                      uint32_t slice_bits);
uint32_t PublicMaximumSubBinDegree(uint64_t sender_size,
                                  const VbfPsiCaConfig& config);

SenderVbfPreparation PrepareVbfPsiCaSender(const std::vector<ItemBytes>& sender_set,
                                           const VbfPsiCaConfig& config);
ReceiverOprfBatch CreateReceiverOprfBatch(const std::vector<ItemBytes>& receiver_set);
std::vector<crypto::OprfMessage> EvaluateReceiverOprfBatch(
    const SenderVbfPreparation& preparation,
    const std::vector<crypto::OprfMessage>& blinded_inputs);
ReceiverVbfState BuildReceiverVbfState(
    const ReceiverOprfBatch& batch,
    const std::vector<crypto::OprfMessage>& shuffled_responses,
    const VbfPsiCaConfig& config,
    uint64_t dummy_seed = 0x555053494341ULL);
EncryptedVbfQuery EncryptReceiverVbfQuery(const ReceiverVbfState& state,
                                          uint32_t maximum_power,
                                          crypto::FheWrapper& receiver_fhe,
                                          uint64_t plain_modulus);
EncryptedVbfResponse EvaluateEncryptedVbfQuery(
    const SenderVbfPreparation& preparation,
    const EncryptedVbfQuery& query);
uint64_t DecryptIntersectionCardinality(const ReceiverVbfState& state,
                                        const EncryptedVbfResponse& response,
                                        crypto::FheWrapper& receiver_fhe,
                                        uint64_t plain_modulus);

}  // namespace upsica::protocol
