#include "upsica/vbf_psi_ca.h"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <limits>
#include <random>
#include <stdexcept>

#include "upsica/vbf.h"

#if UPSICA_ENABLE_SEAL
#include <seal/seal.h>
#endif
#include <openssl/evp.h>

namespace upsica::protocol {
namespace {

uint64_t ResolvePlainModulus(const VbfPsiCaConfig& config) {
#if UPSICA_ENABLE_SEAL
    return seal::PlainModulus::Batching(config.poly_modulus_degree,
                                        config.plain_modulus_bits).value();
#else
    return (uint64_t{1} << config.plain_modulus_bits) - 1;
#endif
}

uint32_t ChooseBalancedSubBin(
    const std::vector<std::vector<std::vector<uint64_t>>>& sub_bins) {
    uint32_t best = 0;
    size_t best_size = std::numeric_limits<size_t>::max();
    for (uint32_t i = 0; i < sub_bins.size(); ++i) {
        if (sub_bins[i].size() < best_size) {
            best = i;
            best_size = sub_bins[i].size();
        }
    }
    return best;
}

}  // namespace

std::vector<uint32_t> SharedCandidateBins(uint64_t sub_item,
                                          uint32_t bin_count,
                                          uint32_t hash_count) {
    if (!bin_count || !hash_count) return {};
    std::vector<uint32_t> result;
    result.reserve(hash_count);
    for (uint32_t h = 0; h < hash_count; ++h) {
        uint32_t counter = 0;
        uint32_t candidate = 0;
        do {
            uint8_t input[16]{};
            for (size_t i = 0; i < 8; ++i)
                input[i] = static_cast<uint8_t>(sub_item >> (8 * i));
            for (size_t i = 0; i < 4; ++i) {
                input[8 + i] = static_cast<uint8_t>(h >> (8 * i));
                input[12 + i] = static_cast<uint8_t>(counter >> (8 * i));
            }
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digest_size = 0;
            if (EVP_Digest(input, sizeof(input), digest, &digest_size,
                           EVP_sha256(), nullptr) != 1 || digest_size < 8) {
                throw std::runtime_error("SHA-256 bin hashing failed");
            }
            uint64_t hash_value = 0;
            for (size_t i = 0; i < 8; ++i)
                hash_value |= static_cast<uint64_t>(digest[i]) << (8 * i);
            candidate = static_cast<uint32_t>(hash_value % bin_count);
            ++counter;
        } while (std::find(result.begin(), result.end(), candidate) != result.end());
        result.push_back(candidate);
    }
    return result;
}

std::vector<uint64_t> SliceVbfSubItem(uint64_t value,
                                      uint32_t value_bits,
                                      uint32_t slice_bits) {
    if (!slice_bits || slice_bits >= 63 || !value_bits || value_bits > 63) {
        throw std::invalid_argument("invalid VBF slicing parameters");
    }
    const uint32_t count = (value_bits + slice_bits - 1) / slice_bits;
    const uint64_t mask = (uint64_t{1} << slice_bits) - 1;
    std::vector<uint64_t> slices(count);
    for (uint32_t i = 0; i < count; ++i) {
        slices[i] = (value >> (i * slice_bits)) & mask;
    }
    return slices;
}

uint32_t PublicMaximumSubBinDegree(uint64_t sender_size,
                                  const VbfPsiCaConfig& config) {
    const double insertions = static_cast<double>(sender_size) * config.kv *
                              config.hash_function_count;
    const double buckets = static_cast<double>(config.bin_count) *
                           config.alpha_sub_bins;
    const double average = insertions / buckets;
    return static_cast<uint32_t>(std::ceil(
        average + 8.0 * std::sqrt(std::max(1.0, average) *
                                  std::log(std::max(2u, config.bin_count))) + 32.0));
}

SenderVbfPreparation PrepareVbfPsiCaSender(const std::vector<ItemBytes>& sender_set,
                                           const VbfPsiCaConfig& config) {
    if (config.kv == 0 || config.vbf_item_bits == 0 || config.vbf_item_bits > 63 ||
        config.slice_bits == 0 || config.slice_bits >= config.plain_modulus_bits ||
        config.bin_count < config.hash_function_count || config.alpha_sub_bins == 0 ||
        config.hash_function_count != 3) {
        throw std::invalid_argument("invalid VBF PSI-CA configuration");
    }

    SenderVbfPreparation output;
    output.config = config;
    output.plain_modulus = ResolvePlainModulus(config);
    output.slice_count = (config.vbf_item_bits + config.slice_bits - 1) /
                         config.slice_bits;
    if ((uint64_t{1} << config.slice_bits) >= output.plain_modulus) {
        throw std::invalid_argument("slice values must fit below the BFV plaintext modulus");
    }

    crypto::ShuffledDhOprf oprf({"sha256_to_curve", "sha256"});
    const auto keygen_start = std::chrono::steady_clock::now();
    output.oprf_secret_key_hex = oprf.GenerateKeypair().secret_key;
    const auto keygen_end = std::chrono::steady_clock::now();
    output.oprf_keygen_ms = std::chrono::duration<double, std::milli>(
        keygen_end - keygen_start).count();
    ds::VirtualBloomFilter vbf(config.vbf_item_bits, config.kv);

    // Simple hashing: every VBF sub-item is inserted into all three bins.
    std::vector<std::vector<std::vector<uint64_t>>> bins(config.bin_count);
    for (const auto& item : sender_set) {
        auto token = oprf.EvaluateInput(item);
        for (uint64_t sub_item : vbf.Encode64(token)) {
            auto slices = SliceVbfSubItem(sub_item, config.vbf_item_bits,
                                          config.slice_bits);
            for (uint32_t bin : SharedCandidateBins(sub_item, config.bin_count,
                                                    config.hash_function_count)) {
                bins[bin].push_back(slices);
            }
        }
    }

    output.polynomials.resize(config.bin_count);
    output.sub_bin_sizes.resize(config.bin_count);
    for (uint32_t bin = 0; bin < config.bin_count; ++bin) {
        std::vector<std::vector<std::vector<uint64_t>>> sub_bins(config.alpha_sub_bins);
        for (const auto& slices : bins[bin]) {
            sub_bins[ChooseBalancedSubBin(sub_bins)].push_back(slices);
        }

        output.polynomials[bin].resize(config.alpha_sub_bins);
        output.sub_bin_sizes[bin].resize(config.alpha_sub_bins);
        for (uint32_t sb = 0; sb < config.alpha_sub_bins; ++sb) {
            output.sub_bin_sizes[bin][sb] = static_cast<uint32_t>(sub_bins[sb].size());
            output.maximum_sub_bin_degree = std::max(
                output.maximum_sub_bin_degree,
                static_cast<uint32_t>(sub_bins[sb].size()));
            output.polynomials[bin][sb].resize(output.slice_count);
            for (uint32_t slice = 0; slice < output.slice_count; ++slice) {
                std::vector<uint64_t> roots;
                roots.reserve(sub_bins[sb].size());
                for (const auto& item_slices : sub_bins[sb]) {
                    roots.push_back(item_slices[slice]);
                }
                auto polynomial = ds::BuildRootPolynomialMod(roots, output.plain_modulus);
                output.polynomials[bin][sb][slice].coefficients =
                    std::move(polynomial.coefficients);
            }
        }
    }
    const uint32_t public_bound = PublicMaximumSubBinDegree(sender_set.size(), config);
    if (output.maximum_sub_bin_degree > public_bound) {
        throw std::runtime_error(
            "public sub-bin degree bound exceeded; increase bin_count or alpha_sub_bins");
    }
    return output;
}

ReceiverOprfBatch CreateReceiverOprfBatch(const std::vector<ItemBytes>& receiver_set) {
    crypto::ShuffledDhOprf receiver({"sha256_to_curve", "sha256"});
    ReceiverOprfBatch batch;
    batch.blind_factor = receiver.GenerateBlindFactor();
    batch.blinded_inputs.reserve(receiver_set.size());
    for (const auto& item : receiver_set) {
        batch.blinded_inputs.push_back(
            receiver.BlindWithFactor(item, batch.blind_factor));
    }
    return batch;
}

std::vector<crypto::OprfMessage> EvaluateReceiverOprfBatch(
    const SenderVbfPreparation& preparation,
    const std::vector<crypto::OprfMessage>& blinded_inputs) {
    crypto::ShuffledDhOprf sender({"sha256_to_curve", "sha256"});
    sender.ImportSecretKeyHex(preparation.oprf_secret_key_hex);
    return sender.EvaluateBatchShuffled(blinded_inputs);
}

ReceiverVbfState BuildReceiverVbfState(
    const ReceiverOprfBatch& batch,
    const std::vector<crypto::OprfMessage>& shuffled_responses,
    const VbfPsiCaConfig& config,
    uint64_t dummy_seed) {
    if (shuffled_responses.size() != batch.blinded_inputs.size()) {
        throw std::invalid_argument("OPRF response count mismatch");
    }
    crypto::ShuffledDhOprf receiver({"sha256_to_curve", "sha256"});
    ds::VirtualBloomFilter vbf(config.vbf_item_bits, config.kv);

    ReceiverVbfState state;
    state.config = config;
    state.token_count = static_cast<uint32_t>(shuffled_responses.size());
    state.table.resize(config.bin_count);
    state.token_bins.assign(state.token_count,
                            std::vector<uint32_t>(config.kv, config.bin_count));

    std::vector<CuckooVbfEntry> entries;
    entries.reserve(static_cast<size_t>(state.token_count) * config.kv);
    for (uint32_t token_idx = 0; token_idx < state.token_count; ++token_idx) {
        auto token = receiver.Unblind(shuffled_responses[token_idx], batch.blind_factor);
        auto sub_items = vbf.Encode64(token);
        if (sub_items.size() != config.kv) {
            throw std::runtime_error("VBF encoding failed");
        }
        for (uint32_t v = 0; v < config.kv; ++v) {
            entries.push_back({true, sub_items[v], token_idx, v,
                               SliceVbfSubItem(sub_items[v], config.vbf_item_bits,
                                               config.slice_bits)});
        }
    }

    // Standard bounded cuckoo displacement with exactly the same three bin
    // functions used by the sender's Simple Hashing.
    for (const auto& input : entries) {
        CuckooVbfEntry current = input;
        uint32_t previous_bin = config.bin_count;
        bool placed = false;
        for (uint32_t kick = 0; kick < config.cuckoo_max_kicks; ++kick) {
            auto candidates = SharedCandidateBins(current.sub_item, config.bin_count,
                                                  config.hash_function_count);
            uint32_t target = candidates[kick % candidates.size()];
            if (target == previous_bin) {
                target = candidates[(kick + 1) % candidates.size()];
            }
            if (!state.table[target].real) {
                state.table[target] = std::move(current);
                placed = true;
                break;
            }
            std::swap(current, state.table[target]);
            previous_bin = target;
        }
        if (!placed) {
            throw std::runtime_error(
                "Cuckoo insertion failed; increase bin_count or cuckoo_max_kicks");
        }
    }

    for (uint32_t bin = 0; bin < state.table.size(); ++bin) {
        const auto& entry = state.table[bin];
        if (entry.real) state.token_bins[entry.token_index][entry.vbf_index] = bin;
    }
    for (const auto& bins : state.token_bins) {
        for (uint32_t bin : bins) {
            if (bin >= config.bin_count) {
                throw std::runtime_error("Cuckoo table lost a VBF sub-item");
            }
        }
    }

    std::mt19937_64 rng(dummy_seed);
    const uint64_t slice_mask = (uint64_t{1} << config.slice_bits) - 1;
    for (auto& entry : state.table) {
        if (!entry.real) {
            entry.sub_item = rng() & ((uint64_t{1} << config.vbf_item_bits) - 1);
            entry.slices = SliceVbfSubItem(entry.sub_item, config.vbf_item_bits,
                                           config.slice_bits);
            for (auto& slice : entry.slices) slice &= slice_mask;
        }
    }
    return state;
}

EncryptedVbfQuery EncryptReceiverVbfQuery(const ReceiverVbfState& state,
                                          uint32_t maximum_power,
                                          crypto::FheWrapper& receiver_fhe,
                                          uint64_t plain_modulus) {
    if (!maximum_power) throw std::invalid_argument("maximum polynomial degree is zero");
    EncryptedVbfQuery query;
    query.evaluation_keys = receiver_fhe.ExportEvaluationKeys();
    query.slot_count = static_cast<uint32_t>(receiver_fhe.SlotCount());
    query.chunk_count = static_cast<uint32_t>(
        (state.table.size() + query.slot_count - 1) / query.slot_count);
    query.maximum_power = maximum_power;
    query.slice_count = state.table.empty() ? 0 :
        static_cast<uint32_t>(state.table.front().slices.size());
    query.encrypted_powers.resize(query.slice_count);

    for (uint32_t slice = 0; slice < query.slice_count; ++slice) {
        query.encrypted_powers[slice].resize(query.chunk_count);
        for (uint32_t chunk = 0; chunk < query.chunk_count; ++chunk) {
            std::vector<uint64_t> base(query.slot_count, 0);
            for (uint32_t slot = 0; slot < query.slot_count; ++slot) {
                size_t bin = static_cast<size_t>(chunk) * query.slot_count + slot;
                if (bin < state.table.size()) base[slot] = state.table[bin].slices[slice];
            }
            std::vector<uint64_t> power = base;
            auto& ciphertexts = query.encrypted_powers[slice][chunk];
            ciphertexts.reserve(maximum_power);
            for (uint32_t degree = 1; degree <= maximum_power; ++degree) {
                ciphertexts.push_back(receiver_fhe.Encrypt(receiver_fhe.Encode(power)));
                for (uint32_t slot = 0; slot < query.slot_count; ++slot) {
                    power[slot] = static_cast<uint64_t>(
                        (static_cast<unsigned __int128>(power[slot]) * base[slot]) %
                        plain_modulus);
                }
            }
        }
    }
    return query;
}

EncryptedVbfResponse EvaluateEncryptedVbfQuery(
    const SenderVbfPreparation& preparation,
    const EncryptedVbfQuery& query) {
    if (query.maximum_power < preparation.maximum_sub_bin_degree) {
        throw std::invalid_argument("query does not contain enough encrypted powers");
    }
    crypto::FheParams params{preparation.config.poly_modulus_degree,
                             preparation.config.plain_modulus_bits};
    crypto::FheWrapper evaluator(params);
    evaluator.InitializeEvaluator(query.evaluation_keys);

    EncryptedVbfResponse response;
    response.chunk_count = query.chunk_count;
    response.slice_count = preparation.slice_count;
    response.alpha_sub_bins = preparation.config.alpha_sub_bins;
    response.evaluations.resize(response.alpha_sub_bins);
    for (uint32_t sb = 0; sb < response.alpha_sub_bins; ++sb) {
        response.evaluations[sb].resize(response.slice_count);
        for (uint32_t slice = 0; slice < response.slice_count; ++slice) {
            auto& outputs = response.evaluations[sb][slice];
            outputs.reserve(query.chunk_count);
            for (uint32_t chunk = 0; chunk < query.chunk_count; ++chunk) {
                size_t max_coeffs = 1;
                const size_t first_bin = static_cast<size_t>(chunk) * query.slot_count;
                const size_t last_bin = std::min(first_bin + query.slot_count,
                                                 preparation.polynomials.size());
                for (size_t bin = first_bin; bin < last_bin; ++bin) {
                    max_coeffs = std::max(max_coeffs,
                        preparation.polynomials[bin][sb][slice].coefficients.size());
                }
                std::vector<crypto::Plaintext> packed(max_coeffs);
                for (auto& coefficient : packed) coefficient.slots.assign(query.slot_count, 0);
                for (size_t bin = first_bin; bin < last_bin; ++bin) {
                    const auto& coefficients =
                        preparation.polynomials[bin][sb][slice].coefficients;
                    const size_t slot = bin - first_bin;
                    for (size_t degree = 0; degree < coefficients.size(); ++degree) {
                        packed[degree].slots[slot] = coefficients[degree];
                    }
                }
                outputs.push_back(evaluator.EvaluatePolynomialSIMDWindowed(
                    query.encrypted_powers[slice][chunk], packed,
                    query.maximum_power));
            }
        }
    }
    return response;
}

uint64_t DecryptIntersectionCardinality(const ReceiverVbfState& state,
                                        const EncryptedVbfResponse& response,
                                        crypto::FheWrapper& receiver_fhe,
                                        uint64_t plain_modulus) {
    if (response.slice_count == 0 || response.chunk_count == 0) return 0;
    const uint32_t slot_count = static_cast<uint32_t>(receiver_fhe.SlotCount());
    std::vector<std::vector<std::vector<uint64_t>>> decoded(
        response.alpha_sub_bins,
        std::vector<std::vector<uint64_t>>(response.slice_count,
            std::vector<uint64_t>(state.table.size(), 1)));
    for (uint32_t sb = 0; sb < response.alpha_sub_bins; ++sb) {
        for (uint32_t slice = 0; slice < response.slice_count; ++slice) {
            for (uint32_t chunk = 0; chunk < response.chunk_count; ++chunk) {
                auto slots = receiver_fhe.Decrypt(
                    response.evaluations[sb][slice][chunk]).slots;
                for (uint32_t slot = 0; slot < slot_count; ++slot) {
                    size_t bin = static_cast<size_t>(chunk) * slot_count + slot;
                    if (bin < state.table.size() && slot < slots.size()) {
                        decoded[sb][slice][bin] = slots[slot] % plain_modulus;
                    }
                }
            }
        }
    }

    std::vector<bool> sub_item_match(state.table.size(), false);
    for (uint32_t bin = 0; bin < state.table.size(); ++bin) {
        if (!state.table[bin].real) continue;
        for (uint32_t sb = 0; sb < response.alpha_sub_bins; ++sb) {
            bool all_slices_zero = true;
            for (uint32_t slice = 0; slice < response.slice_count; ++slice) {
                all_slices_zero = all_slices_zero && (decoded[sb][slice][bin] == 0);
            }
            if (all_slices_zero) {
                sub_item_match[bin] = true;
                break;
            }
        }
    }

    uint64_t cardinality = 0;
    for (const auto& bins : state.token_bins) {
        bool all_vbf_sub_items_match = true;
        for (uint32_t bin : bins) {
            all_vbf_sub_items_match = all_vbf_sub_items_match && sub_item_match[bin];
        }
        if (all_vbf_sub_items_match) ++cardinality;
    }
    return cardinality;
}

}  // namespace upsica::protocol
