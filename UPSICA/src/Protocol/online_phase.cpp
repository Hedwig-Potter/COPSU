#include "upsica/online_phase.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <unordered_set>

#include "upsica/fhe_wrapper.h"
#include "upsica/dh_oprf.h"

namespace {

uint64_t SplitMix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

struct EncodedSlices {
    uint64_t x1 = 0;
    uint64_t x2 = 0;
    uint64_t x3 = 0;
};

std::vector<uint8_t> ItemToBytes(uint64_t item) {
    std::vector<uint8_t> out(8, 0);
    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((item >> (8 * i)) & 0xFFu);
    }
    return out;
}

uint64_t LoadU64Mod(const std::vector<uint8_t>& bytes, size_t offset, uint64_t modulus) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        size_t idx = (offset + i) % bytes.size();
        v |= (static_cast<uint64_t>(bytes[idx]) << (8 * i));
    }
    return v % modulus;
}

std::vector<uint32_t> CandidateBins(uint64_t x1, uint32_t bin_count, uint32_t k) {
    if (bin_count == 0) {
        return {0};
    }
    std::vector<uint32_t> out;
    out.reserve(k);
    std::unordered_set<uint32_t> used;
    for (uint32_t i = 0; i < k; ++i) {
        uint64_t h = SplitMix64(x1 ^ (0x9e3779b97f4a7c15ULL + 0x100000001b3ULL * (i + 1)));
        uint32_t idx = static_cast<uint32_t>(h % bin_count);
        if (used.insert(idx).second) {
            out.push_back(idx);
        }
    }
    if (out.empty()) {
        out.push_back(static_cast<uint32_t>(x1 % bin_count));
    }
    return out;
}

}  // namespace

namespace upsica::protocol {

OnlineOutput RunOnline(const std::vector<uint64_t>& receiver_set, const PreparationOutput& prep_output) {
    OnlineOutput output;

    if (prep_output.plain_modulus == 0) {
        throw std::runtime_error("invalid preparation output: plain_modulus must be non-zero");
    }
    const uint32_t bin_count = std::max<uint32_t>(1, prep_output.config.bin_count);
    if (prep_output.bin_polynomials.size() != bin_count) {
        throw std::runtime_error("invalid preparation output: bin polynomial count mismatch");
    }
    if (prep_output.slot_count != bin_count) {
        throw std::runtime_error("slot/bin mismatch: expected slot_count == bin_count");
    }
    if (prep_output.alpha_sub_bins == 0) {
        throw std::runtime_error("invalid preparation output: alpha_sub_bins must be >= 1");
    }
    if (prep_output.packed_root_coeffs_by_subbin.size() != prep_output.alpha_sub_bins ||
        prep_output.packed_link2_coeffs_by_subbin.size() != prep_output.alpha_sub_bins ||
        prep_output.packed_link3_coeffs_by_subbin.size() != prep_output.alpha_sub_bins) {
        throw std::runtime_error("invalid preparation output: packed sub-bin coefficient count mismatch");
    }
    output.bin_count = bin_count;
    output.alpha_sub_bins = prep_output.alpha_sub_bins;

    std::unordered_set<uint64_t> unique_matches;
    const uint32_t k = std::max<uint32_t>(1, prep_output.config.cuckoo_hash_num);

    // (1) Receiver-side slice encoding.
    struct ReceiverQuery {
        EncodedSlices slices;
        uint64_t original_item = 0;
    };

    struct CuckooSlot {
        bool occupied = false;
        bool real = false;
        ReceiverQuery query;
    };

    std::vector<CuckooSlot> slots(bin_count);
    output.receiver_oprf_values.reserve(receiver_set.size());

    // Priority-2: real shuffled DH-OPRF for receiver queries.
    upsica::crypto::ShuffledDhOprf oprf({"sha256_to_curve", "sha256"});
    oprf.ImportSecretKeyHex(prep_output.oprf_secret_key_hex);

    std::vector<upsica::crypto::OprfMessage> blinded_msgs;
    std::vector<std::vector<uint8_t>> blind_factors;
    blinded_msgs.reserve(receiver_set.size());
    blind_factors.reserve(receiver_set.size());
    for (uint64_t item : receiver_set) {
        std::vector<uint8_t> blind;
        auto blinded = oprf.Blind(ItemToBytes(item), blind);
        blinded_msgs.push_back(std::move(blinded));
        blind_factors.push_back(std::move(blind));
    }

    std::vector<size_t> permutation;
    auto shuffled_eval = oprf.EvaluateBatchShuffled(blinded_msgs, permutation);

    std::vector<std::vector<uint8_t>> unblinded_by_index(receiver_set.size());
    for (size_t i = 0; i < shuffled_eval.size(); ++i) {
        size_t original_idx = permutation[i];
        unblinded_by_index[original_idx] = oprf.Unblind(shuffled_eval[i], blind_factors[original_idx]);
    }

    std::mt19937_64 prng(prep_output.config.dummy_seed);
    std::uniform_int_distribution<uint64_t> dist(0, prep_output.plain_modulus - 1);

    auto insert_cuckoo = [&](const ReceiverQuery& q) {
        auto candidate_bins = CandidateBins(q.slices.x1, bin_count, k);
        for (uint32_t b : candidate_bins) {
            if (!slots[b].occupied) {
                slots[b].occupied = true;
                slots[b].real = true;
                slots[b].query = q;
                return true;
            }
        }

        ReceiverQuery cur = q;
        uint32_t cur_bin = candidate_bins[SplitMix64(q.slices.x1) % candidate_bins.size()];
        for (uint32_t kick = 0; kick < prep_output.config.cuckoo_max_kicks; ++kick) {
            std::swap(cur, slots[cur_bin].query);
            slots[cur_bin].occupied = true;
            slots[cur_bin].real = true;

            auto evicted_bins = CandidateBins(cur.slices.x1, bin_count, k);
            bool placed = false;
            for (uint32_t b : evicted_bins) {
                if (!slots[b].occupied) {
                    slots[b].occupied = true;
                    slots[b].real = true;
                    slots[b].query = cur;
                    placed = true;
                    break;
                }
            }
            if (placed) {
                return true;
            }
            cur_bin = evicted_bins[SplitMix64(cur.slices.x1 ^ kick) % evicted_bins.size()];
        }
        return false;
    };

    for (size_t idx = 0; idx < receiver_set.size(); ++idx) {
        EncodedSlices s;
        s.x1 = LoadU64Mod(unblinded_by_index[idx], 0, prep_output.plain_modulus);
        s.x2 = LoadU64Mod(unblinded_by_index[idx], 8, prep_output.plain_modulus);
        s.x3 = LoadU64Mod(unblinded_by_index[idx], 16, prep_output.plain_modulus);
        output.receiver_oprf_values.push_back(s.x1);
        if (insert_cuckoo(ReceiverQuery{s, receiver_set[idx]})) {
            output.cuckoo_items_placed += 1;
        } else {
            output.cuckoo_items_dropped += 1;
        }
    }

    // Fill empty slots with random dummy elements to hide sparsity.
    for (uint32_t b = 0; b < bin_count; ++b) {
        if (!slots[b].occupied) {
            slots[b].occupied = true;
            slots[b].real = false;
            slots[b].query.slices.x1 = dist(prng);
            slots[b].query.slices.x2 = dist(prng);
            slots[b].query.slices.x3 = dist(prng);
            slots[b].query.original_item = 0;
        }
    }

#if UPSICA_ENABLE_SEAL
    // Receiver: generate keys/context and encrypt query root slices.
    upsica::crypto::FheParams fhe_params;
    fhe_params.poly_modulus_degree = prep_output.config.fhe_poly_modulus_degree;
    fhe_params.plain_modulus_bits = prep_output.config.fhe_plain_modulus_bits;

    upsica::crypto::FheWrapper receiver_fhe(fhe_params);
    receiver_fhe.Initialize();

    output.used_fhe_online = true;
    output.used_polynomial_links = prep_output.config.enable_polynomial_links;
    output.used_cuckoo_hashing = true;
    output.used_sender_simple_hashing = true;

    // Step 1 target: one Evaluate call computes all bins simultaneously (slot==bin).
    std::vector<uint64_t> x1_slots(bin_count, 0);
    for (uint32_t b = 0; b < bin_count; ++b) {
        x1_slots[b] = slots[b].query.slices.x1;
    }

    std::vector<uint64_t> x2_slots(bin_count, 0);
    std::vector<uint64_t> x3_slots(bin_count, 0);
    for (uint32_t b = 0; b < bin_count; ++b) {
        x2_slots[b] = static_cast<uint64_t>((static_cast<unsigned __int128>(x1_slots[b]) * x1_slots[b]) % prep_output.plain_modulus);
        x3_slots[b] = static_cast<uint64_t>((static_cast<unsigned __int128>(x2_slots[b]) * x1_slots[b]) % prep_output.plain_modulus);
    }

    auto enc_x1 = receiver_fhe.Encrypt(receiver_fhe.Encode(x1_slots));
    auto enc_x2 = receiver_fhe.Encrypt(receiver_fhe.Encode(x2_slots));
    auto enc_x3 = receiver_fhe.Encrypt(receiver_fhe.Encode(x3_slots));
    std::vector<upsica::crypto::Ciphertext> encrypted_powers = {enc_x1, enc_x2, enc_x3};
    output.encrypted_query_slices = encrypted_powers.size();

    // Evaluate alpha sub-bins; any sub-bin match is accepted.
    std::vector<bool> slot_matched(bin_count, false);
    for (uint32_t sb = 0; sb < prep_output.alpha_sub_bins; ++sb) {
        auto enc_p1 = receiver_fhe.EvaluatePolynomialSIMDWindowed(
            encrypted_powers, prep_output.packed_root_coeffs_by_subbin[sb].coeffs_by_degree, 3);
        output.sender_evaluated_slices += 1;
        auto dec_p1 = receiver_fhe.Decrypt(enc_p1);
        output.returned_ciphertexts += 1;

        std::vector<uint64_t> dec_p2_slots;
        std::vector<uint64_t> dec_p3_slots;
        if (prep_output.config.enable_polynomial_links) {
            auto enc_p2 = receiver_fhe.EvaluatePolynomialSIMDWindowed(
                encrypted_powers, prep_output.packed_link2_coeffs_by_subbin[sb].coeffs_by_degree, 3);
            auto enc_p3 = receiver_fhe.EvaluatePolynomialSIMDWindowed(
                encrypted_powers, prep_output.packed_link3_coeffs_by_subbin[sb].coeffs_by_degree, 3);
            output.sender_evaluated_slices += 2;
            output.returned_ciphertexts += 2;
            dec_p2_slots = receiver_fhe.Decrypt(enc_p2).slots;
            dec_p3_slots = receiver_fhe.Decrypt(enc_p3).slots;
        }

        const size_t used_slots = std::min<size_t>(bin_count, dec_p1.slots.size());
        for (size_t b = 0; b < used_slots; ++b) {
            if (!slots[b].real || slot_matched[b]) {
                continue;
            }

            uint64_t val1 = dec_p1.slots[b] % prep_output.plain_modulus;
            bool match = (val1 == 0);
            if (prep_output.config.enable_polynomial_links) {
                if (b >= dec_p2_slots.size() || b >= dec_p3_slots.size()) {
                    continue;
                }
                uint64_t val2 = dec_p2_slots[b] % prep_output.plain_modulus;
                uint64_t val3 = dec_p3_slots[b] % prep_output.plain_modulus;
                match = match && (val2 == slots[b].query.slices.x2) && (val3 == slots[b].query.slices.x3);
            }

            if (match) {
                slot_matched[b] = true;
                unique_matches.insert(slots[b].query.slices.x1);
            }
        }
    }
#else
    throw std::runtime_error("RunOnline requires UPSICA_ENABLE_SEAL=ON (plaintext fallback removed)");
#endif

    output.matched_oprf_values.assign(unique_matches.begin(), unique_matches.end());
    output.intersection_cardinality = static_cast<uint64_t>(output.matched_oprf_values.size());
    return output;
}

}  // namespace upsica::protocol
