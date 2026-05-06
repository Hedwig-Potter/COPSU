#include "upsica/preparation_phase.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <unordered_set>
#include <vector>

#include "upsica/dh_oprf.h"

#if UPSICA_ENABLE_SEAL
#include <seal/seal.h>
#endif

namespace {

uint64_t SplitMix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

uint64_t ResolvePlainModulusValue(const upsica::protocol::ProtocolConfig& config) {
#if UPSICA_ENABLE_SEAL
    return seal::PlainModulus::Batching(config.fhe_poly_modulus_degree, config.fhe_plain_modulus_bits).value();
#else
    // Kept for non-SEAL builds; production path uses SEAL-provided modulus.
    return (1ULL << std::min<uint32_t>(config.fhe_plain_modulus_bits, 31)) - 1;
#endif
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

EncodedSlices EncodeThreeSlicesWithOprf(upsica::crypto::ShuffledDhOprf& oprf,
                                        uint64_t item,
                                        uint64_t modulus) {
    auto item_bytes = ItemToBytes(item);
    std::vector<uint8_t> blind;
    auto blinded = oprf.Blind(item_bytes, blind);
    auto evaluated = oprf.Evaluate(blinded);
    auto oprf_out = oprf.Unblind(evaluated, blind);

    EncodedSlices out;
    out.x1 = LoadU64Mod(oprf_out, 0, modulus);
    out.x2 = LoadU64Mod(oprf_out, 8, modulus);
    out.x3 = LoadU64Mod(oprf_out, 16, modulus);
    return out;
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

std::vector<uint64_t> DedupPreserve(const std::vector<uint64_t>& in) {
    std::vector<uint64_t> out;
    out.reserve(in.size());
    std::unordered_set<uint64_t> seen;
    for (uint64_t v : in) {
        if (seen.insert(v).second) {
            out.push_back(v);
        }
    }
    return out;
}

upsica::protocol::PackedPolynomialCoefficients PackCoefficientsByDegree(
    const std::vector<upsica::ds::PolynomialLink>& polys,
    uint32_t slot_count) {
    upsica::protocol::PackedPolynomialCoefficients packed;
    size_t max_degree = 0;
    for (const auto& p : polys) {
        if (!p.coefficients.empty()) {
            max_degree = std::max(max_degree, p.coefficients.size() - 1);
        }
    }
    packed.max_degree = static_cast<uint32_t>(max_degree);
    packed.coeffs_by_degree.resize(max_degree + 1);

    for (size_t d = 0; d <= max_degree; ++d) {
        std::vector<uint64_t> slots(slot_count, 0);
        for (uint32_t b = 0; b < slot_count; ++b) {
            if (d < polys[b].coefficients.size()) {
                slots[b] = polys[b].coefficients[d];
            }
        }
        packed.coeffs_by_degree[d] = upsica::crypto::Plaintext{std::move(slots)};
    }
    return packed;
}

uint32_t ChooseSubBinForSlice(const std::vector<std::vector<EncodedSlices>>& sub_bins,
                              const EncodedSlices& s) {
    // Prefer a sub-bin that does not yet contain x1 collision.
    uint32_t best = 0;
    size_t best_size = std::numeric_limits<size_t>::max();
    for (uint32_t i = 0; i < sub_bins.size(); ++i) {
        bool has_same_x1 = false;
        for (const auto& existing : sub_bins[i]) {
            if (existing.x1 == s.x1) {
                has_same_x1 = true;
                break;
            }
        }
        if (!has_same_x1) {
            if (sub_bins[i].size() < best_size) {
                best_size = sub_bins[i].size();
                best = i;
            }
        }
    }

    // If all sub-bins already have the same x1, fall back to balanced placement.
    if (best_size == std::numeric_limits<size_t>::max()) {
        for (uint32_t i = 0; i < sub_bins.size(); ++i) {
            if (sub_bins[i].size() < best_size) {
                best_size = sub_bins[i].size();
                best = i;
            }
        }
    }
    return best;
}

}  // namespace

namespace upsica::protocol {

PreparationOutput RunPreparation(const std::vector<uint64_t>& sender_set, const ProtocolConfig& config) {
    PreparationOutput output;
    output.config = config;
    output.plain_modulus = ResolvePlainModulusValue(config);
    output.slot_count = config.fhe_poly_modulus_degree;
    output.alpha_sub_bins = std::max<uint32_t>(1, config.alpha_sub_bins);

    // Step 1: enforce Slot == Bin.
    output.config.bin_count = output.slot_count;
    const uint32_t bin_count = output.config.bin_count;
    const uint32_t k = std::max<uint32_t>(1, output.config.cuckoo_hash_num);

    output.bin_polynomials.resize(bin_count);

    // Priority-2: initialize sender OPRF secret key.
    upsica::crypto::ShuffledDhOprf oprf({"sha256_to_curve", "sha256"});
    auto keypair = oprf.GenerateKeypair();
    output.oprf_secret_key_hex = keypair.secret_key;

    // (1) Sender-side OPRF-to-slice mapping, all values in Z_t.
    std::vector<std::vector<EncodedSlices>> sender_bins_2d(bin_count);
    output.sender_oprf_values.reserve(sender_set.size());
    for (uint64_t item : sender_set) {
        EncodedSlices s = EncodeThreeSlicesWithOprf(oprf, item, output.plain_modulus);
        output.sender_oprf_values.push_back(s.x1);

        // Step 2: Sender 2D Simple Hash - insert into all candidate bins.
        auto bins = CandidateBins(s.x1, bin_count, k);
        for (uint32_t b : bins) {
            sender_bins_2d[b].push_back(s);
        }
    }

    std::vector<std::vector<upsica::ds::PolynomialLink>> root_polys_by_subbin(
        output.alpha_sub_bins, std::vector<upsica::ds::PolynomialLink>(bin_count));
    std::vector<std::vector<upsica::ds::PolynomialLink>> link2_polys_by_subbin(
        output.alpha_sub_bins, std::vector<upsica::ds::PolynomialLink>(bin_count));
    std::vector<std::vector<upsica::ds::PolynomialLink>> link3_polys_by_subbin(
        output.alpha_sub_bins, std::vector<upsica::ds::PolynomialLink>(bin_count));

    // (2) Build bin-wise low-degree root polynomial and polynomial links from 2D hashed bins.
    for (uint32_t b = 0; b < bin_count; ++b) {
        auto& bundle = output.bin_polynomials[b];
        const auto& elems = sender_bins_2d[b];
        bundle.sender_points = static_cast<uint32_t>(elems.size());
        bundle.sub_bin_points.assign(output.alpha_sub_bins, 0);

        std::vector<std::vector<EncodedSlices>> sub_bins(output.alpha_sub_bins);
        for (const auto& e : elems) {
            uint32_t sb = ChooseSubBinForSlice(sub_bins, e);
            sub_bins[sb].push_back(e);
        }

        for (uint32_t sb = 0; sb < output.alpha_sub_bins; ++sb) {
            bundle.sub_bin_points[sb] = static_cast<uint32_t>(sub_bins[sb].size());
        }

        for (uint32_t sb = 0; sb < output.alpha_sub_bins; ++sb) {
            const auto& sub = sub_bins[sb];
            if (sub.empty()) {
                root_polys_by_subbin[sb][b] = upsica::ds::PolynomialLink{{1}};
                link2_polys_by_subbin[sb][b] = upsica::ds::PolynomialLink{{0}};
                link3_polys_by_subbin[sb][b] = upsica::ds::PolynomialLink{{0}};
                continue;
            }

            std::vector<uint64_t> x1;
            std::vector<uint64_t> x2;
            std::vector<uint64_t> x3;
            x1.reserve(sub.size());
            x2.reserve(sub.size());
            x3.reserve(sub.size());
            for (const auto& e : sub) {
                x1.push_back(e.x1);
                x2.push_back(e.x2);
                x3.push_back(e.x3);
            }

            x1 = DedupPreserve(x1);

            // For links, keep consistent pairs for deduped x1.
            std::vector<uint64_t> x2_dedup;
            std::vector<uint64_t> x3_dedup;
            x2_dedup.reserve(x1.size());
            x3_dedup.reserve(x1.size());
            for (uint64_t xv : x1) {
                for (const auto& e : sub) {
                    if (e.x1 == xv) {
                        x2_dedup.push_back(e.x2);
                        x3_dedup.push_back(e.x3);
                        break;
                    }
                }
            }

            root_polys_by_subbin[sb][b] = upsica::ds::BuildRootPolynomialMod(x1, output.plain_modulus);
            if (config.enable_polynomial_links) {
                link2_polys_by_subbin[sb][b] =
                    upsica::ds::BuildInterpolationPolynomialMod(x1, x2_dedup, output.plain_modulus);
                link3_polys_by_subbin[sb][b] =
                    upsica::ds::BuildInterpolationPolynomialMod(x1, x3_dedup, output.plain_modulus);
            } else {
                link2_polys_by_subbin[sb][b] = upsica::ds::PolynomialLink{{0}};
                link3_polys_by_subbin[sb][b] = upsica::ds::PolynomialLink{{0}};
            }
        }
    }

    // Step 1: pack coefficients by degree where slot index equals bin index, for each sub-bin.
    output.packed_root_coeffs_by_subbin.resize(output.alpha_sub_bins);
    output.packed_link2_coeffs_by_subbin.resize(output.alpha_sub_bins);
    output.packed_link3_coeffs_by_subbin.resize(output.alpha_sub_bins);
    for (uint32_t sb = 0; sb < output.alpha_sub_bins; ++sb) {
        output.packed_root_coeffs_by_subbin[sb] =
            PackCoefficientsByDegree(root_polys_by_subbin[sb], output.slot_count);
        output.packed_link2_coeffs_by_subbin[sb] =
            PackCoefficientsByDegree(link2_polys_by_subbin[sb], output.slot_count);
        output.packed_link3_coeffs_by_subbin[sb] =
            PackCoefficientsByDegree(link3_polys_by_subbin[sb], output.slot_count);
    }

    return output;
}

}  // namespace upsica::protocol
