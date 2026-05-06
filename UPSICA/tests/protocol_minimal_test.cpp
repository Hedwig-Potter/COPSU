#include <cassert>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <vector>

#include "upsica/fhe_wrapper.h"
#include "upsica/online_phase.h"
#include "upsica/preparation_phase.h"

namespace {

uint64_t TestSplitMix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

std::pair<uint64_t, uint64_t> FindX1CollisionPair(uint64_t modulus) {
    std::unordered_map<uint64_t, uint64_t> seen;
    for (uint64_t v = 1; v < 500000; ++v) {
        uint64_t x1 = TestSplitMix64(v) % modulus;
        auto it = seen.find(x1);
        if (it != seen.end() && it->second != v) {
            return {it->second, v};
        }
        seen.emplace(x1, v);
    }
    return {0, 0};
}

void TestProtocolHappyPath() {
    const std::vector<uint64_t> sender = {10, 20, 30, 40};
    const std::vector<uint64_t> receiver = {30, 40, 99};

    upsica::protocol::ProtocolConfig config;
    config.bin_count = 16;
    config.fhe_poly_modulus_degree = 4096;
    config.alpha_sub_bins = 4;
    config.enable_polynomial_links = true;

    auto prep = upsica::protocol::RunPreparation(sender, config);
    auto out = upsica::protocol::RunOnline(receiver, prep);

    assert(out.intersection_cardinality == 2 && "Intersection cardinality should be 2");
#if UPSICA_ENABLE_SEAL
    assert(out.used_fhe_online && "FHE online path should be enabled when SEAL is available");
    assert(out.used_polynomial_links && "Polynomial links should be enabled");
    assert(out.used_cuckoo_hashing && "Receiver should use cuckoo hashing");
    assert(out.used_sender_simple_hashing && "Sender should use simple hashing");
    assert(out.bin_count == config.fhe_poly_modulus_degree && "bin_count must be aligned to slot_count");
    assert(out.alpha_sub_bins == config.alpha_sub_bins && "alpha_sub_bins mismatch");
    assert(out.encrypted_query_slices == 3 && "Windowing should send encrypted x/x^2/x^3 query powers");
    assert(out.sender_evaluated_slices == config.alpha_sub_bins * 3 &&
        "Sender should evaluate P1/P2/P3 for each sub-bin");
    assert(out.returned_ciphertexts == config.alpha_sub_bins * 3 &&
        "Sender should return three ciphertexts per sub-bin");
#endif
}

void TestProtocolEmptyReceiver() {
    const std::vector<uint64_t> sender = {1, 2, 3};
    const std::vector<uint64_t> receiver = {};

    upsica::protocol::ProtocolConfig config;
    config.fhe_poly_modulus_degree = 4096;
    config.alpha_sub_bins = 4;
    config.enable_polynomial_links = true;

    auto prep = upsica::protocol::RunPreparation(sender, config);
    auto out = upsica::protocol::RunOnline(receiver, prep);

    assert(out.intersection_cardinality == 0 && "Empty receiver set should produce zero cardinality");
}

void TestSealRoundTripAndPolynomial() {
    upsica::crypto::FheParams params;
    params.poly_modulus_degree = 8192;
    params.plain_modulus_bits = 20;

    upsica::crypto::FheWrapper fhe(params);
    fhe.Initialize();

    // p(x) = 3 + 2x, evaluated at slots [5, 7] -> [13, 17]
    auto pt = fhe.Encode({5, 7});
    auto ct = fhe.Encrypt(pt);
    auto ct_eval = fhe.EvaluatePolynomial(ct, {3, 2});
    auto pt_eval = fhe.Decrypt(ct_eval);

    assert(pt_eval.slots.size() >= 2 && "Decoded slots should contain at least two values");
    assert(pt_eval.slots[0] == 13 && "First slot polynomial evaluation mismatch");
    assert(pt_eval.slots[1] == 17 && "Second slot polynomial evaluation mismatch");
}

void TestPolynomialLinksDisabledStillRuns() {
    const std::vector<uint64_t> sender = {101, 202, 303};
    const std::vector<uint64_t> receiver = {202, 999};

    upsica::protocol::ProtocolConfig config;
    config.fhe_poly_modulus_degree = 4096;
    config.alpha_sub_bins = 4;
    config.enable_polynomial_links = false;

    auto prep = upsica::protocol::RunPreparation(sender, config);
    auto out = upsica::protocol::RunOnline(receiver, prep);

    assert(out.intersection_cardinality >= 1 && "Root-only mode should still detect at least one match");
}

void TestPartitioningHandlesX1Collision() {
    upsica::protocol::ProtocolConfig config;
    config.fhe_poly_modulus_degree = 4096;
    config.alpha_sub_bins = 4;
    config.enable_polynomial_links = true;

    // First run to resolve modulus.
    auto prep_probe = upsica::protocol::RunPreparation({1}, config);
    auto pair = FindX1CollisionPair(prep_probe.plain_modulus);
    assert(pair.first != 0 && pair.second != 0 && "Need a real x1 collision pair");

    std::vector<uint64_t> sender = {pair.first, pair.second, 777777};
    std::vector<uint64_t> receiver = {pair.first, pair.second, 888888};

    auto prep = upsica::protocol::RunPreparation(sender, config);
    auto out = upsica::protocol::RunOnline(receiver, prep);

    assert(out.intersection_cardinality >= 2 &&
           "Partitioning/sub-bins should preserve matches under x1 collision");
}

}  // namespace

int main() {
    TestProtocolHappyPath();
    TestProtocolEmptyReceiver();
    TestSealRoundTripAndPolynomial();
    TestPolynomialLinksDisabledStillRuns();
    TestPartitioningHandlesX1Collision();

    std::cout << "All UPSICA minimal tests passed.\n";
    return 0;
}
