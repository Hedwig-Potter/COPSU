#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "upsica/dh_oprf.h"
#include "upsica/fhe_wrapper.h"
#include "upsica/vbf_psi_ca.h"

namespace {

void TestSenderEvaluatorHasNoSecretKey() {
    upsica::crypto::FheParams params{4096, 20};
    upsica::crypto::FheWrapper receiver(params);
    receiver.Initialize();
    auto input = receiver.Encrypt(receiver.Encode({5, 7}));

    upsica::crypto::FheWrapper sender(params);
    sender.InitializeEvaluator(receiver.ExportEvaluationKeys());
    auto evaluated = sender.EvaluatePolynomial(input, {3, 2});
    auto decoded = receiver.Decrypt(evaluated);
    assert(decoded.slots[0] == 13 && decoded.slots[1] == 17);

    bool rejected = false;
    try {
        (void)sender.Decrypt(evaluated);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected && "Sender must not hold the FHE secret key");
}

void TestShuffledOprfUsesOneBatchBlind() {
    upsica::crypto::ShuffledDhOprf sender({"sha256_to_curve", "sha256"});
    sender.GenerateKeypair();
    const std::vector<std::vector<uint8_t>> inputs = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    const auto beta = sender.GenerateBlindFactor();
    std::vector<upsica::crypto::OprfMessage> blinded;
    for (const auto& input : inputs) blinded.push_back(sender.BlindWithFactor(input, beta));
    auto shuffled = sender.EvaluateBatchShuffled(blinded);
    std::vector<std::vector<uint8_t>> outputs;
    for (const auto& response : shuffled) outputs.push_back(sender.Unblind(response, beta));
    for (const auto& input : inputs) {
        const auto expected = sender.EvaluateInput(input);
        assert(std::find(outputs.begin(), outputs.end(), expected) != outputs.end());
    }
}

upsica::protocol::VbfPsiCaConfig SmallConfig() {
    upsica::protocol::VbfPsiCaConfig config;
    config.bin_count = 64;
    config.alpha_sub_bins = 4;
    config.kv = 2;
    config.vbf_item_bits = 46;
    config.slice_bits = 19;
    config.poly_modulus_degree = 4096;
    return config;
}

void TestVbfSenderPreparationUsesThreeBinsAndAllSlices() {
    auto config = SmallConfig();
    std::vector<upsica::protocol::ItemBytes> sender = {{1}, {2}, {3}, {4}};
    auto prep = upsica::protocol::PrepareVbfPsiCaSender(sender, config);
    assert(prep.slice_count == 3);
    uint64_t inserted = 0;
    for (const auto& bin : prep.sub_bin_sizes)
        for (uint32_t count : bin) inserted += count;
    assert(inserted == sender.size() * config.kv * config.hash_function_count);
    for (const auto& bin : prep.polynomials)
        for (const auto& sub_bin : bin) assert(sub_bin.size() == prep.slice_count);
}

void TestVbfPsiCaEncryptedEndToEnd() {
    auto config = SmallConfig();
    std::vector<upsica::protocol::ItemBytes> sender = {{10}, {20}, {30}, {40}};
    std::vector<upsica::protocol::ItemBytes> receiver = {{30}, {40}, {99}};
    auto preparation = upsica::protocol::PrepareVbfPsiCaSender(sender, config);
    auto batch = upsica::protocol::CreateReceiverOprfBatch(receiver);
    auto responses = upsica::protocol::EvaluateReceiverOprfBatch(
        preparation, batch.blinded_inputs);
    auto state = upsica::protocol::BuildReceiverVbfState(batch, responses, config);

    upsica::crypto::FheWrapper receiver_fhe(
        {config.poly_modulus_degree, config.plain_modulus_bits});
    receiver_fhe.Initialize();
    auto query = upsica::protocol::EncryptReceiverVbfQuery(
        state, preparation.maximum_sub_bin_degree,
        receiver_fhe, preparation.plain_modulus);
    auto encrypted_response = upsica::protocol::EvaluateEncryptedVbfQuery(preparation, query);
    auto cardinality = upsica::protocol::DecryptIntersectionCardinality(
        state, encrypted_response, receiver_fhe, preparation.plain_modulus);
    assert(cardinality == 2);
}

void TestReal128BitElements() {
    auto config = SmallConfig();
    upsica::protocol::ItemBytes common(16, 0xA5);
    upsica::protocol::ItemBytes sender_only(16, 0x5A);
    upsica::protocol::ItemBytes receiver_only(16, 0x3C);
    auto preparation = upsica::protocol::PrepareVbfPsiCaSender(
        {common, sender_only}, config);
    auto batch = upsica::protocol::CreateReceiverOprfBatch({common, receiver_only});
    auto responses = upsica::protocol::EvaluateReceiverOprfBatch(
        preparation, batch.blinded_inputs);
    auto state = upsica::protocol::BuildReceiverVbfState(batch, responses, config);
    upsica::crypto::FheWrapper receiver_fhe({4096, 20});
    receiver_fhe.Initialize();
    auto query = upsica::protocol::EncryptReceiverVbfQuery(
        state, preparation.maximum_sub_bin_degree, receiver_fhe, preparation.plain_modulus);
    auto response = upsica::protocol::EvaluateEncryptedVbfQuery(preparation, query);
    assert(upsica::protocol::DecryptIntersectionCardinality(
               state, response, receiver_fhe, preparation.plain_modulus) == 1);
}

}  // namespace

int main() {
    TestSenderEvaluatorHasNoSecretKey();
    TestShuffledOprfUsesOneBatchBlind();
    TestVbfSenderPreparationUsesThreeBinsAndAllSlices();
    TestVbfPsiCaEncryptedEndToEnd();
    TestReal128BitElements();
    std::cout << "All UPSICA VBF+slicing tests passed.\n";
}
