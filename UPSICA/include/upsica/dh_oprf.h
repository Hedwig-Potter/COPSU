#pragma once

#include <string>
#include <vector>

namespace upsica::crypto {

struct OprfConfig {
    std::string hash_to_group;
    std::string hash_to_output;
};

struct OprfKeypair {
    std::string secret_key;
    std::string public_key;
};

struct OprfMessage {
    std::vector<uint8_t> payload;
};

class ShuffledDhOprf {
public:
    explicit ShuffledDhOprf(OprfConfig config);

    OprfKeypair GenerateKeypair();
    OprfMessage Blind(const std::vector<uint8_t>& element, std::vector<uint8_t>& blind_factor) const;
    OprfMessage Evaluate(const OprfMessage& blinded) const;
    std::vector<OprfMessage> EvaluateBatchShuffled(const std::vector<OprfMessage>& blinded_batch,
                                                   std::vector<size_t>& permutation) const;
    std::vector<uint8_t> Unblind(const OprfMessage& evaluated, const std::vector<uint8_t>& blind_factor) const;

    void ImportSecretKeyHex(const std::string& secret_key_hex);
    std::string ExportSecretKeyHex() const;

private:
    OprfConfig config_;
    mutable std::string secret_key_hex_;
};

}  // namespace upsica::crypto
