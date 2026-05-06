#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#if UPSICA_ENABLE_SEAL
#include <seal/seal.h>
#endif

namespace upsica::crypto {

struct FheParams {
    uint32_t poly_modulus_degree = 8192;
    uint32_t plain_modulus_bits = 20;
};

struct Ciphertext {
    std::vector<uint8_t> data;
};

struct Plaintext {
    std::vector<uint64_t> slots;
};

class FheWrapper {
public:
    explicit FheWrapper(FheParams params);

    void Initialize();
    Plaintext Encode(const std::vector<uint64_t>& slots) const;
    Ciphertext Encrypt(const Plaintext& pt) const;
    Plaintext Decrypt(const Ciphertext& ct) const;

    Ciphertext EvaluatePolynomial(const Ciphertext& x, const std::vector<uint64_t>& coeffs) const;
    Ciphertext EvaluatePolynomialSIMD(const Ciphertext& x, const std::vector<Plaintext>& coeffs_by_degree) const;
    Ciphertext EvaluatePolynomialSIMDWindowed(const std::vector<Ciphertext>& encrypted_powers,
                                              const std::vector<Plaintext>& coeffs_by_degree,
                                              size_t window_size) const;

    size_t SlotCount() const;

private:
    size_t slot_count_ = 0;
    bool initialized_ = false;
    FheParams params_;

#if UPSICA_ENABLE_SEAL
    std::shared_ptr<seal::SEALContext> context_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    seal::PublicKey public_key_;
    seal::SecretKey secret_key_;
    seal::RelinKeys relin_keys_;
#endif
};

}  // namespace upsica::crypto
