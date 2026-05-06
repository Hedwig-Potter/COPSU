#include "upsica/fhe_wrapper.h"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <stdexcept>

namespace upsica::crypto {

namespace {

std::vector<uint8_t> SerializeCiphertext(
#if UPSICA_ENABLE_SEAL
    const seal::Ciphertext& ct
#else
    const std::vector<uint8_t>& ct
#endif
) {
#if UPSICA_ENABLE_SEAL
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    ct.save(ss);
    const std::string buffer = ss.str();
    return std::vector<uint8_t>(buffer.begin(), buffer.end());
#else
    return ct;
#endif
}

}  // namespace

FheWrapper::FheWrapper(FheParams params) : params_(params) {}

void FheWrapper::Initialize() {
#if UPSICA_ENABLE_SEAL
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(params_.poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(params_.poly_modulus_degree));
    parms.set_plain_modulus(
        seal::PlainModulus::Batching(params_.poly_modulus_degree, params_.plain_modulus_bits));

    context_ = std::make_shared<seal::SEALContext>(parms);
    if (!context_ || !context_->parameters_set()) {
        throw std::runtime_error("SEAL context initialization failed");
    }

    seal::KeyGenerator keygen(*context_);
    secret_key_ = keygen.secret_key();
    keygen.create_public_key(public_key_);
    keygen.create_relin_keys(relin_keys_);

    encoder_ = std::make_unique<seal::BatchEncoder>(*context_);
    encryptor_ = std::make_unique<seal::Encryptor>(*context_, public_key_);
    decryptor_ = std::make_unique<seal::Decryptor>(*context_, secret_key_);
    evaluator_ = std::make_unique<seal::Evaluator>(*context_);

    slot_count_ = encoder_->slot_count();
    initialized_ = true;
#else
    initialized_ = true;
#endif
}

Plaintext FheWrapper::Encode(const std::vector<uint64_t>& slots) const {
    return {slots};
}

Ciphertext FheWrapper::Encrypt(const Plaintext& pt) const {
#if UPSICA_ENABLE_SEAL
    if (!initialized_) {
        throw std::runtime_error("FheWrapper::Initialize must be called before Encrypt");
    }

    std::vector<uint64_t> padded(slot_count_, 0);
    const size_t copy_count = std::min(pt.slots.size(), padded.size());
    std::copy_n(pt.slots.begin(), copy_count, padded.begin());

    seal::Plaintext encoded;
    encoder_->encode(padded, encoded);

    seal::Ciphertext encrypted;
    encryptor_->encrypt(encoded, encrypted);
    return {SerializeCiphertext(encrypted)};
#else
    return {std::vector<uint8_t>(pt.slots.size() * sizeof(uint64_t))};
#endif
}

Plaintext FheWrapper::Decrypt(const Ciphertext& ct) const {
#if UPSICA_ENABLE_SEAL
    if (!initialized_) {
        throw std::runtime_error("FheWrapper::Initialize must be called before Decrypt");
    }

    seal::Ciphertext encrypted;
    std::string buffer(ct.data.begin(), ct.data.end());
    std::stringstream ss(buffer, std::ios::in | std::ios::binary);
    encrypted.load(*context_, ss);

    seal::Plaintext decoded_pt;
    decryptor_->decrypt(encrypted, decoded_pt);

    std::vector<uint64_t> slots;
    encoder_->decode(decoded_pt, slots);
    return {slots};
#else
    return {std::vector<uint64_t>(ct.data.size() / sizeof(uint64_t), 0)};
#endif
}

Ciphertext FheWrapper::EvaluatePolynomial(const Ciphertext& x, const std::vector<uint64_t>& coeffs) const {
#if UPSICA_ENABLE_SEAL
    if (!initialized_) {
        throw std::runtime_error("FheWrapper::Initialize must be called before EvaluatePolynomial");
    }

    if (coeffs.empty()) {
        return Encrypt(Encode({0}));
    }

    seal::Ciphertext x_ct;
    {
        std::string xbuf(x.data.begin(), x.data.end());
        std::stringstream xss(xbuf, std::ios::in | std::ios::binary);
        x_ct.load(*context_, xss);
    }

    // Horner form with ciphertext-ciphertext multiply + plaintext constant add.
    seal::Plaintext last_coeff_pt;
    encoder_->encode(std::vector<uint64_t>(slot_count_, coeffs.back()), last_coeff_pt);
    seal::Ciphertext result;
    encryptor_->encrypt(last_coeff_pt, result);

    for (size_t i = coeffs.size() - 1; i-- > 0;) {
        evaluator_->multiply_inplace(result, x_ct);
        evaluator_->relinearize_inplace(result, relin_keys_);

        seal::Plaintext coeff_pt;
        encoder_->encode(std::vector<uint64_t>(slot_count_, coeffs[i]), coeff_pt);
        evaluator_->add_plain_inplace(result, coeff_pt);
    }

    auto ctx_data = context_->get_context_data(result.parms_id());
    if (ctx_data && ctx_data->chain_index() > 0) {
        evaluator_->mod_switch_to_next_inplace(result);
    }

    return {SerializeCiphertext(result)};
#else
    (void)coeffs;
    return x;
#endif
}

Ciphertext FheWrapper::EvaluatePolynomialSIMD(const Ciphertext& x,
                                              const std::vector<Plaintext>& coeffs_by_degree) const {
#if UPSICA_ENABLE_SEAL
    if (!initialized_) {
        throw std::runtime_error("FheWrapper::Initialize must be called before EvaluatePolynomialSIMD");
    }

    if (coeffs_by_degree.empty()) {
        return Encrypt(Encode({0}));
    }

    seal::Ciphertext x_ct;
    {
        std::string xbuf(x.data.begin(), x.data.end());
        std::stringstream xss(xbuf, std::ios::in | std::ios::binary);
        x_ct.load(*context_, xss);
    }

    auto encode_slots = [&](const Plaintext& pt_slots) {
        std::vector<uint64_t> padded(slot_count_, 0);
        const size_t copy_count = std::min(pt_slots.slots.size(), padded.size());
        std::copy_n(pt_slots.slots.begin(), copy_count, padded.begin());
        seal::Plaintext pt;
        encoder_->encode(padded, pt);
        return pt;
    };

    seal::Plaintext last_coeff_pt = encode_slots(coeffs_by_degree.back());
    seal::Ciphertext result;
    encryptor_->encrypt(last_coeff_pt, result);

    for (size_t i = coeffs_by_degree.size() - 1; i-- > 0;) {
        evaluator_->multiply_inplace(result, x_ct);
        evaluator_->relinearize_inplace(result, relin_keys_);

        seal::Plaintext coeff_pt = encode_slots(coeffs_by_degree[i]);
        evaluator_->add_plain_inplace(result, coeff_pt);
    }

    auto ctx_data = context_->get_context_data(result.parms_id());
    if (ctx_data && ctx_data->chain_index() > 0) {
        evaluator_->mod_switch_to_next_inplace(result);
    }

    return {SerializeCiphertext(result)};
#else
    (void)coeffs_by_degree;
    return x;
#endif
}

Ciphertext FheWrapper::EvaluatePolynomialSIMDWindowed(const std::vector<Ciphertext>& encrypted_powers,
                                                      const std::vector<Plaintext>& coeffs_by_degree,
                                                      size_t window_size) const {
#if UPSICA_ENABLE_SEAL
    if (!initialized_) {
        throw std::runtime_error("FheWrapper::Initialize must be called before EvaluatePolynomialSIMDWindowed");
    }
    if (coeffs_by_degree.empty()) {
        return Encrypt(Encode({0}));
    }
    if (encrypted_powers.empty()) {
        throw std::runtime_error("encrypted_powers is empty");
    }

    const size_t degree = coeffs_by_degree.size() - 1;
    const size_t usable_window = std::min(window_size, encrypted_powers.size());
    if (degree > usable_window) {
        // Fallback for higher degrees; keep correctness while windowing applies to low-degree bins.
        return EvaluatePolynomialSIMD(encrypted_powers[0], coeffs_by_degree);
    }

    auto encode_slots = [&](const Plaintext& pt_slots) {
        std::vector<uint64_t> padded(slot_count_, 0);
        const size_t copy_count = std::min(pt_slots.slots.size(), padded.size());
        std::copy_n(pt_slots.slots.begin(), copy_count, padded.begin());
        seal::Plaintext pt;
        encoder_->encode(padded, pt);
        return pt;
    };

    seal::Plaintext const_pt = encode_slots(coeffs_by_degree[0]);
    seal::Ciphertext result;
    encryptor_->encrypt(const_pt, result);

    for (size_t d = 1; d <= degree; ++d) {
        seal::Ciphertext power_ct;
        {
            std::string buf(encrypted_powers[d - 1].data.begin(), encrypted_powers[d - 1].data.end());
            std::stringstream ss(buf, std::ios::in | std::ios::binary);
            power_ct.load(*context_, ss);
        }

        seal::Plaintext coeff_pt = encode_slots(coeffs_by_degree[d]);
        evaluator_->multiply_plain_inplace(power_ct, coeff_pt);
        evaluator_->add_inplace(result, power_ct);
    }

    auto ctx_data = context_->get_context_data(result.parms_id());
    if (ctx_data && ctx_data->chain_index() > 0) {
        evaluator_->mod_switch_to_next_inplace(result);
    }

    return {SerializeCiphertext(result)};
#else
    (void)encrypted_powers;
    (void)coeffs_by_degree;
    (void)window_size;
    return Ciphertext{};
#endif
}

size_t FheWrapper::SlotCount() const {
    return slot_count_;
}

}  // namespace upsica::crypto
