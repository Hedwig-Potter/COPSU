#include "upsica/dh_oprf.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

namespace upsica::crypto {

namespace {

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using EC_GROUP_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("invalid hex length");
    }
    std::vector<uint8_t> out(hex.size() / 2, 0);
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + c - 'a');
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + c - 'A');
        throw std::runtime_error("invalid hex char");
    };
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return out;
}

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int out_len = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &out_len, EVP_sha256(), nullptr);
    digest.resize(out_len);
    return digest;
}

std::vector<uint8_t> BNToBytes(const BIGNUM* bn, size_t width) {
    std::vector<uint8_t> out(width, 0);
    int bn_len = BN_num_bytes(bn);
    if (bn_len > static_cast<int>(width)) {
        throw std::runtime_error("bn width overflow");
    }
    BN_bn2bin(bn, out.data() + (width - bn_len));
    return out;
}

BN_ptr BytesToBN(const std::vector<uint8_t>& bytes) {
    BIGNUM* raw = BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
    if (!raw) {
        throw std::runtime_error("BN_bin2bn failed");
    }
    return BN_ptr(raw, BN_free);
}

}  // namespace

ShuffledDhOprf::ShuffledDhOprf(OprfConfig config) : config_(std::move(config)) {}

OprfKeypair ShuffledDhOprf::GenerateKeypair() {
    EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
    if (!group) {
        throw std::runtime_error("failed to create EC group");
    }
    BN_CTX_ptr bn_ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr order(BN_new(), BN_free);
    if (!bn_ctx || !order || !EC_GROUP_get_order(group.get(), order.get(), bn_ctx.get())) {
        throw std::runtime_error("failed to get group order");
    }

    BN_ptr sk(BN_new(), BN_free);
    do {
        if (!BN_rand_range(sk.get(), order.get())) {
            throw std::runtime_error("failed to sample secret key");
        }
    } while (BN_is_zero(sk.get()));

    EC_POINT_ptr pk(EC_POINT_new(group.get()), EC_POINT_free);
    if (!pk || !EC_POINT_mul(group.get(), pk.get(), sk.get(), nullptr, nullptr, bn_ctx.get())) {
        throw std::runtime_error("failed to derive public key");
    }

    secret_key_hex_ = BytesToHex(BNToBytes(sk.get(), 32));

    size_t pk_len = EC_POINT_point2oct(group.get(), pk.get(), POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());
    std::vector<uint8_t> pk_bytes(pk_len);
    EC_POINT_point2oct(group.get(), pk.get(), POINT_CONVERSION_COMPRESSED, pk_bytes.data(), pk_bytes.size(), bn_ctx.get());
    return {secret_key_hex_, BytesToHex(pk_bytes)};
}

OprfMessage ShuffledDhOprf::Blind(const std::vector<uint8_t>& element, std::vector<uint8_t>& blind_factor) const {
    EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
    BN_CTX_ptr bn_ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr order(BN_new(), BN_free);
    if (!group || !bn_ctx || !order || !EC_GROUP_get_order(group.get(), order.get(), bn_ctx.get())) {
        throw std::runtime_error("failed to init EC params in Blind");
    }

    auto digest = Sha256(element);
    BN_ptr h_scalar = BytesToBN(digest);
    BN_mod(h_scalar.get(), h_scalar.get(), order.get(), bn_ctx.get());
    if (BN_is_zero(h_scalar.get())) {
        BN_one(h_scalar.get());
    }

    EC_POINT_ptr h_point(EC_POINT_new(group.get()), EC_POINT_free);
    EC_POINT_mul(group.get(), h_point.get(), h_scalar.get(), nullptr, nullptr, bn_ctx.get());

    BN_ptr beta(BN_new(), BN_free);
    do {
        if (!BN_rand_range(beta.get(), order.get())) {
            throw std::runtime_error("failed to sample blind factor");
        }
    } while (BN_is_zero(beta.get()));

    EC_POINT_ptr blinded(EC_POINT_new(group.get()), EC_POINT_free);
    EC_POINT_mul(group.get(), blinded.get(), nullptr, h_point.get(), beta.get(), bn_ctx.get());

    blind_factor = BNToBytes(beta.get(), 32);
    size_t out_len = EC_POINT_point2oct(group.get(), blinded.get(), POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());
    std::vector<uint8_t> payload(out_len);
    EC_POINT_point2oct(group.get(), blinded.get(), POINT_CONVERSION_COMPRESSED, payload.data(), payload.size(), bn_ctx.get());
    return {payload};
}

OprfMessage ShuffledDhOprf::Evaluate(const OprfMessage& blinded) const {
    if (secret_key_hex_.empty()) {
        throw std::runtime_error("sender key is not initialized");
    }

    EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
    BN_CTX_ptr bn_ctx(BN_CTX_new(), BN_CTX_free);
    if (!group || !bn_ctx) {
        throw std::runtime_error("failed to init EC params in Evaluate");
    }

    auto sk_bytes = HexToBytes(secret_key_hex_);
    BN_ptr sk = BytesToBN(sk_bytes);

    EC_POINT_ptr in_point(EC_POINT_new(group.get()), EC_POINT_free);
    if (!EC_POINT_oct2point(group.get(), in_point.get(), blinded.payload.data(), blinded.payload.size(), bn_ctx.get())) {
        throw std::runtime_error("invalid blinded point");
    }

    EC_POINT_ptr out_point(EC_POINT_new(group.get()), EC_POINT_free);
    EC_POINT_mul(group.get(), out_point.get(), nullptr, in_point.get(), sk.get(), bn_ctx.get());

    size_t out_len = EC_POINT_point2oct(group.get(), out_point.get(), POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());
    std::vector<uint8_t> payload(out_len);
    EC_POINT_point2oct(group.get(), out_point.get(), POINT_CONVERSION_COMPRESSED, payload.data(), payload.size(), bn_ctx.get());
    return {payload};
}

std::vector<OprfMessage> ShuffledDhOprf::EvaluateBatchShuffled(const std::vector<OprfMessage>& blinded_batch,
                                                               std::vector<size_t>& permutation) const {
    std::vector<OprfMessage> evaluated;
    evaluated.reserve(blinded_batch.size());
    for (const auto& msg : blinded_batch) {
        evaluated.push_back(Evaluate(msg));
    }

    permutation.resize(blinded_batch.size());
    for (size_t i = 0; i < permutation.size(); ++i) {
        permutation[i] = i;
    }
    std::mt19937_64 rng(static_cast<uint64_t>(std::random_device{}()));
    std::shuffle(permutation.begin(), permutation.end(), rng);

    std::vector<OprfMessage> shuffled;
    shuffled.reserve(evaluated.size());
    for (size_t idx : permutation) {
        shuffled.push_back(evaluated[idx]);
    }
    return shuffled;
}

std::vector<uint8_t> ShuffledDhOprf::Unblind(const OprfMessage& evaluated,
                                             const std::vector<uint8_t>& blind_factor) const {
    EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
    BN_CTX_ptr bn_ctx(BN_CTX_new(), BN_CTX_free);
    BN_ptr order(BN_new(), BN_free);
    if (!group || !bn_ctx || !order || !EC_GROUP_get_order(group.get(), order.get(), bn_ctx.get())) {
        throw std::runtime_error("failed to init EC params in Unblind");
    }

    BN_ptr beta = BytesToBN(blind_factor);
    BN_mod(beta.get(), beta.get(), order.get(), bn_ctx.get());
    if (BN_is_zero(beta.get())) {
        throw std::runtime_error("invalid blind factor");
    }

    BN_ptr beta_inv(BN_mod_inverse(nullptr, beta.get(), order.get(), bn_ctx.get()), BN_free);
    if (!beta_inv) {
        throw std::runtime_error("failed to invert blind factor");
    }

    // Load evaluated point.
    EC_POINT_ptr eval_point(EC_POINT_new(group.get()), EC_POINT_free);
    if (!EC_POINT_oct2point(group.get(), eval_point.get(), evaluated.payload.data(), evaluated.payload.size(), bn_ctx.get())) {
        throw std::runtime_error("invalid evaluated point");
    }

    EC_POINT_ptr unblinded(EC_POINT_new(group.get()), EC_POINT_free);
    EC_POINT_mul(group.get(), unblinded.get(), nullptr, eval_point.get(), beta_inv.get(), bn_ctx.get());

    size_t pt_len = EC_POINT_point2oct(group.get(), unblinded.get(), POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx.get());
    std::vector<uint8_t> pt_bytes(pt_len);
    EC_POINT_point2oct(group.get(), unblinded.get(), POINT_CONVERSION_COMPRESSED, pt_bytes.data(), pt_bytes.size(), bn_ctx.get());
    return Sha256(pt_bytes);
}

void ShuffledDhOprf::ImportSecretKeyHex(const std::string& secret_key_hex) {
    secret_key_hex_ = secret_key_hex;
}

std::string ShuffledDhOprf::ExportSecretKeyHex() const {
    return secret_key_hex_;
}

}  // namespace upsica::crypto
