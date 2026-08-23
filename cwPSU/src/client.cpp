//
// Created by Administrator on 2025/9/23.
//

#include "client.h"
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <random>
#include <numeric>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <chrono>
#include <filesystem>
#include <unordered_map>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <arpa/inet.h>
#include <endian.h>
#include <unistd.h>

#include "bcs.h"
#include "bcs_osn.h"

using namespace std;
using namespace seal;

namespace {
constexpr uint32_t kStandaloneMagic = 0x43575031U; // "CWP1"
constexpr uint32_t kStandaloneWireVersion = 2;
constexpr uint32_t kStandaloneSetupMessage = 1;
constexpr uint32_t kStandaloneBatchMessage = 2;
}

void Client::set_server_endpoint(const std::string& host, uint16_t psu_port) {
    if (host.empty()) throw std::invalid_argument("server host must not be empty");
    server_host_ = host;
    server_port_ = psu_port;
    remote_server_ = true;
}

void Client::start_permute_share_service() {
    if (permute_share_thread_.joinable()) {
        return;
    }

    const char* port_env = std::getenv("PSU_PERMUTE_PORT");
    if (port_env && port_env[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(port_env, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            permute_share_port_ = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_PERMUTE_PORT='" << port_env
                      << "', fallback to " << permute_share_port_ << std::endl;
        }
    }

    permute_share_stop_.store(false, std::memory_order_release);
    permute_share_thread_ = std::thread(&Client::serve_permute_share_requests, this);
}

void Client::stop_permute_share_service() {
    permute_share_stop_.store(true, std::memory_order_release);

    if (permute_listen_fd_ != -1) {
        int wake_fd = net::connect_socket("127.0.0.1", permute_share_port_);
        if (wake_fd >= 0) {
            ::close(wake_fd);
        }
    }

    if (permute_share_thread_.joinable()) {
        permute_share_thread_.join();
    }
}

void Client::serve_permute_share_requests() {
    permute_listen_fd_ = net::create_listen_socket(permute_share_port_);
    if (permute_listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to open permute-share listen socket on port "
                  << permute_share_port_ << std::endl;
        return;
    }

    while (!permute_share_stop_.load(std::memory_order_acquire)) {
        int conn_fd = net::accept_client(permute_listen_fd_);
        if (conn_fd < 0) {
            if (permute_share_stop_.load(std::memory_order_acquire)) {
                break;
            }
            int err = errno;
            std::cerr << "[WARN] accept() failed for permute-share service: "
                      << std::strerror(err) << std::endl;
            continue;
        }

        if (permute_share_stop_.load(std::memory_order_acquire)) {
            ::close(conn_fd);
            break;
        }

        try {
            handle_permute_share_connection(conn_fd);
        } catch (const std::exception& ex) {
            std::cerr << "[ERROR] permute-share handling error: " << ex.what() << std::endl;
        }
        ::close(conn_fd);
    }

    if (permute_listen_fd_ != -1) {
        ::close(permute_listen_fd_);
        permute_listen_fd_ = -1;
    }
}

void Client::handle_permute_share_connection(int conn_fd) {
    uint32_t header[2];
    if (!net::recv_all(conn_fd, header, sizeof(header))) {
        std::cerr << "[WARN] Failed to read permute-share request header" << std::endl;
        return;
    }

    uint32_t msg_type = ntohl(header[0]);
    if (msg_type != 1) {
        std::cerr << "[WARN] Unexpected permute-share message type " << msg_type << std::endl;
        return;
    }

    uint64_t count_be = 0;
    if (!net::recv_all(conn_fd, &count_be, sizeof(count_be))) {
        std::cerr << "[WARN] Failed to read permute-share payload length" << std::endl;
        return;
    }
    uint64_t count = be64toh(count_be);
    uint16_t osn_port = static_cast<uint16_t>(ntohl(header[1]));
    if (osn_port == 0) osn_port = permute_osn_port_;
    if (bcs_permutation_.size() != count) {
        uint32_t error_header[2] = {htonl(3), 0};
        net::send_all(conn_fd, error_header, sizeof(error_header));
        throw std::runtime_error("permute-share permutation length mismatch");
    }

    // The control connection carries only metadata. The server's random mask
    // is consumed by the receiver side of the OSN and is never sent in clear.
    uint32_t ready_header[2] = {htonl(2), 0};
    if (!net::send_all(conn_fd, ready_header, sizeof(ready_header))) {
        throw std::runtime_error("failed to acknowledge permute-share request");
    }

    uint64_t compute_us = 0;
    uint64_t osn_comm_bytes = 0;
    try {
        const std::string endpoint = "0.0.0.0:" + std::to_string(osn_port);
        const uint64_t plain_modulus = this->enc_params->plain_modulus().value();
        bcs::PartyShareOutput output = bcs::permute_share_sender_arithmetic(
            bcs_permutation_, endpoint, plain_modulus, 1);
        compute_us = output.compute_us;
        bcs_client_share_ = std::move(output.share);
        for (auto& share : bcs_client_share_) share %= plain_modulus;
        osn_comm_bytes = output.comm_bytes;
        if (this->metrics) {
            this->metrics->metrics_["time_permute_share_client_compute_us"] += compute_us;
        }
    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] permute-share sender failed: " << ex.what() << std::endl;
        uint32_t resp_header[2] = {htonl(3), 0};
        net::send_all(conn_fd, resp_header, sizeof(resp_header));
        return;
    }

    uint32_t resp_header[2] = {htonl(4), 0};
    if (!net::send_all(conn_fd, resp_header, sizeof(resp_header))) {
        std::cerr << "[WARN] Failed to send permute-share response header" << std::endl;
        return;
    }

    uint64_t compute_us_be = htobe64(compute_us);
    if (!net::send_all(conn_fd, &compute_us_be, sizeof(compute_us_be))) {
        std::cerr << "[WARN] Failed to send permute-share compute time" << std::endl;
        return;
    }

    uint64_t osn_comm_be = htobe64(osn_comm_bytes);
    if (!net::send_all(conn_fd, &osn_comm_be, sizeof(osn_comm_be))) {
        std::cerr << "[WARN] Failed to send permute-share communication count" << std::endl;
        return;
    }
}

void Client::setup_crypto(uint64_t log_poly_modulus_degree, vector<Modulus> coeff_bits, uint64_t prime_bitlength, bool _verbose)
{
    this->enc_params = new EncryptionParameters(scheme_type::bfv);
    this->enc_params->set_poly_modulus_degree(1 << log_poly_modulus_degree);
    this->enc_params->set_coeff_modulus(coeff_bits);
    // for (Modulus mod: this->enc_params->coeff_modulus()) {
    //     cout << mod.bit_count() << " ";
    // } cout << endl;

    this->enc_params->set_plain_modulus(PlainModulus::Batching(1 << log_poly_modulus_degree, prime_bitlength));

    this->context = new SEALContext(*(this->enc_params));
    if (!this->context->parameters_set()) {
        std::ostringstream err;
        err << "invalid encryption parameters: " << this->context->parameter_error_message();
        throw std::invalid_argument(err.str());
    }
    this->keygen = new KeyGenerator(*(this->context));
    this->secret_key = keygen->secret_key();
    this->encryptor = new Encryptor(*(this->context), secret_key);
    this->batch_encoder = new BatchEncoder(*(this->context));
    this->evaluator = new Evaluator(*(this->context));
    // if (_verbose) {
    //     uint64_t coeff_bitcount = 0;
    //     for (auto& prime : this->enc_params->coeff_modulus()) {
    //         coeff_bitcount += prime.bit_count();
    //     }
    //     cout << "-------------------------- Crypto Parameters "
    //             "--------------------------"
    //          << endl
    //          << "\tPoly Mod Degree: " << this->enc_params->poly_modulus_degree() << endl
    //          << "\tPlain Modulus: " << this->enc_params->plain_modulus().value() << " ("
    //          << this->enc_params->plain_modulus().bit_count() << " bits)" << endl
    //          << "\tCiphertext Modulus Bitcount: " << coeff_bitcount << endl;
    // }

}

void Client::send_parameters_and_keys(bool debug_mode)
{
    this->metrics->metrics_["comm_params"] = this->enc_params->save(this->params_stream);

    Serializable<RelinKeys> rlk_client = this->keygen->create_relin_keys();
    this->metrics->metrics_["comm_relin_keys"] = rlk_client.save(this->params_stream);

    // m_hat remains encrypted while applying the offline OSN permutation pi.
    // Retain a local copy for those rotations and send the setup object using
    // the same wire layout/accounting as FeUPSU.
    seal::GaloisKeys gal_keys_client;
    this->keygen->create_galois_keys(gal_keys_client);
    this->metrics->metrics_["comm_gal_keys"] = gal_keys_client.save(this->params_stream);
    this->gal_keys_local = std::make_unique<seal::GaloisKeys>(std::move(gal_keys_client));

    Serializable<PublicKey> public_key = this->keygen->create_public_key();
    this->metrics->metrics_["comm_pk"] = public_key.save(this->params_stream);

    if (debug_mode) this->secret_key.save(this->params_stream);
}

uint64_t Client::client_get(uint64_t gamma_prime, uint64_t bin_index, uint64_t effective_lambda){
    const uint64_t value = bin_index * (gamma_prime + 1ULL);
    return effective_lambda >= 64 ? value : value % (1ULL << effective_lambda);
}

void Client::send_setup_over_network(uint64_t& setup_round_ms,
                                     uint64_t& server_load_ms,
                                     uint64_t& server_keygen_ms) {
    if (!remote_server_) throw std::logic_error("remote setup requested in local mode");

    std::mt19937_64 session_rng(std::random_device{}());
    do {
        setup_session_id_ = session_rng();
    } while (setup_session_id_ == 0);

    std::string host = server_host_;
    uint16_t port = server_port_;
    if (const char* env_host = std::getenv("PSU_SERVER_HOST"); env_host && env_host[0]) {
        host = env_host;
    }
    if (const char* env_port = std::getenv("PSU_SERVER_PORT"); env_port && env_port[0]) {
        char* end_ptr = nullptr;
        const long value = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && value > 0 && value <= 65535) {
            port = static_cast<uint16_t>(value);
        }
    }

    std::ostringstream wire(std::ios::binary);
    auto put32 = [&](uint32_t value) {
        value = htonl(value);
        wire.write(reinterpret_cast<const char*>(&value), sizeof(value));
    };
    auto put64 = [&](uint64_t value) {
        value = htobe64(value);
        wire.write(reinterpret_cast<const char*>(&value), sizeof(value));
    };
    const std::string setup = params_stream.str();
    put32(kStandaloneMagic);
    put32(kStandaloneWireVersion);
    put32(kStandaloneSetupMessage);
    put64(setup_session_id_);
    put64(setup.size());
    wire.write(setup.data(), static_cast<std::streamsize>(setup.size()));
    const std::string request = wire.str();

    const auto start = std::chrono::steady_clock::now();
    const int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) throw std::runtime_error("failed to connect for standalone setup");
    const uint64_t request_len_be = htobe64(request.size());
    if (!net::send_all(sock_fd, &request_len_be, sizeof(request_len_be)) ||
        !net::send_all(sock_fd, request.data(), request.size())) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send standalone setup");
    }
    uint64_t response_len_be = 0;
    if (!net::recv_all(sock_fd, &response_len_be, sizeof(response_len_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive standalone setup response length");
    }
    const uint64_t response_len = be64toh(response_len_be);
    std::string response(response_len, '\0');
    if (response_len && !net::recv_all(sock_fd, response.data(), response.size())) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive standalone setup response");
    }
    ::close(sock_fd);
    const auto end = std::chrono::steady_clock::now();
    setup_round_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start).count());

    if (response.size() < sizeof(uint32_t)) {
        throw std::runtime_error("truncated standalone setup response");
    }
    uint32_t status_be = 0;
    std::memcpy(&status_be, response.data(), sizeof(status_be));
    if (ntohl(status_be) != 0) {
        throw std::runtime_error("server rejected standalone setup: " +
            response.substr(sizeof(status_be)));
    }
    if (response.size() != sizeof(uint32_t) + 2 * sizeof(uint64_t)) {
        throw std::runtime_error("invalid standalone setup response size");
    }
    uint64_t load_be = 0;
    uint64_t keygen_be = 0;
    std::memcpy(&load_be, response.data() + sizeof(uint32_t), sizeof(load_be));
    std::memcpy(&keygen_be, response.data() + sizeof(uint32_t) + sizeof(uint64_t),
                sizeof(keygen_be));
    server_load_ms = be64toh(load_be);
    server_keygen_ms = be64toh(keygen_be);
}

std::string Client::send_psu_request_over_network(const std::string& payload,
                                                  uint64_t& request_ms,
                                                  uint64_t& response_ms) {
    std::string host = server_host_;
    uint16_t port = server_port_;
    if (const char* env_host = std::getenv("PSU_SERVER_HOST"); env_host && env_host[0] != '\0') {
        host = std::string(env_host);
    }
    if (const char* env_port = std::getenv("PSU_SERVER_PORT"); env_port && env_port[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            port = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_SERVER_PORT='" << env_port
                      << "', fallback to " << port << std::endl;
        }
    }

    int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) {
        throw std::runtime_error("failed to connect to PSU server at " + host + ":" + std::to_string(port));
    }

    std::string wire_payload = payload;
    if (remote_server_) {
        if (setup_session_id_ == 0) {
            ::close(sock_fd);
            throw std::runtime_error("standalone batch requested before setup");
        }
        std::ostringstream wire(std::ios::binary);
        auto put32 = [&](uint32_t v) { v = htonl(v); wire.write(reinterpret_cast<char*>(&v), sizeof(v)); };
        auto put64 = [&](uint64_t v) { v = htobe64(v); wire.write(reinterpret_cast<char*>(&v), sizeof(v)); };
        put32(kStandaloneMagic);
        put32(kStandaloneWireVersion);
        put32(kStandaloneBatchMessage);
        put64(setup_session_id_);
        put32(static_cast<uint32_t>(current_request_params_.task));
        put32(static_cast<uint32_t>(current_request_params_.ell));
        put64(current_request_params_.server_set);
        put64(current_request_params_.effective_lambda);
        put64(current_request_params_.hw);
        put64(current_request_params_.client_set);
        put64(current_request_params_.client_bin_offset);
        wire.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        wire_payload = wire.str();
    }

    auto request_start = std::chrono::steady_clock::now();
    uint64_t len_be = htobe64(wire_payload.size());
    if (!net::send_all(sock_fd, &len_be, sizeof(len_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send PSU request length");
    }
    if (!wire_payload.empty() && !net::send_all(sock_fd, wire_payload.data(), wire_payload.size())) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send PSU request payload");
    }
    auto request_end = std::chrono::steady_clock::now();
    request_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(request_end - request_start).count());

    auto response_start = std::chrono::steady_clock::now();
    uint64_t resp_len_be = 0;
    if (!net::recv_all(sock_fd, &resp_len_be, sizeof(resp_len_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive PSU response length");
    }
    uint64_t resp_len = be64toh(resp_len_be);
    std::string response(resp_len, '\0');
    if (resp_len > 0 && !net::recv_all(sock_fd, response.data(), response.size())) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive PSU response payload");
    }
    auto response_end = std::chrono::steady_clock::now();
    response_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(response_end - response_start).count());

    ::close(sock_fd);
    if (response.size() < sizeof(uint32_t)) throw std::runtime_error("truncated PSU response");
    uint32_t status_be = 0;
    std::memcpy(&status_be, response.data(), sizeof(status_be));
    uint32_t status = ntohl(status_be);
    response.erase(0, sizeof(status_be));
    if (status != 0) throw std::runtime_error("server rejected request: " + response);
    constexpr std::size_t kServerMetricCount = 11;
    if (response.size() < kServerMetricCount * sizeof(uint64_t)) {
        throw std::runtime_error("truncated PSU response metrics");
    }
    uint64_t server_time_be = 0;
    std::memcpy(&server_time_be, response.data(), sizeof(server_time_be));
    if (remote_server_ && metrics) metrics->metrics_["time_server"] += be64toh(server_time_be);
    response.erase(0, sizeof(server_time_be));
    const char* response_metric_names[] = {
        "comm_permuteshare",
        "comm_permute_share_request_bytes",
        "comm_permute_share_response_bytes",
        "time_permute_share_server_compute_ms",
        "time_permute_share_batch_encrypt_ms",
        "time_permute_share_network_ms",
        "time_setup_server_keygen_ms",
        "time_setup_server_load_ms",
        "time_offline_server_encode_ms",
        "time_online_server_comp_ms"
    };
    for (const char* name : response_metric_names) {
        uint64_t value_be = 0;
        std::memcpy(&value_be, response.data(), sizeof(value_be));
        if (remote_server_ && metrics) metrics->metrics_[name] += be64toh(value_be);
        response.erase(0, sizeof(value_be));
    }
    return response;
}

void Client::send_masked_payload_over_network(const std::string& payload, uint64_t& send_ms) {
    std::string host = server_host_;
    uint16_t port = 39003;
    if (const char* env_host = std::getenv("PSU_SERVER_HOST"); env_host && env_host[0] != '\0') {
        host = std::string(env_host);
    }
    if (const char* env_port = std::getenv("PSU_MASKED_PORT"); env_port && env_port[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            port = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_MASKED_PORT='" << env_port
                      << "', fallback to " << port << std::endl;
        }
    }

    int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) {
        throw std::runtime_error("failed to connect to masked server at " + host + ":" + std::to_string(port));
    }

    auto send_start = std::chrono::steady_clock::now();
    uint64_t len_be = htobe64(payload.size());
    if (!net::send_all(sock_fd, &len_be, sizeof(len_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send masked payload length");
    }
    if (!payload.empty() && !net::send_all(sock_fd, payload.data(), payload.size())) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send masked payload");
    }
    uint64_t resp_len_be = 0;
    if (!net::recv_all(sock_fd, &resp_len_be, sizeof(resp_len_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive masked ack length");
    }
    uint64_t resp_len = be64toh(resp_len_be);
    if (resp_len > 0) {
        std::string response(resp_len, '\0');
        if (!net::recv_all(sock_fd, response.data(), response.size())) {
            ::close(sock_fd);
            throw std::runtime_error("failed to receive masked ack payload");
        }
        if (resp_len == sizeof(uint64_t)) {
            uint64_t extract_be = 0;
            std::memcpy(&extract_be, response.data(), sizeof(extract_be));
            if (remote_server_ && metrics) {
                metrics->metrics_["time_server_extract"] += be64toh(extract_be);
            }
        }
    }

    const auto round_end = std::chrono::steady_clock::now();
    send_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(round_end - send_start).count());

    ::close(sock_fd);
}

void Client::encrypt_and_send(vector<Plaintext>& plaintexts, bool _verbose) {
    data_stream.str("");
    std::vector<Plaintext> result;
    this->metrics->metrics_["comm_request"] = 0;
    for (int i = 0; i < plaintexts.size(); i++) {
        this->metrics->metrics_["comm_request"] += this->encryptor->encrypt_symmetric(plaintexts[i]).save(data_stream);
    }
}

vector<Plaintext> Client::load_and_decrypt(int num_cts, Params params, bool _verbose) {
    (void)num_cts;
    std::vector<Plaintext> result;

    this->metrics->metrics_["comm_response"] = 0;

    this->metrics->metrics_["comm_response"] +=
        this->server_public_key.load(*(this->context), data_stream);

    uint64_t ind_cipher_count = 0;
    data_stream.read(reinterpret_cast<char*>(&ind_cipher_count), sizeof(ind_cipher_count));
    this->metrics->metrics_["comm_response"] += sizeof(ind_cipher_count);

    std::vector<Ciphertext> ind_hat_cts(ind_cipher_count);
    for (uint64_t i = 0; i < ind_cipher_count; ++i) {
        try {
            this->metrics->metrics_["comm_response"] += ind_hat_cts[i].load(*(this->context), data_stream);
        } catch (const std::exception &ex) {
            std::cerr << "[DEBUG] ind_hat_ct load failed at i=" << i << ": " << ex.what() << std::endl;
            throw;
        }
    }
    // cout << "[TRACE][client] loaded " << ind_cipher_count << " indicator ciphertexts" << endl;

    uint64_t share_cipher_count = 0;
    data_stream.read(reinterpret_cast<char*>(&share_cipher_count), sizeof(share_cipher_count));
    this->metrics->metrics_["comm_response"] += sizeof(share_cipher_count);

    std::vector<Ciphertext> server_share_cts(share_cipher_count);
    for (uint64_t i = 0; i < share_cipher_count; ++i) {
        try {
            this->metrics->metrics_["comm_response"] += server_share_cts[i].load(*(this->context), data_stream);
        } catch (const std::exception &ex) {
            std::cerr << "[DEBUG] server_share_ct load failed at i=" << i << ": " << ex.what() << std::endl;
            throw;
        }
    }
    // cout << "[TRACE][client] loaded " << share_cipher_count << " permute-share ciphertexts" << endl;

    if (ind_hat_cts.empty()) {
        throw std::runtime_error("server response missing ind_hat ciphertext");
    }
    if (server_share_cts.empty()) {
        throw std::runtime_error("server response missing permute-share ciphertext");
    }
    uint64_t slot_count = this->batch_encoder->slot_count();
    uint64_t num_bins = 1ULL << params.log_poly_modulus_degree;
    if (num_bins > slot_count) {
        num_bins = slot_count;
    }

    if (bcs_permutation_.size() != num_bins) {
        throw std::runtime_error("client permutation size mismatch when applying permuted indicators");
    }
    if (bcs_client_share_.size() < num_bins) {
        throw std::runtime_error("client permute-share share missing or truncated");
    }

    // Keep m_hat encrypted while applying the exact permutation pi used by the
    // offline permute+share.  It is safe to decrypt only afterwards: its slots
    // still contain pi(indicator)+pi(r), while the client owns only one additive
    // share of pi(r).  The masked plaintext is then used as the bridge to pk_S;
    // ciphertexts encrypted under the client and server keys are never mixed.
    auto perm_loop_start = std::chrono::steady_clock::now();
    if (!this->gal_keys_local) {
        throw std::runtime_error("ciphertext permutation requires local Galois keys");
    }

    // EEQ leaves too little noise budget for an arbitrary slot permutation.
    // Refresh the still-one-time-padded value locally before rotating it.  The
    // decrypted value is information-theoretically masked by r and therefore
    // does not reveal the indicator.
    Decryptor client_decryptor(*this->context, this->secret_key);
    Plaintext incoming_masked_plain;
    client_decryptor.decrypt(ind_hat_cts.front(), incoming_masked_plain);
    Ciphertext refreshed_masked_cipher;
    this->encryptor->encrypt_symmetric(incoming_masked_plain, refreshed_masked_cipher);

    const uint64_t row_size = slot_count / 2;
    std::vector<uint64_t> mask_slots(slot_count, 0ULL);
    Plaintext mask_plain;
    Ciphertext masked_pi_cipher;
    bool permutation_initialized = false;
    for (uint64_t dest = 0; dest < num_bins; ++dest) {
        const uint32_t src = bcs_permutation_[dest];
        if (src >= num_bins) {
            throw std::runtime_error("client permutation contains an out-of-range source slot");
        }

        std::fill(mask_slots.begin(), mask_slots.end(), 0ULL);
        mask_slots[src] = 1ULL;
        this->batch_encoder->encode(mask_slots, mask_plain);

        Ciphertext isolated;
        this->evaluator->multiply_plain(refreshed_masked_cipher, mask_plain, isolated);

        uint64_t src_index = src;
        uint64_t dest_index = dest;
        const bool src_second_row = src_index >= row_size;
        const bool dest_second_row = dest_index >= row_size;
        if (src_second_row) {
            this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_local);
            src_index -= row_size;
        }
        if (dest_second_row) dest_index -= row_size;

        const int modulus = static_cast<int>(std::max<uint64_t>(row_size, 1ULL));
        // SEAL's positive row rotation moves a value towards the lower slot
        // index.  With pi[dest] = src, moving src to dest therefore requires
        // src-dest (not dest-src).
        int rotation = static_cast<int>(src_index) - static_cast<int>(dest_index);
        rotation %= modulus;
        if (rotation > modulus / 2) rotation -= modulus;
        if (rotation < -modulus / 2) rotation += modulus;
        if (rotation != 0) {
            this->evaluator->rotate_rows_inplace(isolated, rotation, *this->gal_keys_local);
        }
        if (dest_second_row) {
            this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_local);
        }

        if (!permutation_initialized) {
            masked_pi_cipher = std::move(isolated);
            permutation_initialized = true;
        } else {
            this->evaluator->add_inplace(masked_pi_cipher, isolated);
        }
    }
    if (!permutation_initialized) {
        throw std::runtime_error("failed to construct permuted m_hat ciphertext");
    }

    Plaintext masked_plain;
    std::vector<uint64_t> masked_slots;
    client_decryptor.decrypt(masked_pi_cipher, masked_plain);
    this->batch_encoder->decode(masked_plain, masked_slots);
    if (masked_slots.size() < num_bins) {
        throw std::runtime_error("decrypted masked indicator is truncated");
    }

    const uint64_t plain_mod = this->enc_params->plain_modulus().value();
    std::vector<uint64_t> client_unmasked_slots(slot_count, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        const uint64_t share = bcs_client_share_[i] % plain_mod;
        const uint64_t masked = masked_slots[i] % plain_mod;
        client_unmasked_slots[i] = masked >= share
            ? masked - share
            : plain_mod - (share - masked);
    }

    Plaintext client_unmasked_plain;
    this->batch_encoder->encode(client_unmasked_slots, client_unmasked_plain);

    Ciphertext server_share_cipher = server_share_cts.front();
    Ciphertext ind_cipher(server_share_cipher);
    this->evaluator->negate_inplace(ind_cipher);
    this->evaluator->add_plain_inplace(ind_cipher, client_unmasked_plain);
    const EEQParams eeq_params = build_eeq_params(params.hw, plain_mod);
    std::vector<uint64_t> inv_factorial_slots(slot_count, eeq_params.coefficients.back());
    Plaintext inv_factorial_plain;
    this->batch_encoder->encode(inv_factorial_slots, inv_factorial_plain);
    this->evaluator->multiply_plain_inplace(ind_cipher, inv_factorial_plain);
    if (std::getenv("CWPSU_VERIFY_OUTPUT") && this->server) {
        Decryptor server_decryptor(*this->context, this->server->server_secret_key);
        Plaintext verify_plain;
        std::vector<uint64_t> verify_slots;
        server_decryptor.decrypt(ind_cipher, verify_plain);
        this->batch_encoder->decode(verify_plain, verify_slots);
        for (uint64_t i = 0; i < num_bins; ++i) {
            const uint64_t expected = 0;
            if (verify_slots[i] != expected) {
                throw std::runtime_error("re-encrypted indicator verification failed at slot "
                    + std::to_string(i) + ", expected " + std::to_string(expected)
                    + ", got " + std::to_string(verify_slots[i]));
            }
        }
        std::cout << "[VERIFY] additive key transfer passed" << std::endl;
    }

    auto perm_loop_end = std::chrono::steady_clock::now();
    auto perm_total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(perm_loop_end - perm_loop_start).count();
    if (this->metrics) {
        this->metrics->metrics_["time_client_permute_reencrypt_ms"] += perm_total_ms;
        this->metrics->metrics_["time_extract_permute_mask"] += perm_total_ms;
    }

    vector<Ciphertext> ind_cts;
    ind_cts.push_back(ind_cipher);

    /*
     */

    // K = final_cts.size(); num_bins = number of bins = 1 << log_poly_modulus_degree
    uint64_t K = ind_cts.size();
    if (num_bins > slot_count) num_bins = slot_count; // safety

    uint64_t p = this->enc_params->plain_modulus().value();
    vector<vector<uint64_t>> all_elements_per_group(K, vector<uint64_t>(num_bins));
    uint64_t global_max = 0;
    for (uint64_t k = 0; k < K; ++k) {
        uint64_t gamma_prime = k;
        for (uint64_t i = 0; i < num_bins; ++i) {
            uint64_t global_bin = params.client_bin_offset + i;
            all_elements_per_group[k][i] = global_bin;
            if (all_elements_per_group[k][i] > global_max) global_max = all_elements_per_group[k][i];
        }
    }

    uint64_t D = 1;
    uint64_t tmp_max = global_max;
    while (tmp_max >= p) { tmp_max = tmp_max / p; D++; }

    this->data_stream.str("");
    this->data_stream.clear();
    uint64_t comm_final_response = 0;
    this->data_stream.write(reinterpret_cast<const char*>(&K), sizeof(K));
    this->data_stream.write(reinterpret_cast<const char*>(&D), sizeof(D));
    this->data_stream.write(reinterpret_cast<const char*>(&num_bins), sizeof(num_bins));
    comm_final_response += sizeof(K) + sizeof(D) + sizeof(num_bins);

    // cout << "[TRACE][client] starting digit masking with K=" << K << ", D=" << D << endl;
    for (uint64_t k = 0; k < K; ++k) {
        // if (k % 16 == 0) {
        //     cout << "[TRACE][client] masking group " << k << "/" << K << endl;
        // }
        vector<uint64_t> permuted_elements = bcs::apply_permutation(all_elements_per_group[k], bcs_permutation_);

        for (uint64_t d = 0; d < D; ++d) {
            // if (d % 8 == 0) {
            //     cout << "[TRACE][client]   digit " << d << "/" << D << " for group " << k << endl;
            // }
            vector<uint64_t> digit_slots(slot_count, 0);
            uint64_t base = 1;
            for (uint64_t dd = 0; dd < d; ++dd) base *= p;
            for (uint64_t i = 0; i < num_bins; ++i) {
                uint64_t val = permuted_elements[i];
                uint64_t digit = (val / base) % p;
                digit_slots[i] = digit;
            }

            Ciphertext masked_ct;
            try {
                const bool all_zero = std::all_of(digit_slots.begin(), digit_slots.end(),
                                                  [](uint64_t value) { return value == 0; });
                if (all_zero) {
                    // SEAL intentionally rejects transparent ciphertexts. Encrypt a
                    // semantic zero under the server key instead of multiplying by 0.
                    Encryptor server_zero_encryptor(*context, server_public_key);
                    server_zero_encryptor.encrypt_zero(masked_ct);
                } else {
                    Plaintext digit_pt;
                    batch_encoder->encode(digit_slots, digit_pt);
                    evaluator->multiply_plain(ind_cts[k], digit_pt, masked_ct);
                }
                uint64_t bytes = masked_ct.save(this->data_stream);
                comm_final_response += bytes;
            } catch (const exception &e) {
                throw std::runtime_error("masked ciphertext construction failed for group "
                    + std::to_string(k) + " digit " + std::to_string(d) + ": " + e.what());
            }
        }
    }

    this->data_stream.clear();
    this->data_stream.seekg(0, std::ios::beg);
    this->metrics->metrics_["comm_final_response"] = comm_final_response;
    uint64_t send_ms = 0;
    send_masked_payload_over_network(this->data_stream.str(), send_ms);
    this->metrics->metrics_["time_masked_send_ms"] = send_ms;
    auto it_online = this->metrics->metrics_.find("time_online_comm");
    if (it_online != this->metrics->metrics_.end()) {
        it_online->second += send_ms;
    } else {
        this->metrics->metrics_["time_online_comm"] = send_ms;
    }
    // cout << "[INFO] Sent masked digits to server and received reconstructed elements (groups="<<reconstructed.size()<<")."<<endl;

    // return result;


    // Ciphertext __temp_ct;
    // Plaintext __temp_pt;
    // this->metrics->metrics_["comm_response"] = 0;
    // for (int i = 0; i < num_cts; i++) {
    //     this->metrics->metrics_["comm_response"] += __temp_ct.load(*(this->context), data_stream);
    //     decryptor.decrypt(__temp_ct, __temp_pt);
    //     if (i==0){
    //         cout << "Final Noise: " << decryptor.invariant_noise_budget(__temp_ct) << endl;
    //     }
    //     result.push_back(__temp_pt);
    // }


    return result;
}

void Client::params_to_metrics(Params params) {
    // this->metrics->metrics_["gamma"] = params.gamma;
    this->metrics->metrics_["ell"] = params.ell;
    this->metrics->metrics_["hw"] = params.hw;
    this->metrics->metrics_["log_poly_modulus_degree"] = params.log_poly_modulus_degree;
    this->metrics->metrics_["effective_lambda"] = params.effective_lambda;
    this->metrics->metrics_["mu"] = params.mu;
    this->metrics->metrics_["task"] = params.task;
    this->metrics->metrics_["server_set"] = params.server_set;
    this->metrics->metrics_["client_set"] = params.client_set;
}

bool Client::run_protocol(Params params, bool verbose)
{
    Timer timer;
    metrics = new Metrics();
    params_to_metrics(params);

    const uint64_t bin_count = 1ULL << params.log_poly_modulus_degree;
    const uint64_t client_set = params.client_set == 0 ? bin_count : params.client_set;
    if (client_set != bin_count && client_set != 2 * bin_count) {
        throw std::invalid_argument("client_set must equal 1x or 2x poly_modulus_degree");
    }
    const uint64_t batches = client_set / bin_count;
    metrics->metrics_["client_set"] = client_set;
    metrics->metrics_["client_batches"] = batches;
    metrics->metrics_["psu_batches"] = batches;
    metrics->metrics_["client_total_elements"] = client_set;

    const auto setup_client_start = std::chrono::steady_clock::now();
    timer.start();
    setup_crypto(params.log_poly_modulus_degree, params.coeff_bits,
                 params.prime_bitlength, verbose);
    metrics->metrics_["time_setup_crypto"] = timer.end_and_get();
    send_parameters_and_keys(false);
    const auto setup_client_end = std::chrono::steady_clock::now();
    metrics->metrics_["time_setup_client_ms"] = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            setup_client_end - setup_client_start).count());
    uint64_t setup_interaction_ms = 0;
    uint64_t setup_server_load_ms = 0;
    uint64_t setup_server_keygen_ms = 0;
    if (!remote_server_) {
        if (!server) throw std::runtime_error("local mode requires a Server instance");
        const auto setup_server_start = std::chrono::steady_clock::now();
        setup_server_keygen_ms = server->load_parameters_and_keys(params_stream, false, verbose);
        const auto setup_server_end = std::chrono::steady_clock::now();
        const uint64_t setup_server_total_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                setup_server_end - setup_server_start).count());
        setup_server_load_ms = setup_server_total_ms > setup_server_keygen_ms
            ? setup_server_total_ms - setup_server_keygen_ms : 0ULL;
    } else {
        send_setup_over_network(setup_interaction_ms,
                                setup_server_load_ms,
                                setup_server_keygen_ms);
    }
    metrics->metrics_["time_setup_interaction"] = setup_interaction_ms;
    metrics->metrics_["time_setup_server_load_ms"] = setup_server_load_ms;
    metrics->metrics_["time_setup_server_keygen_ms"] = setup_server_keygen_ms;
    metrics->metrics_["time_server_keygen_ms"] = setup_server_keygen_ms;
    metrics->metrics_["setup_requests"] = 1;

    uint64_t total_build = 0, total_request = 0, total_wait = 0;
    uint64_t total_extract = 0, total_masked = 0;
    uint64_t total_comm_request = 0, total_comm_response = 0, total_comm_final = 0;
    const auto overall_start = std::chrono::steady_clock::now();

    for (uint64_t batch_id = 0; batch_id < batches; ++batch_id) {
        Params batch_params = params;
        batch_params.client_set = client_set;
        batch_params.client_bin_offset = batch_id * bin_count;
        current_request_params_ = batch_params;

        timer.start();
        std::vector<std::vector<uint64_t>> operands(
            params.ell, std::vector<uint64_t>(bin_count));
        std::mt19937_64 perm_rng(std::random_device{}());
        bcs_permutation_ = bcs::generate_permutation(bin_count, perm_rng);
        for (uint64_t bin = 0; bin < bin_count; ++bin) {
            const auto code = get_cw(batch_params.client_bin_offset + bin,
                                     params.ell, params.hw, false);
            for (uint64_t l = 0; l < params.ell; ++l) operands[l][bin] = code[l];
        }
        std::vector<Plaintext> input;
        input.reserve(params.ell);
        for (uint64_t l = 0; l < params.ell; ++l) {
            Plaintext pt;
            batch_encoder->encode(operands[l], pt);
            input.push_back(std::move(pt));
        }
        encrypt_and_send(input, verbose);
        total_build += static_cast<uint64_t>(timer.end_and_get());
        total_comm_request += metrics->metrics_["comm_request"];

        start_permute_share_service();
        if (!remote_server_) {
            server->start_masked_service();
            server->start_psu_service(batch_params, static_cast<int>(input.size()), metrics, verbose);
        }
        try {
            uint64_t request_ms = 0, response_ms = 0;
            std::string response = send_psu_request_over_network(
                data_stream.str(), request_ms, response_ms);
            total_request += request_ms;
            total_wait += response_ms;
            data_stream.str("");
            data_stream.clear();
            data_stream.write(response.data(), static_cast<std::streamsize>(response.size()));
            data_stream.seekg(0, std::ios::beg);
            if (!remote_server_) server->stop_psu_service();
            stop_permute_share_service();

            timer.start();
            load_and_decrypt(2, batch_params, verbose);
            const uint64_t extraction_with_send = static_cast<uint64_t>(timer.end_and_get());
            const uint64_t masked_ms = metrics->metrics_["time_masked_send_ms"];
            total_masked += masked_ms;
            total_extract += extraction_with_send > masked_ms
                ? extraction_with_send - masked_ms : 0;
            total_comm_response += metrics->metrics_["comm_response"];
            total_comm_final += metrics->metrics_["comm_final_response"];
            if (!remote_server_) server->stop_masked_service();
        } catch (...) {
            if (!remote_server_ && server) {
                server->stop_psu_service();
                server->stop_masked_service();
            }
            stop_permute_share_service();
            throw;
        }
    }

    metrics->metrics_["time_build_request"] = total_build;
    metrics->metrics_["time_request_send_ms"] = total_request;
    metrics->metrics_["time_server_response_wait_ms"] = total_wait;
    metrics->metrics_["time_extract_response"] = total_extract;
    metrics->metrics_["time_masked_send_ms"] = total_masked;
    const uint64_t ps_client_ms =
        (metrics->metrics_["time_permute_share_client_compute_us"] + 999ULL) / 1000ULL;
    const uint64_t ps_critical_compute_ms = std::max(
        ps_client_ms, metrics->metrics_["time_permute_share_server_compute_ms"]);
    metrics->metrics_["time_permute_share_comm_ms"] =
        metrics->metrics_["time_permute_share_network_ms"] > ps_critical_compute_ms
            ? metrics->metrics_["time_permute_share_network_ms"] - ps_critical_compute_ms
            : 0ULL;
    metrics->metrics_["time_setup"] = metrics->metrics_["time_setup_client_ms"]
        + (remote_server_ ? metrics->metrics_["time_setup_interaction"]
                          : metrics->metrics_["time_setup_server_load_ms"]
                            + metrics->metrics_["time_setup_server_keygen_ms"]);
    metrics->metrics_["time_offline_comp"] = total_build
        + metrics->metrics_["time_offline_server_encode_ms"]
        + ps_client_ms
        + metrics->metrics_["time_permute_share_server_compute_ms"];
    metrics->metrics_["time_offline"] = metrics->metrics_["time_offline_comp"];
    metrics->metrics_["time_offline_comm"] = total_request
        + metrics->metrics_["time_permute_share_comm_ms"];

    const uint64_t initial_server_ms = metrics->metrics_["time_server"];
    const uint64_t initial_online_comm_ms = total_wait > initial_server_ms
        ? total_wait - initial_server_ms : 0ULL;
    const uint64_t final_online_comm_ms = total_masked > metrics->metrics_["time_server_extract"]
        ? total_masked - metrics->metrics_["time_server_extract"] : 0ULL;
    metrics->metrics_["time_online_comp"] = metrics->metrics_["time_online_server_comp_ms"]
        + total_extract + metrics->metrics_["time_server_extract"];
    metrics->metrics_["time_online_comm"] = initial_online_comm_ms + final_online_comm_ms;
    metrics->metrics_["time_end_to_end"] = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - overall_start).count());
    metrics->metrics_["comm_request"] = total_comm_request;
    metrics->metrics_["comm_response"] = total_comm_response;
    metrics->metrics_["comm_final_response"] = total_comm_final;
    metrics->metrics_["comm_setup"] = metrics->metrics_["comm_params"]
        + metrics->metrics_["comm_relin_keys"]
        + metrics->metrics_["comm_gal_keys"]
        + metrics->metrics_["comm_pk"];
    metrics->metrics_["comm_offline"] = metrics->metrics_["comm_request"]
        + metrics->metrics_["comm_permuteshare"]
        + metrics->metrics_["comm_permute_share_request_bytes"]
        + metrics->metrics_["comm_permute_share_response_bytes"];
    metrics->metrics_["comm_online"] = metrics->metrics_["comm_response"]
        + metrics->metrics_["comm_final_response"];
    metrics->metrics_["metrics_schema_version"] = 2;
    metrics->metrics_["comm_total"] = metrics->metrics_["comm_params"]
        + metrics->metrics_["comm_relin_keys"]
        + metrics->metrics_["comm_pk"]
        + metrics->metrics_["comm_request"]
        + metrics->metrics_["comm_response"]
        + metrics->metrics_["comm_final_response"]
        + metrics->metrics_["comm_permuteshare"]
        + metrics->metrics_["comm_permute_share_request_bytes"]
        + metrics->metrics_["comm_permute_share_response_bytes"];

    namespace fs = std::filesystem;
    const char *requested_file = std::getenv("PSU_RESULTS_FILE");
    std::string filename;
    if (requested_file && requested_file[0] != '\0') {
        filename = requested_file;
        fs::path path(filename);
        if (path.has_parent_path()) fs::create_directories(path.parent_path());
    } else {
        fs::create_directories("results");
        const char *profile_env = std::getenv("NETEM_PROFILE");
        const std::string profile = profile_env && profile_env[0] ? profile_env : "native";
        filename = "results/effective_" + std::to_string(params.effective_lambda)
                 + "_hw_" + std::to_string(params.hw) + "__" + profile + ".csv";
    }
    std::ofstream output(filename);
    if (!output) throw std::runtime_error("cannot open results file: " + filename);
    for (const auto &metric : metrics->metrics_) {
        output << metric.first << ',' << metric.second << '\n';
    }
    std::cout << "Writing to file " << filename << std::endl;
    return true;
}
