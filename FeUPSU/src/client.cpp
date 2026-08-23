//
// Created by Administrator on 2025/9/23.
//

#include "client.h"
#include "server.h"
#include "bcs.h"
#include "bcs_osn.h"
#include "circuit_ot.h"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <endian.h>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <limits>

using namespace std;
using namespace seal;

namespace {
constexpr uint64_t kSharePadBits = 10;
constexpr uint32_t kStandaloneMagic = 0x46505531U; // "FPU1"
constexpr uint32_t kStandaloneWireVersion = 2;
constexpr uint32_t kStandaloneSetupMessage = 1;
constexpr uint32_t kStandaloneBatchMessage = 2;
constexpr uint64_t kPsucaRefreshMagic = 0x5053554341524546ULL; // "PSUCAREF"

inline uint64_t append_zeros(uint64_t value, uint64_t bits) {
    if (bits >= 64) {
        return 0ULL;
    }
    return value << bits;
}

std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
make_secret_shares(const std::vector<uint64_t>& values, uint64_t pad_bits) {
    std::vector<uint64_t> share(values.size(), 0ULL);
    std::vector<uint64_t> share_prime(values.size(), 0ULL);
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist(0ULL, std::numeric_limits<uint64_t>::max());
    for (size_t i = 0; i < values.size(); ++i) {
        uint64_t shifted = append_zeros(values[i], pad_bits);
        uint64_t rnd = dist(rng);
        share[i] = rnd;
        share_prime[i] = shifted ^ rnd;
    }
    return {share, share_prime};
}

}

Client::Client() {
    // The default constructor is used by the standalone client process.
    server = nullptr;
    remote_server_ = true;
    gal_keys_local = nullptr;
    metrics = nullptr;
    record_otsss_time_ = false;
    pending_masked_response_ = false;
    pending_otsss_timing_ = false;
    permute_share_time_us_.store(0, std::memory_order_relaxed);
    permute_share_invocations_.store(0, std::memory_order_relaxed);
}

Client::Client(Server* _server) {
    server = _server;
    if (server) {
        server->set_client(this);
    }
    gal_keys_local = nullptr;
    metrics = nullptr;
    record_otsss_time_ = false;
    pending_masked_response_ = false;
    pending_otsss_timing_ = false;
    permute_share_time_us_.store(0, std::memory_order_relaxed);
    permute_share_invocations_.store(0, std::memory_order_relaxed);
}

void save_circuit_share_if_requested(const char* env_name,
                                     const std::vector<uint64_t>& share) {
    const char* path = std::getenv(env_name);
    if (!path || !*path) return;
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error(std::string("cannot open circuit share file: ") + path);
    const uint64_t count = share.size();
    output.write(reinterpret_cast<const char*>(&count), sizeof(count));
    output.write(reinterpret_cast<const char*>(share.data()),
                 static_cast<std::streamsize>(share.size() * sizeof(uint64_t)));
    if (!output) throw std::runtime_error(std::string("cannot write circuit share file: ") + path);
}

void Client::set_server_endpoint(const std::string& host, uint16_t psu_port) {
    if (host.empty()) {
        throw std::invalid_argument("server host must not be empty");
    }
    net_cfg_.server_ip = host;
    net_cfg_.host = host;
    net_cfg_.psu_server_port = psu_port;
    net_cfg_.psu_port = psu_port;
    remote_server_ = true;
}

Client::~Client() {
    stop_permute_share_service();
}

void Client::finalize_masked_response() {
    if (!pending_masked_response_) {
        return;
    }
    this->data_stream.clear();
    this->data_stream.seekg(0, std::ios::beg);
    uint64_t send_ms = 0;
    send_masked_payload_over_network(this->data_stream.str(), send_ms);
    auto it_online = this->metrics->metrics_.find("time_online_comm");
    if (it_online != this->metrics->metrics_.end()) {
        it_online->second += send_ms;
    } else {
        this->metrics->metrics_["time_online_comm"] = send_ms;
    }
    if (pending_otsss_timing_) {
        auto otsss_end = std::chrono::steady_clock::now();
        uint64_t otsss_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(otsss_end - otsss_start_).count());
        this->metrics->metrics_["time_OTSSS_ms"] = otsss_ms;
        pending_otsss_timing_ = false;
    }
    pending_masked_response_ = false;
}

std::vector<uint64_t> Client::execute_permute_share(const std::vector<uint64_t>& rnd_bits) {
    if (bcs_permutation_.empty() || bcs_permutation_.size() != rnd_bits.size()) {
        throw std::runtime_error("permute-share requires a client-defined permutation of matching size");
    }
    bcs::PermuteShareOutput output = bcs::permute_share_bits(rnd_bits, bcs_permutation_, 1);
    bcs_client_share_ = std::move(output.client_share);
    return std::move(output.server_share);
}

void Client::start_permute_share_service() {
    permute_server_ = std::make_unique<psu::network::SocketServer>(
        net_cfg_.permute_share_port,
        [this](int conn_fd) {
            this->handle_permute_share_connection(conn_fd);
        }
    );
    permute_server_->start();
}

void Client::stop_permute_share_service() {
    if (permute_server_) {
        permute_server_->stop();
        permute_server_.reset();
    }
}

void Client::serve_permute_share_requests() {
    permute_listen_fd_ = net::create_listen_socket(net_cfg_.permute_share_port);
    if (permute_listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to open permute-share listen socket on port "
                  << net_cfg_.permute_share_port << std::endl;
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
    std::vector<uint64_t> rnd_bits(count);
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t word_be = 0;
        if (!net::recv_all(conn_fd, &word_be, sizeof(word_be))) {
            std::cerr << "[WARN] Failed to read permute-share payload body" << std::endl;
            return;
        }
        rnd_bits[i] = be64toh(word_be);
    }

    std::vector<uint64_t> server_share;
    uint64_t compute_us = 0;
    try {
        auto start = std::chrono::steady_clock::now();
        server_share = execute_permute_share(rnd_bits);
        auto end = std::chrono::steady_clock::now();
        compute_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
        if (record_otsss_time_) {
            permute_share_time_us_.fetch_add(compute_us, std::memory_order_relaxed);
            permute_share_invocations_.fetch_add(1, std::memory_order_relaxed);
        }
    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] execute_permute_share failed: " << ex.what() << std::endl;
        uint32_t resp_header[2] = {htonl(3), 0};
        net::send_all(conn_fd, resp_header, sizeof(resp_header));
        uint64_t zero = 0;
        net::send_all(conn_fd, &zero, sizeof(zero));
        net::send_all(conn_fd, &zero, sizeof(zero));
        return;
    }

    uint32_t resp_header[2] = {htonl(2), 0};
    if (!net::send_all(conn_fd, resp_header, sizeof(resp_header))) {
        std::cerr << "[WARN] Failed to send permute-share response header" << std::endl;
        return;
    }

    uint64_t compute_us_be = htobe64(compute_us);
    if (!net::send_all(conn_fd, &compute_us_be, sizeof(compute_us_be))) {
        std::cerr << "[WARN] Failed to send permute-share compute time" << std::endl;
        return;
    }

    uint64_t share_count = server_share.size();
    uint64_t share_count_be = htobe64(share_count);
    if (!net::send_all(conn_fd, &share_count_be, sizeof(share_count_be))) {
        std::cerr << "[WARN] Failed to send permute-share count" << std::endl;
        return;
    }

    std::vector<uint64_t> payload(share_count);
    for (uint64_t i = 0; i < share_count; ++i) {
        payload[i] = htobe64(server_share[i]);
    }

    if (!payload.empty() && !net::send_all(conn_fd, payload.data(), payload.size() * sizeof(uint64_t))) {
        std::cerr << "[WARN] Failed to send permute-share payload" << std::endl;
    }
}

void Client::setup_crypto(uint64_t log_poly_modulus_degree, vector<Modulus> coeff_bits, uint64_t prime_bitlength, bool _verbose)
{
    uint64_t poly_modulus_degree = 1ULL << log_poly_modulus_degree;
    enc_params = std::make_unique<seal::EncryptionParameters>(seal::scheme_type::bfv);
    enc_params->set_poly_modulus_degree(poly_modulus_degree);
    enc_params->set_coeff_modulus(coeff_bits);
    enc_params->set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, prime_bitlength));

    context = std::make_shared<seal::SEALContext>(*enc_params);
    keygen = std::make_unique<seal::KeyGenerator>(*context);
    secret_key = keygen->secret_key();
    
    evaluator = std::make_unique<seal::Evaluator>(*context);
    encryptor = std::make_unique<seal::Encryptor>(*context, secret_key);
    batch_encoder = std::make_unique<seal::BatchEncoder>(*context);

}

void Client::send_parameters_and_keys(bool debug_mode)
{
    this->metrics->metrics_["comm_params"] = this->enc_params->save(this->params_stream);

    Serializable<RelinKeys> rlk_client = this->keygen->create_relin_keys();
    this->metrics->metrics_["comm_relin_keys"] = rlk_client.save(this->params_stream);

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

void Client::finalize_phase_metrics(Params params) {
    auto get = [this](const char* key) -> uint64_t {
        const auto it = metrics->metrics_.find(key);
        return it == metrics->metrics_.end() ? 0ULL : it->second;
    };

    // Canonical, non-overlapping byte counters used by all four tasks.
    metrics->metrics_["comm_setup"] =
        get("comm_params") + get("comm_relin_keys") + get("comm_gal_keys") + get("comm_pk");
    metrics->metrics_["comm_offline"] = get("comm_request");

    uint64_t online_bytes = get("comm_response");
    if (params.task == PSU) {
        online_bytes += get("comm_final_response");
    } else if (params.task == PSUca_S) {
        online_bytes += sizeof(uint64_t); // client -> server ca_mid
    } else if (params.task == circuitPSU) {
        // comm_response already contains the ciphertext-refresh round.
        online_bytes += get("comm_ot") + get("comm_permuteshare");
    }
    metrics->metrics_["comm_online"] = online_bytes;

    // Compatibility aliases: old result readers used time_offline for the
    // mixed client-encryption/request-send value.  New files expose the phase
    // split explicitly and keep time_offline as computation only.
    metrics->metrics_["time_offline"] = get("time_offline_comp");
    metrics->metrics_["metrics_schema_version"] = 2;
}

uint64_t Client::send_setup_over_network(uint64_t& setup_round_ms) {
    if (!remote_server_) {
        throw std::logic_error("remote setup requested in local mode");
    }

    std::mt19937_64 session_rng(std::random_device{}());
    do {
        setup_session_id_ = session_rng();
    } while (setup_session_id_ == 0);

    std::vector<uint8_t> request;
    auto append_u32 = [&](uint32_t value) {
        const uint32_t be = htonl(value);
        const auto* p = reinterpret_cast<const uint8_t*>(&be);
        request.insert(request.end(), p, p + sizeof(be));
    };
    auto append_u64 = [&](uint64_t value) {
        const uint64_t be = htobe64(value);
        const auto* p = reinterpret_cast<const uint8_t*>(&be);
        request.insert(request.end(), p, p + sizeof(be));
    };

    const std::string setup = params_stream.str();
    append_u32(kStandaloneMagic);
    append_u32(kStandaloneWireVersion);
    append_u32(kStandaloneSetupMessage);
    append_u64(setup_session_id_);
    append_u64(setup.size());
    request.insert(request.end(), setup.begin(), setup.end());

    const auto start = std::chrono::steady_clock::now();
    auto client_fd = psu::network::SocketClient::connect_to(net_cfg_.host, net_cfg_.psu_port);
    psu::network::SocketUtils::send_message(client_fd.get(), request);
    std::vector<uint8_t> response;
    if (!psu::network::SocketUtils::recv_message(client_fd.get(), response)) {
        throw std::runtime_error("failed to receive standalone setup response");
    }
    const auto end = std::chrono::steady_clock::now();
    setup_round_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

    if (response.size() < sizeof(uint32_t)) {
        throw std::runtime_error("truncated standalone setup response");
    }
    uint32_t status_be = 0;
    std::memcpy(&status_be, response.data(), sizeof(status_be));
    if (ntohl(status_be) != 0) {
        throw std::runtime_error("server rejected standalone setup: " +
            std::string(response.begin() + sizeof(uint32_t), response.end()));
    }
    if (response.size() != sizeof(uint32_t) + sizeof(uint64_t)) {
        throw std::runtime_error("invalid standalone setup response size");
    }
    uint64_t keygen_be = 0;
    std::memcpy(&keygen_be, response.data() + sizeof(uint32_t), sizeof(keygen_be));
    return be64toh(keygen_be);
}

std::string Client::send_psu_request_over_network(const std::string& payload,
                                                  uint64_t& request_ms,
                                                  uint64_t& response_ms) {
    auto start_t = std::chrono::steady_clock::now();
    
    auto client_fd = psu::network::SocketClient::connect_to(net_cfg_.host, net_cfg_.psu_port);
    
    // Standalone batch requests reference the setup session installed once at
    // the start of run_protocol.  They never resend the large SEAL key bundle.
    std::vector<uint8_t> payload_bytes;
    if (remote_server_) {
        auto append_u32 = [&](uint32_t value) {
            uint32_t be = htonl(value);
            const auto* p = reinterpret_cast<const uint8_t*>(&be);
            payload_bytes.insert(payload_bytes.end(), p, p + sizeof(be));
        };
        auto append_u64 = [&](uint64_t value) {
            uint64_t be = htobe64(value);
            const auto* p = reinterpret_cast<const uint8_t*>(&be);
            payload_bytes.insert(payload_bytes.end(), p, p + sizeof(be));
        };

        if (setup_session_id_ == 0) {
            throw std::runtime_error("standalone batch requested before setup");
        }
        append_u32(kStandaloneMagic);
        append_u32(kStandaloneWireVersion);
        append_u32(kStandaloneBatchMessage);
        append_u64(setup_session_id_);
        append_u32(static_cast<uint32_t>(metrics->metrics_["task"]));
        append_u32(static_cast<uint32_t>(metrics->metrics_["ell"]));
        append_u64(metrics->metrics_["server_set"]);
        append_u64(metrics->metrics_["effective_lambda"]);
        append_u64(metrics->metrics_["hw"]);
        append_u64(metrics->metrics_["client_set"]);
        append_u64(metrics->metrics_["active_bins"]);
        append_u64(metrics->metrics_["client_bin_offset"]);
        payload_bytes.insert(payload_bytes.end(), payload.begin(), payload.end());
    } else {
        payload_bytes.assign(payload.begin(), payload.end());
    }
    psu::network::SocketUtils::send_message(client_fd.get(), payload_bytes);
    auto sent_t = std::chrono::steady_clock::now();
    
    std::string response;
    std::vector<uint8_t> response_bytes;
    if (!psu::network::SocketUtils::recv_message(client_fd.get(), response_bytes)) {
        throw std::runtime_error("failed to receive PSU response");
    }
    if (response_bytes.size() < sizeof(uint32_t)) {
        throw std::runtime_error("truncated PSU response");
    }
    uint32_t status_be = 0;
    std::memcpy(&status_be, response_bytes.data(), sizeof(status_be));
    uint32_t status = ntohl(status_be);
    response.assign(response_bytes.begin() + sizeof(uint32_t), response_bytes.end());
    if (status != 0) {
        throw std::runtime_error("server rejected PSU request: " + response);
    }
    auto recv_t = std::chrono::steady_clock::now();

    request_ms = std::chrono::duration_cast<std::chrono::milliseconds>(sent_t - start_t).count();
    response_ms = std::chrono::duration_cast<std::chrono::milliseconds>(recv_t - sent_t).count();
    
    return response;
}

void Client::send_masked_payload_over_network(const std::string& payload, uint64_t& send_ms) {
    std::string host = net_cfg_.host;
    uint16_t port = net_cfg_.masked_port;
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
    }

    auto round_end = std::chrono::steady_clock::now();
    send_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(round_end - send_start).count());

    ::close(sock_fd);
}

void Client::send_psuca_mid_over_network(int64_t ca_mid, uint64_t& send_ms) {
    std::string host = net_cfg_.host;
    uint16_t port = net_cfg_.ca_mid_port;
    if (const char* env_host = std::getenv("PSU_SERVER_HOST"); env_host && env_host[0] != '\0') {
        host = std::string(env_host);
    }
    if (const char* env_port = std::getenv("PSU_CA_MID_PORT"); env_port && env_port[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            port = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_CA_MID_PORT='" << env_port
                      << "', fallback to " << port << std::endl;
        }
    }

    int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) {
        throw std::runtime_error("failed to connect to PSUca mid server at " + host + ":" + std::to_string(port));
    }

    auto send_start = std::chrono::steady_clock::now();
    uint64_t ca_mid_be = htobe64(static_cast<uint64_t>(ca_mid));
    if (!net::send_all(sock_fd, &ca_mid_be, sizeof(ca_mid_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send PSUca mid value");
    }
    uint64_t ack = 0;
    if (!net::recv_all(sock_fd, &ack, sizeof(ack))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive PSUca mid ack");
    }

    auto round_end = std::chrono::steady_clock::now();
    send_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(round_end - send_start).count());

    ::close(sock_fd);
}

std::vector<uint64_t> Client::receive_syprime_over_network(uint64_t& recv_ms) {
    std::string host = net_cfg_.host;
    uint16_t port = net_cfg_.syprime_port;
    if (const char* env_host = std::getenv("PSU_SERVER_HOST"); env_host && env_host[0] != '\0') {
        host = std::string(env_host);
    }
    if (const char* env_port = std::getenv("PSU_SYPRIME_PORT"); env_port && env_port[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            port = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_SYPRIME_PORT='" << env_port
                      << "', fallback to " << port << std::endl;
        }
    }

    int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) {
        throw std::runtime_error("failed to connect to syprime server at " + host + ":" + std::to_string(port));
    }

    auto recv_start = std::chrono::steady_clock::now();
    uint64_t count_be = 0;
    if (!net::recv_all(sock_fd, &count_be, sizeof(count_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive syprime count");
    }
    uint64_t count = be64toh(count_be);
    std::vector<uint64_t> values(count);
    if (count > 0) {
        std::vector<uint64_t> payload(count);
        size_t bytes = payload.size() * sizeof(uint64_t);
        if (!net::recv_all(sock_fd, payload.data(), bytes)) {
            ::close(sock_fd);
            throw std::runtime_error("failed to receive syprime payload");
        }
        for (uint64_t i = 0; i < count; ++i) {
            values[i] = be64toh(payload[i]);
        }
    }
    auto recv_end = std::chrono::steady_clock::now();
    recv_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(recv_end - recv_start).count());

    ::close(sock_fd);
    return values;
}

void Client::encrypt_and_send(vector<Plaintext>& plaintexts, bool _verbose) {
    data_stream.str("");
    std::vector<Plaintext> result;
    this->metrics->metrics_["comm_request"] = 0;
    for (int i = 0; i < plaintexts.size(); i++) {
        this->metrics->metrics_["comm_request"] += this->encryptor->encrypt_symmetric(plaintexts[i]).save(data_stream);
    }
}

uint64_t Client::decode_cardinality(const Plaintext& pt, uint64_t num_bins) {
    vector<uint64_t> slots;
    this->batch_encoder->decode(pt, slots);
    uint64_t limit = min<uint64_t>(num_bins, slots.size());
    uint64_t sum = 0ULL;
    for (uint64_t i = 0; i < limit; ++i) {
        sum += slots[i];
    }
    return sum;
}

vector<Plaintext> Client::load_and_decrypt(int num_cts, Params params, bool _verbose) {
    std::vector<Plaintext> result;
    Decryptor decryptor(*context, this->secret_key);

    std::stringstream response_stream(this->data_stream.str());
    this->metrics->metrics_["comm_response"] = 0;


    if (params.task == PSUca_C || params.task == PSUca_S) {
        const auto refresh_prepare_start = std::chrono::steady_clock::now();

        // The primary response is deliberately one-time-padded but has an
        // exhausted EEQ noise budget. Decrypting it reveals only uniform
        // random slots. Re-encrypt it so the server can remove this first pad,
        // apply an independent final pad, and perform a Galois slot
        // permutation on a fresh ciphertext.
        Ciphertext blinded_ct;
        this->metrics->metrics_["comm_response"] +=
            blinded_ct.load(*(this->context), response_stream);
        Plaintext blinded_plain;
        decryptor.decrypt(blinded_ct, blinded_plain);
        Ciphertext refreshed_ct;
        this->encryptor->encrypt_symmetric(blinded_plain, refreshed_ct);
        std::stringstream refresh_stream;
        refreshed_ct.save(refresh_stream);
        const std::string refresh_bytes = refresh_stream.str();
        const auto refresh_prepare_end = std::chrono::steady_clock::now();

        const auto refresh_round_start = std::chrono::steady_clock::now();
        auto control = psu::network::SocketClient::connect_to(
            net_cfg_.host, net_cfg_.circuit_control_port);
        uint64_t refresh_request[5] = {
            htobe64(kPsucaRefreshMagic), htobe64(refresh_bytes.size()),
            htobe64(static_cast<uint64_t>(params.task)), 0ULL, 0ULL
        };
        if (!net::send_all(control.get(), refresh_request, sizeof(refresh_request)) ||
            !net::send_all(control.get(), refresh_bytes.data(), refresh_bytes.size())) {
            throw std::runtime_error("failed to send refreshed PSUca ciphertext");
        }
        uint64_t final_size_be = 0;
        if (!net::recv_all(control.get(), &final_size_be, sizeof(final_size_be))) {
            throw std::runtime_error("failed to receive shuffled PSUca response size");
        }
        uint64_t server_compute_ms_be = 0;
        if (!net::recv_all(control.get(), &server_compute_ms_be,
                           sizeof(server_compute_ms_be))) {
            throw std::runtime_error("failed to receive PSUca refresh compute time");
        }
        const uint64_t server_compute_ms = be64toh(server_compute_ms_be);
        const uint64_t final_size = be64toh(final_size_be);
        if (final_size == 0 || final_size > (1ULL << 30)) {
            throw std::runtime_error("invalid shuffled PSUca response size");
        }
        std::string final_bytes(final_size, '\0');
        if (!net::recv_all(control.get(), final_bytes.data(), final_bytes.size())) {
            throw std::runtime_error("failed to receive shuffled PSUca response");
        }
        const auto refresh_round_end = std::chrono::steady_clock::now();
        response_stream.str(final_bytes);
        response_stream.clear();
        const auto online_comp_start = std::chrono::steady_clock::now();

        const uint64_t refresh_wire_bytes = sizeof(refresh_request) + refresh_bytes.size()
                                          + sizeof(final_size_be)
                                          + sizeof(server_compute_ms_be)
                                          + final_bytes.size();
        this->metrics->metrics_["comm_response"] += refresh_wire_bytes;
        this->metrics->metrics_["comm_psuca_refresh"] += refresh_wire_bytes;
        this->metrics->metrics_["time_psuca_refresh_ms"] += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                refresh_round_end - refresh_round_start).count());
        const uint64_t refresh_round_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                refresh_round_end - refresh_round_start).count());
        this->metrics->metrics_["time_online_comm"] +=
            refresh_round_ms > server_compute_ms
                ? refresh_round_ms - server_compute_ms : 0ULL;
        this->metrics->metrics_["time_online_comp"] += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                refresh_prepare_end - refresh_prepare_start).count());
        this->metrics->metrics_["time_online_client"] += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                refresh_prepare_end - refresh_prepare_start).count());

        uint64_t ca_mask = 0;
        if (params.task == PSUca_C) {
            uint64_t mask_be = 0;
            if (!response_stream.read(reinterpret_cast<char*>(&mask_be), sizeof(mask_be))) {
                throw std::runtime_error("failed to read mask from PSUca response");
            }
            ca_mask = be64toh(mask_be);
        }

        Ciphertext ca_ct;
        ca_ct.load(*(this->context), response_stream);
        if (std::getenv("FEUPSU_VERIFY_CARDINALITY")) {
            std::cerr << "[VERIFY][PSUca] noise_budget="
                      << decryptor.invariant_noise_budget(ca_ct) << " bits" << std::endl;
        }
        Plaintext ca_pt;
        decryptor.decrypt(ca_ct, ca_pt);
        result.push_back(ca_pt);

        std::vector<uint64_t> slots;
        this->batch_encoder->decode(ca_pt, slots);

        uint64_t slot_count = this->batch_encoder->slot_count();
        uint64_t num_bins = params.active_bins > 0
                          ? params.active_bins
                          : (1ULL << params.log_poly_modulus_degree);
        if (num_bins > slot_count) {
            num_bins = slot_count;
        }

        if (slots.size() < num_bins) {
            throw std::runtime_error("empty PSU cardinality plaintext");
        }
        const uint64_t plain_mod = this->enc_params->plain_modulus().value();
        uint64_t ca_value = 0;
        for (uint64_t i = 0; i < num_bins; ++i) {
            ca_value = static_cast<uint64_t>(
                (static_cast<unsigned __int128>(ca_value) + slots[i]) % plain_mod);
        }

        if (!remote_server_ && this->server && std::getenv("FEUPSU_VERIFY_CARDINALITY")) {
            std::cerr << "[VERIFY][PSUca] masked_sum=" << ca_value
                      << " mask=" << ca_mask
                      << " server_mask=" << this->server->psuca_shf_sum_
                      << " plain_mod=" << plain_mod
                      << std::endl;
        }

        if (params.task == PSUca_C) {
            const uint64_t scaled_unmatched =
                (ca_value + plain_mod - ca_mask) % plain_mod;
            const uint64_t inv_factorial =
                build_eeq_params(params.hw, plain_mod).coefficients.back();
            const uint64_t unmatched = static_cast<uint64_t>(
                (static_cast<unsigned __int128>(scaled_unmatched) * inv_factorial)
                % plain_mod);
            ca_value = params.server_set + unmatched;
        }

        if (params.task == PSUca_C || params.task == PSUca_S) {
            auto online_comp_end = std::chrono::steady_clock::now();
            uint64_t online_comp_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(online_comp_end - online_comp_start).count());
            this->metrics->metrics_["time_online_comp"] += online_comp_ms;
            this->metrics->metrics_["time_online_client"] += online_comp_ms;
        }

        if (params.task == PSUca_C) {
            cout << "[CLIENT] ca = " << ca_value << endl;
            this->metrics->metrics_["cardi"] = ca_value;
        } else {
            cout << "[CLIENT] ca_mid = " << ca_value << endl;
            uint64_t send_ms = 0;
            const uint64_t server_before = this->metrics->metrics_["time_online_server"];
            send_psuca_mid_over_network(ca_value, send_ms);
            const uint64_t server_after = this->metrics->metrics_["time_online_server"];
            const uint64_t server_delta = server_after - server_before;
            const uint64_t comm_ms = send_ms > server_delta ? send_ms - server_delta : 0ULL;
            auto it_online = this->metrics->metrics_.find("time_online_comm");
            if (it_online != this->metrics->metrics_.end()) {
                it_online->second += comm_ms;
            } else {
                this->metrics->metrics_["time_online_comm"] = comm_ms;
            }
            this->metrics->metrics_["comm_online"] += this->metrics->metrics_["comm_response"] + sizeof(uint64_t);
        }

        this->data_stream.str("");
        this->data_stream.clear();
        return result;
    }

    if (params.task == circuitPSU) {
        const bool measure_otsss = params.time_otsss;
        std::chrono::steady_clock::time_point otsss_start;
        if (measure_otsss) {
            otsss_start = std::chrono::steady_clock::now();
        }

        uint64_t comm_response = 0;
        comm_response += this->server_public_key.load(*(this->context), response_stream);
        Ciphertext masked_indicator;
        comm_response += masked_indicator.load(*(this->context), response_stream);
        this->metrics->metrics_["comm_response"] = comm_response;
        if (std::getenv("FEUPSU_VERIFY_CIRCUIT")) {
            std::cerr << "[VERIFY][circuitPSU] masked_indicator_noise_budget="
                      << decryptor.invariant_noise_budget(masked_indicator) << " bits" << std::endl;
        }

        // Decrypt only the additively one-time-padded EEQ value, then refresh
        // it by symmetric encryption under the same client key.  The server
        // removes its pad from this fresh ciphertext in the control round.
        auto refresh_start = std::chrono::steady_clock::now();
        Plaintext masked_plain;
        decryptor.decrypt(masked_indicator, masked_plain);
        Ciphertext refreshed_masked;
        this->encryptor->encrypt_symmetric(masked_plain, refreshed_masked);
        std::stringstream refresh_stream;
        refreshed_masked.save(refresh_stream);
        const std::string refresh_bytes = refresh_stream.str();
        auto refresh_prepare_end = std::chrono::steady_clock::now();

        uint64_t slot_count = this->batch_encoder->slot_count();
        uint64_t num_bins = params.active_bins > 0
                          ? params.active_bins
                          : (1ULL << params.log_poly_modulus_degree);
        if (num_bins > slot_count) {
            num_bins = slot_count;
        }

        if (client_sx_.size() < num_bins || client_sx_prime_.size() < num_bins) {
            throw std::runtime_error("client x shares missing or truncated");
        }
        uint64_t sy_count_be = 0;
        response_stream.read(reinterpret_cast<char*>(&sy_count_be), sizeof(sy_count_be));
        const uint64_t sy_count = be64toh(sy_count_be);
        if (!response_stream || sy_count != params.server_set) {
            throw std::runtime_error("missing or invalid server y share in circuitPSU response");
        }
        client_sy_prime_.resize(sy_count);
        for (uint64_t i = 0; i < sy_count; ++i) {
            uint64_t word_be = 0;
            response_stream.read(reinterpret_cast<char*>(&word_be), sizeof(word_be));
            if (!response_stream) throw std::runtime_error("truncated server y share");
            client_sy_prime_[i] = be64toh(word_be);
        }
        comm_response += sizeof(uint64_t) * (sy_count + 1);
        this->metrics->metrics_["comm_response"] = comm_response;

        // The bundled Benes implementation supports arbitrary wire counts.
        // Avoid padding 2^22 + N all the way to 2^23, which nearly doubles the
        // switch count and peak OSN memory without adding protocol value.
        const uint64_t shuffle_count = num_bins + sy_count;
        if (bcs_permutation_.size() != shuffle_count) {
            throw std::runtime_error("client permutation size mismatch for circuitPSU shuffle");
        }

        auto control = psu::network::SocketClient::connect_to(net_cfg_.host,
                                                               net_cfg_.circuit_control_port);
        uint64_t request[5] = {htobe64(num_bins), htobe64(shuffle_count),
                               htobe64(net_cfg_.circuit_ot_port),
                               htobe64(net_cfg_.circuit_osn_port),
                               htobe64(refresh_bytes.size())};
        if (!net::send_all(control.get(), request, sizeof(request)) ||
            !net::send_all(control.get(), refresh_bytes.data(), refresh_bytes.size())) {
            throw std::runtime_error("failed to request circuit finalization");
        }

        uint64_t share_size_be = 0;
        if (!net::recv_all(control.get(), &share_size_be, sizeof(share_size_be))) {
            throw std::runtime_error("failed to receive refreshed circuit share size");
        }
        const uint64_t share_size = be64toh(share_size_be);
        if (share_size == 0 || share_size > (1ULL << 30)) {
            throw std::runtime_error("invalid refreshed circuit share size");
        }
        std::string share_bytes(share_size, '\0');
        if (!net::recv_all(control.get(), share_bytes.data(), share_bytes.size())) {
            throw std::runtime_error("failed to receive refreshed circuit share");
        }
        std::stringstream share_stream(share_bytes);
        Ciphertext shs_cipher;
        shs_cipher.load(*(this->context), share_stream);
        if (std::getenv("FEUPSU_VERIFY_CIRCUIT")) {
            std::cerr << "[VERIFY][circuitPSU] refreshed_share_noise_budget="
                      << decryptor.invariant_noise_budget(shs_cipher) << " bits" << std::endl;
        }
        auto refresh_decode_start = std::chrono::steady_clock::now();
        Plaintext shs_plain;
        decryptor.decrypt(shs_cipher, shs_plain);
        std::vector<uint64_t> shs_slots;
        this->batch_encoder->decode(shs_plain, shs_slots);
        std::vector<uint64_t> shs_bits(num_bins, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            if (shs_slots[i] > 1ULL) {
                throw std::runtime_error("circuitPSU refreshed share is not a bit at slot "
                    + std::to_string(i));
            }
            shs_bits[i] = shs_slots[i];
        }
        auto refresh_end = std::chrono::steady_clock::now();
        const uint64_t refresh_wire_bytes =
            sizeof(request) + refresh_bytes.size() + sizeof(share_size_be) + share_bytes.size();
        const uint64_t refresh_local_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                refresh_prepare_end - refresh_start).count())
            + static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                refresh_end - refresh_decode_start).count());
        this->metrics->metrics_["time_online_comp"] += refresh_local_ms;
        this->metrics->metrics_["time_online_client"] += refresh_local_ms;
        const uint64_t refresh_round_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(refresh_end - refresh_start).count());
        this->metrics->metrics_["time_circuit_refresh_ms"] += refresh_round_ms;
        // The refresh round is communication-bearing and the client blocks
        // until the server returns.  Keep its wall time in the communication
        // metric; local/server computation is independently present in
        // time_online_comp.
        this->metrics->metrics_["time_online_comm"] += refresh_round_ms;
        this->metrics->metrics_["comm_circuit_refresh"] += refresh_wire_bytes;
        // Existing analysis scripts total circuit communication from
        // comm_response + comm_ot + comm_permuteshare, so include this new
        // interactive round in comm_response as well as exposing its own key.
        comm_response += refresh_wire_bytes;
        this->metrics->metrics_["comm_response"] = comm_response;

        circuit::PartyResult ot_sender;
        bcs::PartyShareOutput osn_sender;
        const std::string bind_host = "0.0.0.0";
        const std::string ot_endpoint = bind_host + ":" + std::to_string(net_cfg_.circuit_ot_port);
        const std::string osn_endpoint = bind_host + ":" + std::to_string(net_cfg_.circuit_osn_port);
        // The server consumes OT and OSN in this order as well. Sequential
        // execution avoids constructing a second outer worker while the first
        // is joinable; under memory pressure that old pattern caused
        // "terminate called without an active exception".
        ot_sender = circuit::send_x_shares(client_sx_, client_sx_prime_, shs_bits, ot_endpoint);
        osn_sender = bcs::permute_share_sender(bcs_permutation_, osn_endpoint, 1);

        uint64_t response[3]{};
        if (!net::recv_all(control.get(), response, sizeof(response))) {
            throw std::runtime_error("failed to receive circuit finalization response");
        }
        if (be64toh(response[0]) != shuffle_count) {
            throw std::runtime_error("server rejected circuit finalization");
        }

        std::vector<uint64_t> client_inputs;
        client_inputs.reserve(shuffle_count);
        client_inputs.insert(client_inputs.end(), client_sx_.begin(), client_sx_.end());
        client_inputs.insert(client_inputs.end(), client_sy_prime_.begin(), client_sy_prime_.end());
        client_inputs.resize(shuffle_count, 0ULL);
        auto permuted_client = bcs::apply_permutation(client_inputs, bcs_permutation_);
        if (osn_sender.share.size() != permuted_client.size()) {
            throw std::runtime_error("client OSN output size mismatch");
        }
        circuit_output_share_.resize(permuted_client.size());
        for (std::size_t i = 0; i < permuted_client.size(); ++i) {
            circuit_output_share_[i] = permuted_client[i] ^ osn_sender.share[i];
        }
        save_circuit_share_if_requested("FEUPSU_CLIENT_SHARE_FILE", circuit_output_share_);
        this->metrics->metrics_["circuit_output_shares"] = circuit_output_share_.size();
        this->metrics->metrics_["comm_ot"] += ot_sender.comm_bytes + be64toh(response[1]);
        this->metrics->metrics_["comm_permuteshare"] += osn_sender.comm_bytes + be64toh(response[2]);
        this->metrics->metrics_["time_online_comp"] += ot_sender.compute_ms + osn_sender.compute_ms;
        this->metrics->metrics_["time_online_client"] += ot_sender.compute_ms + osn_sender.compute_ms;
        // libOTe/OSN expose complete round latency and byte counters, but not
        // socket-only wait time.  Their communication time is consequently
        // reported as the measured communication-bearing round latency.
        this->metrics->metrics_["time_online_comm"] += ot_sender.compute_ms + osn_sender.compute_ms;
        permute_share_time_us_.store(osn_sender.compute_ms * 1000ULL, std::memory_order_relaxed);
        permute_share_invocations_.store(1, std::memory_order_relaxed);

        if (!remote_server_ && this->server && std::getenv("FEUPSU_VERIFY_CIRCUIT")) {
            if (this->server->circuit_output_share_.size() != circuit_output_share_.size()) {
                throw std::runtime_error("circuit verification: server output share size mismatch");
            }
            std::vector<uint64_t> expected_unpermuted(shuffle_count, 0ULL);
            for (uint64_t i = 0; i < num_bins; ++i) {
                const uint64_t membership = (shs_bits[i] ^ this->server->server_shs_bits_[i]) & 1ULL;
                const uint64_t x_shifted = client_sx_[i] ^ client_sx_prime_[i];
                expected_unpermuted[i] = membership ? 0ULL : x_shifted;
            }
            for (uint64_t i = 0; i < sy_count; ++i) {
                uint64_t y = params.effective_lambda >= 64
                           ? i
                           : i % (1ULL << params.effective_lambda);
                expected_unpermuted[num_bins + i] = append_zeros(y, kSharePadBits);
            }
            std::vector<uint64_t> expected = bcs::apply_permutation(expected_unpermuted,
                                                                     bcs_permutation_);
            if (this->server->circuit_pre_shuffle_share_.size() != client_inputs.size()) {
                throw std::runtime_error("circuit verification: pre-shuffle share size mismatch");
            }
            for (std::size_t i = 0; i < expected_unpermuted.size(); ++i) {
                uint64_t reconstructed = client_inputs[i] ^ this->server->circuit_pre_shuffle_share_[i];
                if (reconstructed != expected_unpermuted[i]) {
                    throw std::runtime_error("circuit verification: OT/input share failed at " +
                                             std::to_string(i) + ": actual=" +
                                             std::to_string(reconstructed) + ", expected=" +
                                             std::to_string(expected_unpermuted[i]));
                }
            }
            for (std::size_t i = 0; i < expected.size(); ++i) {
                if ((circuit_output_share_[i] ^ this->server->circuit_output_share_[i]) != expected[i]) {
                    uint64_t actual = circuit_output_share_[i] ^ this->server->circuit_output_share_[i];
                    throw std::runtime_error("circuit verification failed at output " + std::to_string(i) +
                                             ": actual=" + std::to_string(actual) +
                                             ", expected=" + std::to_string(expected[i]));
                }
            }
            this->metrics->metrics_["circuit_correct"] = 1;
        }

        if (measure_otsss) {
            auto otsss_end = std::chrono::steady_clock::now();
            uint64_t otsss_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(otsss_end - otsss_start).count());
            this->metrics->metrics_["time_OTSSS_ms"] = otsss_ms;
        }

        return result;
    }

    else {
    // The server returns E_pkC(hw!*membership + r) and E_pkS(r), where r is
    // uniform in Z_t per slot.  Decrypting the first value reveals nothing
    // about membership.  Subtracting the encrypted mask transfers the EEQ
    // result to a fresh ciphertext under the server key; normalization is
    // therefore performed with a full noise budget.
    this->metrics->metrics_["comm_response"] +=
        this->server_public_key.load(*(this->context), response_stream);

    Ciphertext masked_indicator;
    this->metrics->metrics_["comm_response"] +=
        masked_indicator.load(*(this->context), response_stream);
    if (std::getenv("FEUPSU_VERIFY_PSU")) {
        std::cerr << "[VERIFY][PSU] masked_indicator_noise_budget="
                  << decryptor.invariant_noise_budget(masked_indicator) << " bits" << std::endl;
    }
    Plaintext masked_plain;
    auto decrypt_start = std::chrono::steady_clock::now();
    decryptor.decrypt(masked_indicator, masked_plain);
    result.push_back(masked_plain);
    auto decrypt_end = std::chrono::steady_clock::now();

    Ciphertext encrypted_mask;
    this->metrics->metrics_["comm_response"] +=
        encrypted_mask.load(*(this->context), response_stream);

    auto ind_compute_start = std::chrono::steady_clock::now();
    Ciphertext membership(encrypted_mask);
    this->evaluator->negate_inplace(membership);
    this->evaluator->add_plain_inplace(membership, masked_plain);

    const uint64_t plain_mod = this->enc_params->plain_modulus().value();
    const uint64_t inv_factorial =
        build_eeq_params(params.hw, plain_mod).coefficients.back();
    std::vector<uint64_t> inv_slots(this->batch_encoder->slot_count(), inv_factorial);
    Plaintext inv_plain;
    this->batch_encoder->encode(inv_slots, inv_plain);
    this->evaluator->multiply_plain_inplace(membership, inv_plain);

    // PSU needs the inverse indicator: client-only bins are 1, intersection
    // bins are 0.  Keep it encrypted under the server key.
    Ciphertext inverse_indicator(membership);
    this->evaluator->negate_inplace(inverse_indicator);
    std::vector<uint64_t> one_slots(this->batch_encoder->slot_count(), 1ULL);
    Plaintext one_plain;
    this->batch_encoder->encode(one_slots, one_plain);
    this->evaluator->add_plain_inplace(inverse_indicator, one_plain);
    vector<Ciphertext> ind_cts{std::move(inverse_indicator)};
    if (std::getenv("FEUPSU_VERIFY_PSU") && !remote_server_ && this->server) {
        Decryptor server_decryptor(*this->context, this->server->server_secret_key);
        for (const auto& ind_ct : ind_cts) {
            Plaintext verify_plain;
            std::vector<uint64_t> verify_slots;
            server_decryptor.decrypt(ind_ct, verify_plain);
            this->batch_encoder->decode(verify_plain, verify_slots);
            const uint64_t verify_bins = std::min<uint64_t>(
                params.active_bins > 0 ? params.active_bins
                                       : (1ULL << params.log_poly_modulus_degree),
                verify_slots.size());
            for (uint64_t slot = 0; slot < verify_bins; ++slot) {
                if (verify_slots[slot] != 0ULL) {
                    throw std::runtime_error("PSU inverse indicator verification failed at slot "
                        + std::to_string(slot));
                }
            }
        }
        std::cerr << "[VERIFY][PSU] normalized inverse indicators passed" << std::endl;
    }
    auto ind_compute_end = std::chrono::steady_clock::now();

    // cout << "[INFO] Client computed shs+shr-2*shs*shr for each share (ind_cts.size()=" << ind_cts.size() << ")." << endl;


    // K = final_cts.size(); num_bins = number of bins = 1 << log_poly_modulus_degree
    uint64_t K = ind_cts.size();
    uint64_t num_bins = params.active_bins > 0
                        ? params.active_bins
                        : (1ULL << params.log_poly_modulus_degree);
    uint64_t slot_count = this->batch_encoder->slot_count();
    if (num_bins > slot_count) num_bins = slot_count; // safety

    uint64_t p = this->enc_params->plain_modulus().value();
    vector<vector<uint64_t>> all_elements_per_group(K, vector<uint64_t>(num_bins));
    uint64_t global_max = 0;
    for (uint64_t k = 0; k < K; ++k) {
        uint64_t gamma_prime = k;
        for (uint64_t i = 0; i < num_bins; ++i) {
            uint64_t global_bin = params.client_bin_offset + i;
            all_elements_per_group[k][i] = client_get(gamma_prime, global_bin, params.effective_lambda);
            if (all_elements_per_group[k][i] > global_max) global_max = all_elements_per_group[k][i];
        }
    }

    uint64_t D = 1;
    uint64_t tmp_max = global_max;
    while (tmp_max >= p) { tmp_max = tmp_max / p; D++; }

    this->data_stream.str("");
    this->data_stream.clear();
    uint64_t comm_otsss_bytes = sizeof(K) + sizeof(D) + sizeof(num_bins);
    this->data_stream.write(reinterpret_cast<const char*>(&K), sizeof(K));
    this->data_stream.write(reinterpret_cast<const char*>(&D), sizeof(D));
    this->data_stream.write(reinterpret_cast<const char*>(&num_bins), sizeof(num_bins));

    if (bcs_permutation_.size() != num_bins) {
        throw std::runtime_error("client permutation size mismatch when applying permuted indicators");
    }
    if (!this->gal_keys_local) {
        throw std::runtime_error("permute requires local Galois keys");
    }

    /*
     */
    uint64_t row_size = slot_count / 2;
    std::vector<uint64_t> mask_slots(slot_count, 0ULL);
    Plaintext mask_plain;

    auto permute_mask_start = std::chrono::steady_clock::now();
    for (uint64_t k = 0; k < K; ++k) {
        std::vector<uint64_t> permuted_elements = bcs::apply_permutation(all_elements_per_group[k], bcs_permutation_);

        Ciphertext permuted_ind_cipher;
        bool permuted_initialized = false;
        // cout << "[TRACE][client] applying permutation across " << num_bins << " bins" << endl;
        // auto perm_loop_start = std::chrono::steady_clock::now();
        for (uint64_t dest = 0; dest < num_bins; ++dest) {
            // if (dest % 2048 == 0) {
            //     auto now = std::chrono::steady_clock::now();
            //     auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - perm_loop_start).count();
            //     cout << "[TRACE][client] permuting slot " << dest << "/" << num_bins
            //          << " (elapsed " << (elapsed_ms / 1000.0) << " s)" << endl;
            // }
            uint32_t src = bcs_permutation_[dest];
            std::fill(mask_slots.begin(), mask_slots.end(), 0ULL);
            mask_slots[src] = 1ULL;
            this->batch_encoder->encode(mask_slots, mask_plain);

            Ciphertext isolated;
            this->evaluator->multiply_plain(ind_cts[k], mask_plain, isolated);

            uint64_t src_index = src;
            uint64_t dest_index = dest;
            bool src_second_row = src_index >= row_size;
            bool dest_second_row = dest_index >= row_size;
            if (src_second_row) {
                this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_local);
                src_index -= row_size;
            }
            if (dest_second_row) {
                dest_index -= row_size;
            }

            int modulus = static_cast<int>(row_size);
            if (modulus == 0) {
                modulus = 1;
            }
            int rotation = static_cast<int>(dest_index) - static_cast<int>(src_index);
            rotation %= modulus;
            if (rotation > modulus / 2) rotation -= modulus;
            if (rotation < -modulus / 2) rotation += modulus;
            if (rotation != 0) {
                this->evaluator->rotate_rows_inplace(isolated, rotation, *this->gal_keys_local);
            }

            if (dest_second_row) {
                this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_local);
            }

            if (!permuted_initialized) {
                permuted_ind_cipher = std::move(isolated);
                permuted_initialized = true;
            } else {
                this->evaluator->add_inplace(permuted_ind_cipher, isolated);
            }
        }

        if (!permuted_initialized) {
            throw std::runtime_error("failed to build permuted indicator ciphertext");
        }

        for (uint64_t d = 0; d < D; ++d) {
            vector<uint64_t> digit_slots(slot_count, 0);
            uint64_t base = 1;
            for (uint64_t dd = 0; dd < d; ++dd) base *= p;
            for (uint64_t i = 0; i < num_bins; ++i) {
                uint64_t val = permuted_elements[i];
                uint64_t digit = (val / base) % p;
                digit_slots[i] = digit;
            }

            Plaintext digit_pt; this->batch_encoder->encode(digit_slots, digit_pt);

            Ciphertext masked_ct;
            const bool all_zero_digit = std::all_of(
                digit_slots.begin(), digit_slots.end(),
                [](uint64_t value) { return value == 0ULL; });
            if (!all_zero_digit) {
                this->evaluator->multiply_plain(permuted_ind_cipher, digit_pt, masked_ct);
            } else {
                // Multiplication by an all-zero plaintext would create a
                // transparent ciphertext that SEAL refuses to serialize.
                // Emit a randomized encryption of zero under the server key.
                Encryptor server_zero_encryptor(*this->context, this->server_public_key);
                server_zero_encryptor.encrypt_zero(masked_ct);
            }
            if (masked_ct.is_transparent()) {
                // A transparent BFV ciphertext necessarily represents zero.
                // Re-randomize that zero so the wire format never contains a
                // transparent ciphertext and no receiver needs to guess.
                Encryptor server_zero_encryptor(*this->context, this->server_public_key);
                server_zero_encryptor.encrypt_zero(masked_ct);
            }
            uint64_t bytes = masked_ct.save(this->data_stream);
            comm_otsss_bytes += bytes;
        }
    }
    auto permute_mask_end = std::chrono::steady_clock::now();
    this->metrics->metrics_["time_extract_permute_mask"] = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(permute_mask_end - permute_mask_start).count());
    const uint64_t client_online_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            permute_mask_end - decrypt_start).count());
    this->metrics->metrics_["time_online_comp"] += client_online_ms;
    this->metrics->metrics_["time_online_client"] += client_online_ms;

    this->data_stream.clear();
    this->data_stream.seekg(0, std::ios::beg);
    this->metrics->metrics_["comm_final_response"] = comm_otsss_bytes;
    uint64_t send_ms = 0;
    const uint64_t server_before = this->metrics->metrics_["time_online_server"];
    send_masked_payload_over_network(this->data_stream.str(), send_ms);
    const uint64_t server_after = this->metrics->metrics_["time_online_server"];
    const uint64_t server_delta = server_after - server_before;
    const uint64_t comm_ms = send_ms > server_delta ? send_ms - server_delta : 0ULL;
    auto it_online = this->metrics->metrics_.find("time_online_comm");
    if (it_online != this->metrics->metrics_.end()) {
        it_online->second += comm_ms;
    } else {
        this->metrics->metrics_["time_online_comm"] = comm_ms;
    }
    pending_masked_response_ = false;
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
}

void Client::params_to_metrics(Params params) {
    // this->metrics->metrics_["gamma"] = params.gamma;
    this->metrics->metrics_["ell"] = params.ell;
    this->metrics->metrics_["hw"] = params.hw;
    this->metrics->metrics_["log_poly_modulus_degree"] = params.log_poly_modulus_degree;
    this->metrics->metrics_["effective_lambda"] = params.effective_lambda;
    this->metrics->metrics_["mu"] = params.mu;
    this->metrics->metrics_["server_set"] = params.server_set;
    this->metrics->metrics_["task"] = params.task;
}

bool Client::run_protocol(Params params, bool _verbose)
{
    Timer time_setup_crypto, time_server_latency, time_extract_response;
    if ((params.task == PSUca_C || params.task == PSUca_S) && params.client_set > 0) {
        const uint64_t capacity = 1ULL << params.log_poly_modulus_degree;
        if (params.client_set > capacity) {
            throw std::invalid_argument("cardinality client_set exceeds one BFV batch");
        }
        params.active_bins = params.client_set;
    }
    this->metrics = new Metrics();
    this->params_to_metrics(params);
    this->metrics->metrics_["client_set"] = params.client_set;
    this->metrics->metrics_["active_bins"] = params.active_bins;
    permute_share_time_us_.store(0, std::memory_order_relaxed);
    permute_share_invocations_.store(0, std::memory_order_relaxed);
    record_otsss_time_ = (params.task == circuitPSU) && params.time_otsss;

    // if (_verbose)
    //     cout << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    //             "<<<<<<<<<<<<<<<<<<<<<<"
    //          << endl;

    bool debug_mode=false;

    uint64_t hw = params.hw;

    // if (_verbose) {
    //     cout << "-------------------------- PSU Parameters "
    //             "--------------------------"
    //          << endl
    //          << "\tHamming Weight: " << params.hw << endl
    //          << "\tEffective Bitlength: " << params.effective_lambda << endl
    //          << "\tCode Length: " << params.ell << endl;
    // }

    // --- 1. Setup: client key generation/serialization plus server setup ---
    time_setup_crypto.start();
        this->setup_crypto(params.log_poly_modulus_degree, params.coeff_bits, params.prime_bitlength, _verbose);
    this->metrics->metrics_["time_setup_crypto"] = time_setup_crypto.end_and_get();

    const auto setup_all_start = std::chrono::steady_clock::now();
    this->send_parameters_and_keys(debug_mode);
    uint64_t server_keygen_ms = 0;
    uint64_t setup_round_ms = 0;
    if (!remote_server_) {
        if (!this->server) {
            throw std::runtime_error("local mode requires a Server instance");
        }
        server_keygen_ms = this->server->load_parameters_and_keys(
            this->params_stream, debug_mode, _verbose);
    } else {
        server_keygen_ms = this->send_setup_over_network(setup_round_ms);
    }
    const auto setup_all_end = std::chrono::steady_clock::now();
    this->metrics->metrics_["time_setup"] += this->metrics->metrics_["time_setup_crypto"];
    this->metrics->metrics_["time_setup"] += static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(setup_all_end - setup_all_start).count());
    this->metrics->metrics_["time_setup_server_keygen"] = server_keygen_ms;
    this->metrics->metrics_["time_setup_interaction"] = setup_round_ms;
    this->metrics->metrics_["setup_requests"] = 1;

    if (params.task == PSU) {
        const char* benchmark_env = std::getenv("FEUPSU_HW_BENCHMARK");
        const bool hw_benchmark = benchmark_env && benchmark_env[0] != '\0'
                                  && std::string(benchmark_env) != "0";
        const uint64_t slot_count = this->batch_encoder->slot_count();
        const uint64_t default_bins = std::min<uint64_t>(1ULL << params.log_poly_modulus_degree, slot_count);
        uint64_t total_bins = default_bins;
        if (params.client_set > 0) {
            total_bins = params.client_set;
        }
        if (total_bins == 0) {
            throw std::invalid_argument("PSU total bin count must be positive");
        }
        if (total_bins != default_bins && total_bins != (default_bins << 1)) {
            std::cerr << "[WARN] client_set=" << total_bins
                      << " is neither 1x nor 2x slot-aligned bins (default=" << default_bins
                      << "), running with manual chunking anyway." << std::endl;
        }

        const uint64_t bins_per_batch = default_bins;
        const uint64_t batch_count = (total_bins + bins_per_batch - 1) / bins_per_batch;

        bool need_masked_service = !hw_benchmark;
        uint64_t accumulated_request_ms = 0;
        uint64_t accumulated_response_ms = 0;
        uint64_t accumulated_extract_ms = 0;
        uint64_t accumulated_comm_request = 0;
        uint64_t accumulated_comm_response = 0;
        uint64_t accumulated_comm_final_response = 0;
        bool service_started = false;

        try {
            if (need_masked_service && !remote_server_) {
                server->start_masked_service();
                service_started = true;
            }

            for (uint64_t batch_idx = 0; batch_idx < batch_count; ++batch_idx) {
                const uint64_t batch_offset = batch_idx * bins_per_batch;
                const uint64_t active_bins = std::min<uint64_t>(bins_per_batch, total_bins - batch_offset);

                Params batch_params = params;
                batch_params.active_bins = active_bins;
                batch_params.client_bin_offset = batch_offset;
                this->metrics->metrics_["active_bins"] = active_bins;
                this->metrics->metrics_["client_bin_offset"] = batch_offset;
                std::mt19937_64 permutation_rng(std::random_device{}());
                bcs_permutation_ = bcs::generate_permutation(active_bins, permutation_rng);

                const auto offline_comp_start = std::chrono::steady_clock::now();
                std::vector<Plaintext> input;
                std::vector<uint64_t> client_elements(slot_count, 0ULL);
                std::vector<std::vector<uint64_t>> operands_vec(batch_params.ell, std::vector<uint64_t>(slot_count, 0ULL));

                for (uint64_t bin_index = 0; bin_index < active_bins; ++bin_index) {
                    const uint64_t global_bin = batch_offset + bin_index;
                    uint64_t element = client_get(0, global_bin, batch_params.effective_lambda);
                    client_elements[bin_index] = element;
                    std::vector<uint64_t> code = get_cw(element, batch_params.ell, batch_params.hw, true);
                    for (uint64_t l = 0; l < batch_params.ell; ++l) {
                        operands_vec[l][bin_index] = code[l];
                    }
                }

                Plaintext operand_pt;
                for (uint64_t l = 0; l < batch_params.ell; ++l) {
                    this->batch_encoder->encode(operands_vec[l], operand_pt);
                    input.push_back(operand_pt);
                }

                this->encrypt_and_send(input, _verbose);
                auto offline_end = std::chrono::steady_clock::now();
                uint64_t offline_ms = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(offline_end - offline_comp_start).count());
                this->metrics->metrics_["time_offline_comp"] += offline_ms;
                this->metrics->metrics_["time_offline_client"] += offline_ms;
                accumulated_comm_request += this->metrics->metrics_["comm_request"];

                uint64_t request_ms = 0;
                uint64_t response_ms = 0;
                if (!remote_server_) {
                    this->server->start_psu_service(batch_params, static_cast<int>(input.size()), this->metrics, _verbose);
                }
                std::string response = send_psu_request_over_network(this->data_stream.str(), request_ms, response_ms);
                this->data_stream.str(response);
                this->data_stream.clear();
                if (!remote_server_) {
                    this->server->stop_psu_service();
                }

                accumulated_request_ms += request_ms;
                accumulated_response_ms += response_ms;
                this->metrics->metrics_["time_offline_comm"] += request_ms;
                this->metrics->metrics_["time_online_response_wait"] += response_ms;

                if (!hw_benchmark) {
                    time_extract_response.start();
                    std::vector<Plaintext> _response_pts = this->load_and_decrypt(2, batch_params, _verbose);
                    (void)_response_pts;
                    accumulated_extract_ms += static_cast<uint64_t>(time_extract_response.end_and_get());
                    finalize_masked_response();
                    accumulated_comm_response += this->metrics->metrics_["comm_response"];
                    accumulated_comm_final_response += this->metrics->metrics_["comm_final_response"];
                }
            }
        } catch (...) {
            if (!remote_server_ && this->server) {
                this->server->stop_psu_service();
            }
            if (service_started) {
                server->stop_masked_service();
            }
            throw;
        }

        if (service_started) {
            server->stop_masked_service();
        }

        this->metrics->metrics_["comm_request"] = accumulated_comm_request;
        this->metrics->metrics_["comm_response"] = accumulated_comm_response;
        this->metrics->metrics_["comm_final_response"] = accumulated_comm_final_response;
        const uint64_t server_total_ms = this->metrics->metrics_["time_server"];
        this->metrics->metrics_["time_online_comm"] +=
            accumulated_response_ms > server_total_ms
                ? accumulated_response_ms - server_total_ms : 0ULL;
        this->metrics->metrics_["time_extract_response"] += accumulated_extract_ms;
        this->metrics->metrics_["psu_batches"] = batch_count;
        this->metrics->metrics_["client_bins_total"] = total_bins;
        this->metrics->metrics_["hw_benchmark"] = hw_benchmark ? 1 : 0;
        this->metrics->metrics_["plain_modulus_bits"] = params.prime_bitlength;
        finalize_phase_metrics(params);

        bool write_to_file=true;
        if (write_to_file) {
            namespace fs = std::filesystem;
            const char* explicit_result = std::getenv("PSU_RESULTS_FILE");
            fs::path explicit_path = explicit_result && explicit_result[0] != '\0'
                                     ? fs::path(explicit_result)
                                     : fs::path();
            const string results_dir = explicit_path.empty()
                                       ? "results"
                                       : (explicit_path.parent_path().empty()
                                          ? "."
                                          : explicit_path.parent_path().string());
            try {
                fs::create_directories(results_dir);
            } catch (const std::exception &e) {
                cerr << "[WARN] unable to ensure results directory: " << e.what() << endl;
            }

            if (!explicit_path.empty()) {
                cout << "Writing to file " << explicit_path.string() << endl;
                ofstream outFile(explicit_path);
                if (!outFile) {
                    throw std::runtime_error("unable to open result file: " + explicit_path.string());
                }
                for (const pair<string, uint64_t>& metric : this->metrics->metrics_) {
                    outFile << metric.first << "," << metric.second << endl;
                }
                return true;
            }

            uint64_t effective_lambda = this->metrics->metrics_["effective_lambda"];
            uint64_t hw_val = this->metrics->metrics_["hw"];
            uint64_t server_set = this->metrics->metrics_["server_set"];
            string prefix = "effective_" + to_string(effective_lambda) + "_hw_" + to_string(hw_val)
                            + "_server_" + to_string(server_set) + "_";
            static std::unordered_map<string, uint64_t> run_counters;
            auto it = run_counters.find(prefix);
            if (it == run_counters.end()) {
                uint64_t max_existing = 0;
                try {
                    if (fs::exists(results_dir)) {
                        for (const auto &entry : fs::directory_iterator(results_dir)) {
                            if (!entry.is_regular_file()) continue;
                            if (entry.path().extension() != ".csv") continue;
                            string stem = entry.path().stem().string();
                            if (stem.rfind(prefix, 0) != 0) continue;
                            string number_part = stem.substr(prefix.size());
                            if (number_part.empty()) continue;
                            try {
                                uint64_t idx = stoull(number_part);
                                if (idx > max_existing) {
                                    max_existing = idx;
                                }
                            } catch (const std::exception &) {
                                continue;
                            }
                        }
                    }
                } catch (const std::exception &e) {
                    cerr << "[WARN] failed to enumerate existing results: " << e.what() << endl;
                }
                run_counters[prefix] = max_existing;
                it = run_counters.find(prefix);
            }
            it->second += 1;
            uint64_t run_index = it->second;

            string filename_string = explicit_path.empty()
                                     ? results_dir + "/" + prefix + to_string(run_index) + ".csv"
                                     : explicit_path.string();
            cout << "Writing to file " << filename_string << endl;

            ofstream outFile;
            outFile.open(filename_string);
            for (pair<string, uint64_t> metric : this->metrics->metrics_) {
                outFile << metric.first << "," << metric.second << endl;
            }
        }
        return true;
    }

    vector<Plaintext> input;
    std::vector<uint64_t> client_elements;

        Plaintext operand_pt;
        uint64_t bin_count = 1ULL << params.log_poly_modulus_degree;
    vector<vector<uint64_t>> operands_vec(params.ell,vector<uint64_t>(bin_count, 0));
    client_elements.assign(bin_count, 0ULL);
        bcs_client_share_.clear();
        if (params.task == circuitPSU || params.task == PSU) {
            uint64_t permutation_bins = std::min<uint64_t>(bin_count, this->batch_encoder->slot_count());
            std::mt19937_64 perm_rng(std::random_device{}());
            uint64_t permutation_size = permutation_bins;
            if (params.task == circuitPSU) {
                permutation_size = permutation_bins + params.server_set;
            }
            bcs_permutation_ = bcs::generate_permutation(permutation_size, perm_rng);
        } else {
            bcs_permutation_.clear();
        }

    const auto client_encode_start = std::chrono::steady_clock::now();

    // for (uint64_t gamma_prime=0; gamma_prime<params.gamma; gamma_prime++){
        for (uint64_t bin_index=0;bin_index<bin_count;bin_index++){
            uint64_t element = client_get(0, bin_index, params.effective_lambda);
            client_elements[bin_index] = element;
            vector<uint64_t> code = get_cw(element, params.ell, params.hw, true);
            for (int l=0;l<params.ell;l++){
                operands_vec[l][bin_index] = code[l];
            }
        }
        for (int l=0;l<params.ell;l++){
            this->batch_encoder->encode(operands_vec[l], operand_pt);
            input.push_back(operand_pt);
        }
    const auto client_encode_end = std::chrono::steady_clock::now();
    // }

    if (params.task == circuitPSU) {
        auto shares = make_secret_shares(client_elements, kSharePadBits);
        client_sx_ = std::move(shares.first);
        client_sx_prime_ = std::move(shares.second);
    }

    const auto client_encrypt_start = std::chrono::steady_clock::now();
    this->encrypt_and_send(input, _verbose);
    const auto client_encrypt_end = std::chrono::steady_clock::now();
    const uint64_t client_offline_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            client_encode_end - client_encode_start).count())
        + static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            client_encrypt_end - client_encrypt_start).count());
    this->metrics->metrics_["time_offline_comp"] += client_offline_ms;
    this->metrics->metrics_["time_offline_client"] += client_offline_ms;

    bool need_circuit_service = ((params.task == circuitPSU ||
                                  params.task == PSUca_C ||
                                  params.task == PSUca_S) && !remote_server_);
    bool need_masked_service = (params.task == PSU);
    bool need_ca_mid_service = (params.task == PSUca_S);
    if (need_circuit_service) {
        server->start_circuit_service();
    }
    if (need_masked_service && !remote_server_) {
        server->start_masked_service();
    }
    if (need_ca_mid_service && !remote_server_) {
        server->start_psuca_mid_service();
    }
    time_server_latency.start();
    try {
        if (!remote_server_) {
            this->server->start_psu_service(params, static_cast<int>(input.size()), this->metrics, _verbose);
        }
        uint64_t request_ms = 0;
        uint64_t response_ms = 0;
        std::string response = send_psu_request_over_network(this->data_stream.str(), request_ms, response_ms);
        this->data_stream.str(response);
        this->data_stream.clear();
        if (!remote_server_) {
            this->server->stop_psu_service();
        }
        this->metrics->metrics_["time_offline_comm"] += request_ms;
        this->metrics->metrics_["time_online_response_wait"] += response_ms;
    } catch (...) {
        if (!remote_server_ && this->server) {
            this->server->stop_psu_service();
        }
        if (need_circuit_service) {
            server->stop_circuit_service();
        }
        if (need_masked_service && !remote_server_) {
            server->stop_masked_service();
        }
        if (need_ca_mid_service && !remote_server_) {
            server->stop_psuca_mid_service();
        }
        throw;
    }
    uint64_t total_latency_ms = static_cast<uint64_t>(time_server_latency.end_and_get());
    uint64_t server_ms = 0;
    auto it_server = this->metrics->metrics_.find("time_server");
    if (it_server != this->metrics->metrics_.end()) {
        server_ms = it_server->second;
    }
    if (this->metrics->metrics_.find("time_online_comm") == this->metrics->metrics_.end()) {
        this->metrics->metrics_["time_online_comm"] = 0;
    }
    // response_ms includes server computation because the client blocks on
    // recv.  Remove that computation so the canonical communication time
    // contains only the communication-bearing residual.
    const uint64_t request_total_ms = this->metrics->metrics_["time_offline_comm"];
    const uint64_t response_wait_ms = total_latency_ms > request_total_ms
                                    ? total_latency_ms - request_total_ms : 0ULL;
    this->metrics->metrics_["time_online_comm"] +=
        response_wait_ms > server_ms ? response_wait_ms - server_ms : 0ULL;
    int num_cts;
    switch (params.task){
        case PSU: num_cts = 2; break;
        case PSUca_C: num_cts = 1; break;
        case circuitPSU: num_cts = 1; break;
        default: num_cts = 1; break;
    }
    // debug print removed
    time_extract_response.start();
    std::vector<Plaintext> _response_pts = this->load_and_decrypt(num_cts, params, _verbose);
    this->metrics->metrics_["time_extract_response"] = time_extract_response.end_and_get();
    finalize_masked_response();

    if (need_circuit_service) {
        server->stop_circuit_service();
    }

    if (need_masked_service && !remote_server_) {
        server->stop_masked_service();
    }
    if (need_ca_mid_service && !remote_server_) {
        server->stop_psuca_mid_service();
    }

    // Interpret the result here
    // cout << "Example Response: " << _response_pts[0].to_string() << endl;
    (void)_response_pts;

    if (params.task == circuitPSU && params.time_otsss) {
        uint64_t total_perm_share_us = permute_share_time_us_.load(std::memory_order_relaxed);
        this->metrics->metrics_["time_permuteshare_ms"] = total_perm_share_us / 1000ULL;
        this->metrics->metrics_["permute_share_requests"] = permute_share_invocations_.load(std::memory_order_relaxed);
    }
    record_otsss_time_ = false;
    finalize_phase_metrics(params);

    // Printing timings
    // if (_verbose) {
    //     cout << "------------------------ Timing "
    //             "----------------------------------------------"
    //          << endl;
    //     cout << "\tTotal Server    : " << setw(10)
    //          << this->metrics->metrics_["time_server"] << " ms" << endl;

    //     cout << "--------------------- Communication "
    //             "------------------------------------------"
    //          << endl << "\tData Independant: "
    //          << this->metrics->metrics_["comm_relin_keys"] / (float)1000000 << " MB (Relin keys) + "
    //          << this->metrics->metrics_["comm_gal_keys"] / 1000000 << " MB (Gal Keys) + "
    //          << this->metrics->metrics_["comm_pk"] / 1000 << " KB (Public Keys)"
    //          << endl << "\tData Dependant: "
    //          << this->metrics->metrics_["comm_request"] / 1000 << " KB (Query) + "
    //          << this->metrics->metrics_["comm_response"] / 1000 << " KB (Reponse)" << endl
    //          << endl
    //          << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    //             "<<<<<<<<<<<<<<<<<<<<<<"
    //          << endl;
    // }
    bool write_to_file=true;
    if (write_to_file) {
        const string results_dir = "results";
        namespace fs = std::filesystem;
        try {
            fs::create_directories(results_dir);
        } catch (const std::exception &e) {
            cerr << "[WARN] unable to ensure results directory: " << e.what() << endl;
        }

    uint64_t effective_lambda = this->metrics->metrics_["effective_lambda"];
    uint64_t hw_val = this->metrics->metrics_["hw"];
    uint64_t server_set = this->metrics->metrics_["server_set"];
    string prefix = "effective_" + to_string(effective_lambda) + "_hw_" + to_string(hw_val)
                    + "_server_" + to_string(server_set) + "_";
    if (this->metrics->metrics_["task"] == PSUca_S) {
        prefix = "ca_S_" + prefix;
    } else if (this->metrics->metrics_["task"] == PSUca_C) {
        prefix = "ca_R_" + prefix;
    }

        static std::unordered_map<string, uint64_t> run_counters;
        auto it = run_counters.find(prefix);
        if (it == run_counters.end()) {
            uint64_t max_existing = 0;
            try {
                if (fs::exists(results_dir)) {
                    for (const auto &entry : fs::directory_iterator(results_dir)) {
                        if (!entry.is_regular_file()) continue;
                        if (entry.path().extension() != ".csv") continue;
                        string stem = entry.path().stem().string();
                        if (stem.rfind(prefix, 0) != 0) continue;
                        string number_part = stem.substr(prefix.size());
                        if (number_part.empty()) continue;
                        try {
                            uint64_t idx = stoull(number_part);
                            if (idx > max_existing) {
                                max_existing = idx;
                            }
                        } catch (const std::exception &) {
                            continue;
                        }
                    }
                }
            } catch (const std::exception &e) {
                cerr << "[WARN] failed to enumerate existing results: " << e.what() << endl;
            }
            run_counters[prefix] = max_existing;
            it = run_counters.find(prefix);
        }
        it->second += 1;
        uint64_t run_index = it->second;

        string filename_string = results_dir + "/" + prefix + to_string(run_index) + ".csv";
        cout << "Writing to file " << filename_string << endl;

        ofstream outFile;
        outFile.open(filename_string);
        for (pair<string, uint64_t> metric : this->metrics->metrics_) {
            outFile << metric.first << "," << metric.second << endl;
        }
    }
    return true;
}
