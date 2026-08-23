//
// Created by Administrator on 2025/9/23.
//

#include "server.h"
#include "circuit_ot.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <endian.h>
#include <iostream>
#include <fstream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <limits>
#include "config.hpp"
#include "network.hpp"
#include <iostream>

using namespace std;
using namespace seal;

Server::~Server() {
    stop_psu_service();
    stop_masked_service();
    stop_syprime_service();
    stop_psuca_mid_service();
    stop_circuit_service();
}

namespace {
constexpr uint64_t kSharePadBits = 10;
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
}

static string parms_id_to_hex(const parms_id_type &pid) {
    std::ostringstream oss;
    oss << std::hex;
    for (size_t i = 0; i < pid.size(); ++i) {
        oss << pid[i];
        if (i + 1 < pid.size()) oss << ":";
    }
    oss << std::dec;
    return oss.str();
}

void Server::set_client(Client* client) {
    client_ref_ = client;
}

Ciphertext Server::permute_psuca_slots(const Ciphertext& input,
                                       uint64_t active_slots) {
    if (!evaluator || !batch_encoder || !gal_keys_server) {
        throw std::runtime_error("PSUca ciphertext permutation requires evaluator, batch encoder, and Galois keys");
    }

    const uint64_t slot_count = batch_encoder->slot_count();
    if (active_slots != slot_count) {
        throw std::invalid_argument(
            "PSUca BFV slot permutation requires a full batching vector; set client_set to poly_modulus_degree");
    }

    // permutation[dest] = src. Fisher-Yates samples the complete permutation
    // space, rather than only the cyclic subgroup provided by one Galois
    // automorphism.
    std::vector<uint32_t> permutation(active_slots);
    std::iota(permutation.begin(), permutation.end(), 0U);
    std::mt19937_64 rng(std::random_device{}());
    std::shuffle(permutation.begin(), permutation.end(), rng);

    const uint64_t row_size = slot_count / 2;
    std::vector<uint64_t> mask_slots(slot_count, 0ULL);
    Plaintext mask_plain;
    Ciphertext output;
    bool initialized = false;

    for (uint64_t dest = 0; dest < active_slots; ++dest) {
        const uint64_t src = permutation[dest];
        std::fill(mask_slots.begin(), mask_slots.end(), 0ULL);
        mask_slots[src] = 1ULL;
        batch_encoder->encode(mask_slots, mask_plain);

        Ciphertext isolated;
        evaluator->multiply_plain(input, mask_plain, isolated);
        uint64_t src_index = src;
        uint64_t dest_index = dest;
        const bool src_second_row = src_index >= row_size;
        const bool dest_second_row = dest_index >= row_size;
        if (src_second_row) {
            evaluator->rotate_columns_inplace(isolated, *gal_keys_server);
            src_index -= row_size;
        }
        if (dest_second_row) dest_index -= row_size;

        int rotation = static_cast<int>(dest_index) - static_cast<int>(src_index);
        const int modulus = static_cast<int>(row_size);
        rotation %= modulus;
        if (rotation > modulus / 2) rotation -= modulus;
        if (rotation < -modulus / 2) rotation += modulus;
        if (rotation != 0) {
            evaluator->rotate_rows_inplace(isolated, rotation, *gal_keys_server);
        }
        if (dest_second_row) {
            evaluator->rotate_columns_inplace(isolated, *gal_keys_server);
        }

        if (!initialized) {
            output = std::move(isolated);
            initialized = true;
        } else {
            evaluator->add_inplace(output, isolated);
        }
    }
    if (!initialized) throw std::runtime_error("PSUca slot permutation produced no output");
    return output;
}

void Server::start_psu_service(const Params& params, int num_input_cts, Metrics* metrics, bool verbose) {
    psu_params_ = params;
    psu_num_input_cts_ = num_input_cts;
    psu_metrics_ = metrics;
    psu_verbose_ = verbose;

    psu_server_ = std::make_unique<psu::network::SocketServer>(
        net_cfg_.psu_port,
        [this](int conn_fd) { this->handle_psu_connection(conn_fd); }
    );
    psu_server_->start();
}

void Server::stop_psu_service() {
    if (psu_server_) {
        psu_server_->stop();
        psu_server_.reset();
    }
}

void Server::start_masked_service() {
    masked_server_ = std::make_unique<psu::network::SocketServer>(
        net_cfg_.masked_port,
        [this](int conn_fd) { this->handle_masked_connection(conn_fd); }
    );
    masked_server_->start();
}

void Server::stop_masked_service() {
    if (masked_server_) {
        masked_server_->stop();
        masked_server_.reset();
    }
}

void Server::start_syprime_service() {
    if (syprime_thread_.joinable()) {
        return;
    }

    const char* port_env = std::getenv("PSU_SYPRIME_PORT");
    if (port_env && port_env[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(port_env, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            syprime_port_ = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_SYPRIME_PORT='" << port_env
                      << "', fallback to " << syprime_port_ << std::endl;
        }
    }

    syprime_stop_.store(false, std::memory_order_release);
    syprime_thread_ = std::thread(&Server::serve_syprime_requests, this);
}

void Server::stop_syprime_service() {
    syprime_stop_.store(true, std::memory_order_release);

    if (syprime_listen_fd_ != -1) {
        int wake_fd = net::connect_socket(syprime_host_, syprime_port_);
        if (wake_fd >= 0) {
            ::close(wake_fd);
        }
    }

    if (syprime_thread_.joinable()) {
        syprime_thread_.join();
    }
}

void Server::start_psuca_mid_service() {
    if (psuca_mid_thread_.joinable()) {
        return;
    }

    psuca_mid_port_ = net_cfg_.ca_mid_port;
    const char* port_env = std::getenv("PSU_CA_MID_PORT");
    if (port_env && port_env[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(port_env, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            psuca_mid_port_ = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_CA_MID_PORT='" << port_env
                      << "', fallback to " << psuca_mid_port_ << std::endl;
        }
    }

    psuca_mid_stop_.store(false, std::memory_order_release);
    psuca_mid_thread_ = std::thread(&Server::serve_psuca_mid_requests, this);
}

void Server::stop_psuca_mid_service() {
    psuca_mid_stop_.store(true, std::memory_order_release);

    if (psuca_mid_listen_fd_ != -1) {
        int wake_fd = net::connect_socket(psuca_mid_host_, psuca_mid_port_);
        if (wake_fd >= 0) {
            ::close(wake_fd);
        }
    }

    if (psuca_mid_thread_.joinable()) {
        psuca_mid_thread_.join();
    }
}

void Server::serve_psu_requests() {
    psu_listen_fd_ = net::create_listen_socket(psu_port_);
    if (psu_listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to open PSU server listen socket on port "
                  << psu_port_ << std::endl;
        return;
    }

    while (!psu_stop_.load(std::memory_order_acquire)) {
        int conn_fd = net::accept_client(psu_listen_fd_);
        if (conn_fd < 0) {
            if (psu_stop_.load(std::memory_order_acquire)) {
                break;
            }
            int err = errno;
            std::cerr << "[WARN] accept() failed for PSU service: "
                      << std::strerror(err) << std::endl;
            continue;
        }

        if (psu_stop_.load(std::memory_order_acquire)) {
            ::close(conn_fd);
            break;
        }

        try {
            handle_psu_connection(conn_fd);
        } catch (const std::exception& ex) {
            std::cerr << "[ERROR] PSU request handling error: " << ex.what() << std::endl;
        }
        ::close(conn_fd);
    }

    if (psu_listen_fd_ != -1) {
        ::close(psu_listen_fd_);
        psu_listen_fd_ = -1;
    }
}

void Server::serve_masked_requests() {
    masked_listen_fd_ = net::create_listen_socket(masked_port_);
    if (masked_listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to open masked listen socket on port "
                  << masked_port_ << std::endl;
        return;
    }

    while (!masked_stop_.load(std::memory_order_acquire)) {
        int conn_fd = net::accept_client(masked_listen_fd_);
        if (conn_fd < 0) {
            if (masked_stop_.load(std::memory_order_acquire)) {
                break;
            }
            int err = errno;
            std::cerr << "[WARN] accept() failed for masked service: "
                      << std::strerror(err) << std::endl;
            continue;
        }

        if (masked_stop_.load(std::memory_order_acquire)) {
            ::close(conn_fd);
            break;
        }

        try {
            handle_masked_connection(conn_fd);
        } catch (const std::exception& ex) {
            std::cerr << "[ERROR] masked request handling error: " << ex.what() << std::endl;
        }
        ::close(conn_fd);
    }

    if (masked_listen_fd_ != -1) {
        ::close(masked_listen_fd_);
        masked_listen_fd_ = -1;
    }
}

void Server::serve_syprime_requests() {
    syprime_listen_fd_ = net::create_listen_socket(syprime_port_);
    if (syprime_listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to open syprime listen socket on port "
                  << syprime_port_ << std::endl;
        return;
    }

    while (!syprime_stop_.load(std::memory_order_acquire)) {
        int conn_fd = net::accept_client(syprime_listen_fd_);
        if (conn_fd < 0) {
            if (syprime_stop_.load(std::memory_order_acquire)) {
                break;
            }
            int err = errno;
            std::cerr << "[WARN] accept() failed for syprime service: "
                      << std::strerror(err) << std::endl;
            continue;
        }

        if (syprime_stop_.load(std::memory_order_acquire)) {
            ::close(conn_fd);
            break;
        }

        try {
            handle_syprime_connection(conn_fd);
        } catch (const std::exception& ex) {
            std::cerr << "[ERROR] syprime handling error: " << ex.what() << std::endl;
        }
        ::close(conn_fd);
    }

    if (syprime_listen_fd_ != -1) {
        ::close(syprime_listen_fd_);
        syprime_listen_fd_ = -1;
    }
}

void Server::serve_psuca_mid_requests() {
    psuca_mid_listen_fd_ = net::create_listen_socket(psuca_mid_port_);
    if (psuca_mid_listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to open PSUca mid listen socket on port "
                  << psuca_mid_port_ << std::endl;
        return;
    }

    while (!psuca_mid_stop_.load(std::memory_order_acquire)) {
        int conn_fd = net::accept_client(psuca_mid_listen_fd_);
        if (conn_fd < 0) {
            if (psuca_mid_stop_.load(std::memory_order_acquire)) {
                break;
            }
            int err = errno;
            std::cerr << "[WARN] accept() failed for PSUca mid service: "
                      << std::strerror(err) << std::endl;
            continue;
        }

        if (psuca_mid_stop_.load(std::memory_order_acquire)) {
            ::close(conn_fd);
            break;
        }

        try {
            handle_psuca_mid_connection(conn_fd);
        } catch (const std::exception& ex) {
            std::cerr << "[ERROR] PSUca mid handling error: " << ex.what() << std::endl;
        }
        ::close(conn_fd);
    }

    if (psuca_mid_listen_fd_ != -1) {
        ::close(psuca_mid_listen_fd_);
        psuca_mid_listen_fd_ = -1;
    }
}

void Server::handle_masked_connection(int conn_fd) {
    uint64_t len_be = 0;
    if (!net::recv_all(conn_fd, &len_be, sizeof(len_be))) {
        std::cerr << "[WARN] Failed to read masked payload length" << std::endl;
        return;
    }
    uint64_t len = be64toh(len_be);

    std::string payload(len, '\0');
    if (len > 0 && !net::recv_all(conn_fd, payload.data(), payload.size())) {
        std::cerr << "[WARN] Failed to read masked payload" << std::endl;
        return;
    }

    std::stringstream stream;
    if (!payload.empty()) {
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        stream.seekg(0, std::ios::beg);
    }
    receive_and_decrypt_masked(stream);

    uint64_t resp_len_be = 0;
    if (!net::send_all(conn_fd, &resp_len_be, sizeof(resp_len_be))) {
        std::cerr << "[WARN] Failed to send masked ack" << std::endl;
    }
}

void Server::handle_syprime_connection(int conn_fd) {
    uint64_t count = server_sy_prime_.size();
    uint64_t count_be = htobe64(count);
    auto send_start = std::chrono::steady_clock::now();
    if (!net::send_all(conn_fd, &count_be, sizeof(count_be))) {
        throw std::runtime_error("failed to send syprime count");
    }
    if (count > 0) {
        std::vector<uint64_t> payload(count);
        for (uint64_t i = 0; i < count; ++i) {
            payload[i] = htobe64(server_sy_prime_[i]);
        }
        size_t bytes = payload.size() * sizeof(uint64_t);
        if (!net::send_all(conn_fd, payload.data(), bytes)) {
            throw std::runtime_error("failed to send syprime payload");
        }
    }
    auto send_end = std::chrono::steady_clock::now();
    uint64_t send_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(send_end - send_start).count());
    if (metrics) {
        metrics->metrics_["time_offline_comm"] += send_ms;
    }
}

void Server::handle_psuca_mid_connection(int conn_fd) {
    uint64_t ca_mid_be = 0;
    if (!net::recv_all(conn_fd, &ca_mid_be, sizeof(ca_mid_be))) {
        std::cerr << "[WARN] Failed to read PSUca mid value" << std::endl;
        return;
    }
    int64_t ca_mid = static_cast<int64_t>(be64toh(ca_mid_be));
    uint64_t server_set = 0;
    uint64_t client_bins = 0;
    {
        std::lock_guard<std::mutex> lock(psu_mutex_);
        server_set = psu_params_.server_set;
        client_bins = psu_params_.active_bins > 0
                    ? psu_params_.active_bins
                    : (1ULL << psu_params_.log_poly_modulus_degree);
    }
    finalize_psuca_s(ca_mid, server_set, client_bins);

    uint64_t ack = 0;
    if (!net::send_all(conn_fd, &ack, sizeof(ack))) {
        std::cerr << "[WARN] Failed to send PSUca mid ack" << std::endl;
    }
}

void Server::handle_circuit_connection(int conn_fd) {
    uint64_t request[5]{};
    if (!net::recv_all(conn_fd, request, sizeof(request))) {
        throw std::runtime_error("failed to receive circuit finalization request");
    }
    if (be64toh(request[0]) == kPsucaRefreshMagic) {
        const uint64_t refresh_size = be64toh(request[1]);
        const Task task = static_cast<Task>(be64toh(request[2]));
        if ((task != PSUca_C && task != PSUca_S) || refresh_size == 0 ||
            refresh_size > (1ULL << 30) ||
            psuca_refresh_mask_.size() != batch_encoder->slot_count()) {
            throw std::runtime_error("PSUca refresh state/request mismatch");
        }

        std::string refresh_bytes(refresh_size, '\0');
        if (!net::recv_all(conn_fd, refresh_bytes.data(), refresh_bytes.size())) {
            throw std::runtime_error("failed to receive refreshed PSUca ciphertext");
        }
        std::stringstream refresh_stream(refresh_bytes);
        Ciphertext refreshed;
        refreshed.load(*context, refresh_stream);

        const auto compute_start = std::chrono::steady_clock::now();
        Plaintext refresh_mask_plain;
        batch_encoder->encode(psuca_refresh_mask_, refresh_mask_plain);
        evaluator->sub_plain_inplace(refreshed, refresh_mask_plain);

        const uint64_t slot_count = batch_encoder->slot_count();
        const uint64_t active_slots = psu_params_.active_bins > 0
                                    ? psu_params_.active_bins : slot_count;
        const uint64_t plain_mod = enc_params->plain_modulus().value();
        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(0ULL, plain_mod - 1ULL);
        std::vector<uint64_t> final_mask(slot_count, 0ULL);
        uint64_t shf_sum = 0;
        for (uint64_t i = 0; i < active_slots; ++i) {
            final_mask[i] = dist(rng);
            shf_sum = static_cast<uint64_t>(
                (static_cast<unsigned __int128>(shf_sum) + final_mask[i]) % plain_mod);
        }
        Plaintext final_mask_plain;
        batch_encoder->encode(final_mask, final_mask_plain);
        evaluator->add_plain_inplace(refreshed, final_mask_plain);

        const auto permute_start = std::chrono::steady_clock::now();
        Ciphertext shuffled = permute_psuca_slots(refreshed, active_slots);
        const auto permute_end = std::chrono::steady_clock::now();

        psuca_refresh_mask_.clear();
        if (task == PSUca_S) {
            psuca_shf_sum_ = static_cast<int64_t>(shf_sum);
            psuca_plain_mod_ = plain_mod;
            psuca_scale_inv_ = build_eeq_params(psu_params_.hw, plain_mod).coefficients.back();
            psuca_shf_valid_ = true;
        }

        std::stringstream response_stream;
        if (task == PSUca_C) {
            const uint64_t mask_be = htobe64(shf_sum);
            response_stream.write(reinterpret_cast<const char*>(&mask_be), sizeof(mask_be));
        }
        shuffled.save(response_stream);
        const std::string response_bytes = response_stream.str();
        const uint64_t response_size_be = htobe64(response_bytes.size());
        const auto compute_end = std::chrono::steady_clock::now();
        const uint64_t compute_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                compute_end - compute_start).count());
        const uint64_t compute_ms_be = htobe64(compute_ms);
        if (!net::send_all(conn_fd, &response_size_be, sizeof(response_size_be)) ||
            !net::send_all(conn_fd, &compute_ms_be, sizeof(compute_ms_be)) ||
            !net::send_all(conn_fd, response_bytes.data(), response_bytes.size())) {
            throw std::runtime_error("failed to send shuffled PSUca ciphertext");
        }

        if (metrics) {
            const uint64_t permute_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    permute_end - permute_start).count());
            metrics->metrics_["time_online_comp"] += compute_ms;
            metrics->metrics_["time_online_server"] += compute_ms;
            metrics->metrics_["time_psuca_permutation"] += permute_ms;
        }
        return;
    }
    const uint64_t count = be64toh(request[0]);
    const uint64_t shuffle_count = be64toh(request[1]);
    const uint16_t ot_port = static_cast<uint16_t>(be64toh(request[2]));
    const uint16_t osn_port = static_cast<uint16_t>(be64toh(request[3]));
    const uint64_t refresh_size = be64toh(request[4]);
    if (count == 0 || circuit_refresh_mask_.size() != batch_encoder->slot_count() ||
        server_sy_.empty() || refresh_size == 0 || refresh_size > (1ULL << 30) ||
        shuffle_count < count + server_sy_.size()) {
        throw std::runtime_error("circuit finalization state/count mismatch");
    }

    std::string refresh_bytes(refresh_size, '\0');
    if (!net::recv_all(conn_fd, refresh_bytes.data(), refresh_bytes.size())) {
        throw std::runtime_error("failed to receive refreshed circuit ciphertext");
    }
    std::stringstream refresh_stream(refresh_bytes);
    Ciphertext refreshed_masked;
    refreshed_masked.load(*context, refresh_stream);

    auto refresh_start = std::chrono::steady_clock::now();
    Plaintext refresh_mask_plain;
    batch_encoder->encode(circuit_refresh_mask_, refresh_mask_plain);
    evaluator->sub_plain_inplace(refreshed_masked, refresh_mask_plain);

    const uint64_t plain_mod = enc_params->plain_modulus().value();
    const uint64_t inv_factorial =
        build_eeq_params(psu_params_.hw, plain_mod).coefficients.back();
    std::vector<uint64_t> inv_slots(batch_encoder->slot_count(), inv_factorial);
    Plaintext inv_plain;
    batch_encoder->encode(inv_slots, inv_plain);
    evaluator->multiply_plain_inplace(refreshed_masked, inv_plain);

    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> bit_dist(0ULL, 1ULL);
    server_shs_bits_.assign(count, 0ULL);
    std::vector<uint64_t> shs_slots(batch_encoder->slot_count(), 0ULL);
    std::vector<uint64_t> twice_shs_slots(batch_encoder->slot_count(), 0ULL);
    for (uint64_t i = 0; i < count; ++i) {
        server_shs_bits_[i] = bit_dist(rng);
        shs_slots[i] = server_shs_bits_[i];
        twice_shs_slots[i] = 2ULL * server_shs_bits_[i];
    }
    Plaintext shs_plain;
    Plaintext twice_shs_plain;
    batch_encoder->encode(shs_slots, shs_plain);
    batch_encoder->encode(twice_shs_slots, twice_shs_plain);
    Ciphertext a_plus_b;
    Ciphertext a_mul_b;
    Ciphertext client_share;
    evaluator->add_plain(refreshed_masked, shs_plain, a_plus_b);
    evaluator->multiply_plain(refreshed_masked, twice_shs_plain, a_mul_b);
    evaluator->sub(a_plus_b, a_mul_b, client_share);

    std::stringstream share_stream;
    client_share.save(share_stream);
    const std::string share_bytes = share_stream.str();
    uint64_t share_size_be = htobe64(share_bytes.size());
    if (!net::send_all(conn_fd, &share_size_be, sizeof(share_size_be)) ||
        !net::send_all(conn_fd, share_bytes.data(), share_bytes.size())) {
        throw std::runtime_error("failed to send refreshed circuit client share");
    }
    circuit_refresh_mask_.clear();
    auto refresh_end = std::chrono::steady_clock::now();
    if (metrics) {
        const uint64_t refresh_server_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(refresh_end - refresh_start).count());
        metrics->metrics_["time_online_comp"] += refresh_server_ms;
        metrics->metrics_["time_online_server"] += refresh_server_ms;
        metrics->metrics_["time_circuit_refresh_server"] += refresh_server_ms;
    }

    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    if (::getpeername(conn_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len) != 0) {
        throw std::runtime_error("failed to identify circuit client endpoint");
    }
    char peer_ip[INET_ADDRSTRLEN]{};
    if (!::inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip))) {
        throw std::runtime_error("failed to format circuit client address");
    }

    const std::string ot_endpoint = std::string(peer_ip) + ":" + std::to_string(ot_port);
    const std::string osn_endpoint = std::string(peer_ip) + ":" + std::to_string(osn_port);
    auto ot = circuit::receive_x_shares(server_shs_bits_, ot_endpoint);
    if (ot.values.size() != count) {
        throw std::runtime_error("circuit OT output size mismatch");
    }

    std::vector<uint64_t> server_inputs;
    server_inputs.reserve(shuffle_count);
    server_inputs.insert(server_inputs.end(), ot.values.begin(), ot.values.end());
    server_inputs.insert(server_inputs.end(), server_sy_.begin(), server_sy_.end());
    server_inputs.resize(shuffle_count, 0ULL);
    circuit_pre_shuffle_share_ = server_inputs;
    auto osn = bcs::permute_share_receiver(server_inputs, osn_endpoint, 1);
    circuit_output_share_ = std::move(osn.share);
    save_circuit_share_if_requested("FEUPSU_SERVER_SHARE_FILE", circuit_output_share_);

    if (metrics) {
        metrics->metrics_["time_online_comp"] += ot.compute_ms + osn.compute_ms;
        metrics->metrics_["time_online_server"] += ot.compute_ms + osn.compute_ms;
    }

    uint64_t response[3] = {
        htobe64(circuit_output_share_.size()),
        htobe64(ot.comm_bytes), htobe64(osn.comm_bytes)
    };
    if (!net::send_all(conn_fd, response, sizeof(response))) {
        throw std::runtime_error("failed to send circuit finalization response");
    }
}

void Server::handle_psu_connection(int conn_fd) {
    std::vector<uint8_t> payload_bytes;
    if (!psu::network::SocketUtils::recv_message(conn_fd, payload_bytes)) {
        return;
    }

    std::vector<uint8_t> response(sizeof(uint32_t), 0);
    bool setup_only = false;
    try {
        std::lock_guard<std::mutex> lock(psu_mutex_);
        constexpr uint32_t kMagic = 0x46505531U; // "FPU1"
        constexpr uint32_t kWireVersion = 2;
        constexpr uint32_t kSetupMessage = 1;
        constexpr uint32_t kBatchMessage = 2;
        size_t cursor = 0;
        auto read_u32 = [&]() -> uint32_t {
            if (cursor + sizeof(uint32_t) > payload_bytes.size()) {
                throw std::runtime_error("truncated request header");
            }
            uint32_t be = 0;
            std::memcpy(&be, payload_bytes.data() + cursor, sizeof(be));
            cursor += sizeof(be);
            return ntohl(be);
        };
        auto read_u64 = [&]() -> uint64_t {
            if (cursor + sizeof(uint64_t) > payload_bytes.size()) {
                throw std::runtime_error("truncated request header");
            }
            uint64_t be = 0;
            std::memcpy(&be, payload_bytes.data() + cursor, sizeof(be));
            cursor += sizeof(be);
            return be64toh(be);
        };

        Params request_params = psu_params_;
        int request_num_cts = psu_num_input_cts_;
        Metrics* request_metrics = psu_metrics_ ? psu_metrics_ : &service_metrics_;

        bool standalone_request = payload_bytes.size() >= sizeof(uint32_t);
        if (standalone_request) {
            uint32_t magic_be = 0;
            std::memcpy(&magic_be, payload_bytes.data(), sizeof(magic_be));
            standalone_request = ntohl(magic_be) == kMagic;
        }

        if (standalone_request) {
            if (read_u32() != kMagic) {
                throw std::runtime_error("invalid standalone wire magic");
            }
            const uint32_t wire_version = read_u32();
            uint64_t request_session_id = 0;
            if (wire_version == kWireVersion) {
                const uint32_t message_type = read_u32();
                request_session_id = read_u64();
                if (request_session_id == 0) {
                    throw std::runtime_error("invalid standalone setup session id");
                }
                if (message_type == kSetupMessage) {
                    const uint64_t setup_size = read_u64();
                    if (setup_size == 0 || setup_size != payload_bytes.size() - cursor) {
                        throw std::runtime_error("invalid standalone SEAL setup length");
                    }
                    std::string setup(
                        reinterpret_cast<const char*>(payload_bytes.data() + cursor),
                        static_cast<size_t>(setup_size));
                    std::stringstream setup_stream(setup);
                    const uint64_t keygen_ms = load_parameters_and_keys(
                        setup_stream, false, psu_verbose_);
                    setup_session_id_ = request_session_id;
                    setup_session_valid_ = true;
                    service_metrics_.metrics_.clear();
                    service_metrics_.metrics_["time_setup_server_keygen"] = keygen_ms;
                    request_metrics = &service_metrics_;
                    psu_metrics_ = request_metrics;
                    const uint64_t keygen_be = htobe64(keygen_ms);
                    const auto* p = reinterpret_cast<const uint8_t*>(&keygen_be);
                    response.insert(response.end(), p, p + sizeof(keygen_be));
                    setup_only = true;
                } else if (message_type != kBatchMessage) {
                    throw std::runtime_error("unsupported standalone message type");
                } else if (!setup_session_valid_ || request_session_id != setup_session_id_) {
                    throw std::runtime_error("unknown or expired standalone setup session");
                }
            } else if (wire_version != 1) {
                throw std::runtime_error("unsupported wire protocol version");
            }

            if (!setup_only) {
            uint32_t task_value = read_u32();
            request_num_cts = static_cast<int>(read_u32());
            uint64_t server_set = read_u64();
            uint64_t effective_lambda = read_u64();
            uint64_t hw = read_u64();
            uint64_t client_set = read_u64();
            uint64_t active_bins = read_u64();
            uint64_t client_bin_offset = read_u64();
            uint64_t setup_size = 0;
            if (wire_version == 1) {
                setup_size = read_u64();
            }

            if (task_value > static_cast<uint32_t>(circuitPSU)) {
                throw std::runtime_error("unsupported standalone task");
            }
            request_params = Params(static_cast<Task>(task_value), server_set,
                                    effective_lambda, hw, client_set);
            request_params.active_bins = active_bins;
            request_params.client_bin_offset = client_bin_offset;
            if (request_num_cts != static_cast<int>(request_params.ell)) {
                throw std::runtime_error("ciphertext count does not match derived code length");
            }
            if (wire_version == 1) {
                if (setup_size == 0 || setup_size > payload_bytes.size() - cursor) {
                    throw std::runtime_error("invalid SEAL setup length");
                }
                std::string setup(reinterpret_cast<const char*>(payload_bytes.data() + cursor),
                                  static_cast<size_t>(setup_size));
                cursor += static_cast<size_t>(setup_size);
                std::stringstream setup_stream(setup);
                load_parameters_and_keys(setup_stream, false, psu_verbose_);
                setup_session_valid_ = false;
            }

            service_metrics_.metrics_.clear();
            request_metrics = &service_metrics_;
            psu_params_ = request_params;
            psu_num_input_cts_ = request_num_cts;
            psu_metrics_ = request_metrics;
            }
        }

        if (!setup_only && (!context || !batch_encoder || !evaluator || !server_encryptor)) {
            throw std::runtime_error("server has no SEAL context; use a standalone setup request");
        }

        if (!setup_only) {
            std::string payload_str(reinterpret_cast<const char*>(payload_bytes.data() + cursor),
                                    payload_bytes.size() - cursor);
            std::stringstream data_stream(payload_str);
            do_server_computation(data_stream, request_num_cts, request_params,
                                  request_metrics, psu_verbose_);

            // do_server_computation clears the input stream and serializes its result
            // back into that same stream.
            std::string result_str = data_stream.str();
            response.insert(response.end(), result_str.begin(), result_str.end());
        }
    } catch (const std::exception& ex) {
        uint32_t status_be = htonl(1);
        std::memcpy(response.data(), &status_be, sizeof(status_be));
        response.insert(response.end(), ex.what(), ex.what() + std::strlen(ex.what()));
        std::cerr << "[ERROR] PSU request failed: " << ex.what() << std::endl;
    }
    const auto response_send_start = std::chrono::steady_clock::now();
    psu::network::SocketUtils::send_message(conn_fd, response);
    const auto response_send_end = std::chrono::steady_clock::now();
    if (!setup_only && psu_metrics_) {
        const uint64_t send_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                response_send_end - response_send_start).count());
        psu_metrics_->metrics_["time_online_primary_send"] += send_ms;
    }
}

void Server::start_circuit_service() {
    if (circuit_server_) return;
    circuit_server_ = std::make_unique<psu::network::SocketServer>(
        net_cfg_.circuit_control_port,
        [this](int conn_fd) { this->handle_circuit_connection(conn_fd); });
    circuit_server_->start();
}

void Server::stop_circuit_service() {
    if (circuit_server_) {
        circuit_server_->stop();
        circuit_server_.reset();
    }
}

Plaintext Server::sample_cardinality_mask(uint64_t active_slots, uint64_t server_set) {
    vector<uint64_t> slots(this->batch_encoder->slot_count(), 0ULL);
    if (active_slots == 0 || server_set == 0) {
        Plaintext pt;
        this->batch_encoder->encode(slots, pt);
        return pt;
    }

    uint64_t usable_slots = min<uint64_t>(active_slots, this->batch_encoder->slot_count());
    vector<uint64_t> composition(usable_slots, 0ULL);

    if (usable_slots == 1) {
        composition[0] = server_set;
    } else {
        std::mt19937_64 gen(std::random_device{}());
        std::vector<uint64_t> cuts(usable_slots - 1, 0ULL);
        std::uniform_int_distribution<uint64_t> dist(0, server_set);
        for (auto &cut : cuts) {
            cut = dist(gen);
        }
        std::sort(cuts.begin(), cuts.end());
        uint64_t prev = 0ULL;
        for (size_t idx = 0; idx < cuts.size(); ++idx) {
            uint64_t current = cuts[idx];
            composition[idx] = current - prev;
            prev = current;
        }
        composition.back() = server_set - prev;
        std::shuffle(composition.begin(), composition.end(), gen);
    }

    for (uint64_t i = 0; i < usable_slots; ++i) {
        slots[i] = composition[i];
    }

    Plaintext pt;
    this->batch_encoder->encode(slots, pt);
    return pt;
}

vector<vector<uint64_t>> Server::receive_and_decrypt_masked(stringstream& data_stream) {
    Timer decrypt_timer;
    uint64_t K, D, m;
    data_stream.read(reinterpret_cast<char*>(&K), sizeof(K));
    data_stream.read(reinterpret_cast<char*>(&D), sizeof(D));
    data_stream.read(reinterpret_cast<char*>(&m), sizeof(m));

    vector<vector<uint64_t>> all_elements(K, vector<uint64_t>(m, 0));
    Decryptor decryptor(*context, this->server_secret_key);
    decrypt_timer.start();
    for (uint64_t k = 0; k < K; ++k) {
        vector<vector<uint64_t>> digits(m, vector<uint64_t>(D, 0));
        for (uint64_t d = 0; d < D; ++d) {
            Ciphertext ct; ct.load(*context, data_stream);
            if (ct.is_transparent()) {
                throw std::runtime_error("received a transparent PSU output ciphertext");
            }
            Plaintext pt;
            vector<uint64_t> slot_vals;
            decryptor.decrypt(ct, pt);
            this->batch_encoder->decode(pt, slot_vals);
            for (size_t pos = 0; pos < m && pos < slot_vals.size(); ++pos) {
                digits[pos][d] = slot_vals[pos];
            }
        }

        uint64_t p = this->enc_params->plain_modulus().value();
        for (size_t i = 0; i < m; ++i) {
            uint64_t val = 0;
            uint64_t base = 1;
            for (uint64_t d = 0; d < D; ++d) {
                val += digits[i][d] * base;
                base *= p;
            }
            all_elements[k][i] = val;
        }
    }

    // cout << "[SERVER] Reconstructed elements from client response (K=" << K
    //      << ", bins=" << m << ", digits=" << D << ")" << endl;
    // size_t preview_bins = min<uint64_t>(m, 8);
    // for (uint64_t k = 0; k < K; ++k) {
    //     cout << "  group " << k << ":";
    //     for (size_t i = 0; i < preview_bins; ++i) {
    //         cout << ' ' << all_elements[k][i];
    //     }
    //     if (preview_bins < m) cout << " ...";
    //     cout << endl;
    // }
    decrypt_timer.end();
    if (this->metrics) {
        const uint64_t decrypt_ms = static_cast<uint64_t>(decrypt_timer.get_time_in_milliseconds());
        this->metrics->metrics_["time_server_extract"] += decrypt_ms;
        this->metrics->metrics_["time_online_comp"] += decrypt_ms;
        this->metrics->metrics_["time_online_server"] += decrypt_ms;
    }
    return all_elements;
}

uint64_t Server::load_parameters_and_keys(stringstream& params_stream, bool debug_mode, bool _verbose)
{
    this->enc_params = std::make_unique<EncryptionParameters>();
    this->enc_params->load(params_stream);

    this->context = std::make_shared<SEALContext>(*enc_params);

    this->rlk_keys_server = std::make_unique<RelinKeys>();
    this->gal_keys_server = std::make_unique<GaloisKeys>();
    this->public_key = std::make_unique<PublicKey>();
    this->rlk_keys_server->load(*context, params_stream);
    this->gal_keys_server->load(*context, params_stream);
    this->public_key->load(*context, params_stream);

    this->batch_encoder = std::make_unique<BatchEncoder>(*context);
    this->encryptor = std::make_unique<Encryptor>(*context, *public_key);
    this->evaluator = std::make_unique<Evaluator>(*context);

    // if (debug_mode){
    //     SecretKey secret_key;
    //     secret_key.load(*context, params_stream);
        // this->noise_calculator = new Decryptor(*context, secret_key);
        // try {
        //     cout << "[DEBUG] noise_calculator initialized; context parms_id=" << parms_id_to_hex(this->context->key_context_data()->parms_id()) << endl;
        // } catch(...){}
    // }
    if (debug_mode){
        SecretKey secret_key;
        secret_key.load(*context, params_stream);
        this->noise_calculator = std::make_unique<Decryptor>(*context, secret_key);
    }

    // Generate the server key pair once per setup session.  All batches in
    // that session reuse it, just as they reuse the loaded client evaluation
    // keys and SEAL context.
    const auto keygen_start = std::chrono::steady_clock::now();
    KeyGenerator server_keygen(*context);
    this->server_secret_key = server_keygen.secret_key();
    server_keygen.create_public_key(this->server_public_key);
    this->server_encryptor = std::make_unique<Encryptor>(*context, this->server_public_key);
    const auto keygen_end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        keygen_end - keygen_start).count());
}

vector<Ciphertext> Server::load_inputs(stringstream& data_stream, int num_input_cts){
    vector<Ciphertext> inputs;
    Ciphertext __ct_temp;
    for (int i=0;i<num_input_cts;i++){
        __ct_temp.load(*context, data_stream);
        inputs.push_back(__ct_temp);
    }
    data_stream.str("");
    return inputs;
}

void Server::send_results(vector<Ciphertext>& results, stringstream& data_stream){
    for (int i=0;i<results.size();i++){
        results[i].save(data_stream);
    }
}

uint64_t Server::server_get(uint64_t mu_prime, uint64_t bin_index,
                            uint64_t effective_lambda, uint64_t bin_count){
    // Deterministic stand-in for a binned server table: row 0 contains the
    // first bin_count elements, row 1 the next bin_count elements, etc.  The
    // effective domain can be smaller than mu*bin_count; wrapped padding must
    // not create a second match in the same bin, otherwise indicators_sum is
    // no longer a bit and cardinality is over-counted.
    const uint64_t stride = bin_count == 0 ? 1 : bin_count;
    const uint64_t raw = mu_prime * stride + bin_index;
    if (effective_lambda >= 64) return raw;
    const uint64_t domain = 1ULL << effective_lambda;
    uint64_t value = raw % domain;
    if (mu_prime > 0 && value == (bin_index % domain)) {
        value = (value + 1) % domain;
    }
    return value;
}

void Server::prepare_secret_shares(const Params& params) {
    std::vector<uint64_t> values(params.server_set, 0ULL);
    for (uint64_t i = 0; i < params.server_set; ++i) {
        values[i] = params.effective_lambda >= 64
                  ? i
                  : i % (1ULL << params.effective_lambda);
    }

    auto start = std::chrono::steady_clock::now();
    auto shares = make_secret_shares(values, kSharePadBits);
    auto end = std::chrono::steady_clock::now();
    uint64_t elapsed_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

    server_sy_ = std::move(shares.first);
    server_sy_prime_ = std::move(shares.second);

    (void)elapsed_ms;
}

std::vector<uint64_t> Server::request_permute_share_over_network(
    const std::vector<uint64_t>& rnd,
    const std::string& host,
    uint16_t port,
    uint64_t& request_bytes,
    uint64_t& response_bytes,
    uint64_t& remote_compute_us) {

    int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) {
        throw std::runtime_error("failed to connect to permute-share service at " + host + ":" + std::to_string(port));
    }

    request_bytes = 0;
    response_bytes = 0;
    remote_compute_us = 0;

    uint32_t header[2] = {htonl(1), 0};
    if (!net::send_all(sock_fd, header, sizeof(header))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send permute-share request header");
    }
    request_bytes += sizeof(header);

    uint64_t count = rnd.size();
    uint64_t count_be = htobe64(count);
    if (!net::send_all(sock_fd, &count_be, sizeof(count_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send permute-share request count");
    }
    request_bytes += sizeof(count_be);

    if (!rnd.empty()) {
        std::vector<uint64_t> payload(count);
        for (uint64_t i = 0; i < count; ++i) {
            payload[i] = htobe64(rnd[i]);
        }
        size_t bytes = payload.size() * sizeof(uint64_t);
        if (!net::send_all(sock_fd, payload.data(), bytes)) {
            ::close(sock_fd);
            throw std::runtime_error("failed to send permute-share request payload");
        }
        request_bytes += static_cast<uint64_t>(bytes);
    }

    uint32_t resp_header[2];
    if (!net::recv_all(sock_fd, resp_header, sizeof(resp_header))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to read permute-share response header");
    }
    response_bytes += sizeof(resp_header);

    uint32_t msg_type = ntohl(resp_header[0]);
    if (msg_type != 2) {
        ::close(sock_fd);
        throw std::runtime_error("unexpected permute-share response type: " + std::to_string(msg_type));
    }

    uint64_t compute_us_be = 0;
    if (!net::recv_all(sock_fd, &compute_us_be, sizeof(compute_us_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to read permute-share compute time");
    }
    response_bytes += sizeof(compute_us_be);
    remote_compute_us = be64toh(compute_us_be);

    uint64_t share_count_be = 0;
    if (!net::recv_all(sock_fd, &share_count_be, sizeof(share_count_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to read permute-share payload length");
    }
    response_bytes += sizeof(share_count_be);
    uint64_t share_count = be64toh(share_count_be);

    std::vector<uint64_t> server_share(share_count);
    if (share_count > 0) {
        std::vector<uint64_t> payload(share_count);
        size_t bytes = payload.size() * sizeof(uint64_t);
        if (!net::recv_all(sock_fd, payload.data(), bytes)) {
            ::close(sock_fd);
            throw std::runtime_error("failed to read permute-share payload data");
        }
        response_bytes += static_cast<uint64_t>(bytes);
        for (uint64_t i = 0; i < share_count; ++i) {
            server_share[i] = be64toh(payload[i]);
        }
    }

    ::close(sock_fd);
    return server_share;
}

void Server::do_server_computation(stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool _verbose){
    Timer online_time;
    Timer server_time;
    vector<Ciphertext> inputs = load_inputs(data_stream, num_input_cts);
    vector<Ciphertext> results;

    online_time.start();
    server_time.start();
    this->metrics = metrics;

    uint64_t bins = params.active_bins > 0
                    ? params.active_bins
                    : (1ULL << params.log_poly_modulus_degree);
    uint64_t slot_count = this->batch_encoder->slot_count();
    if (bins > slot_count) {
        throw std::invalid_argument("active bins exceed BFV slot_count");
    }
    uint64_t mu = params.mu;
    uint64_t ell = params.ell;
    uint64_t hw = params.hw;
    uint64_t effective_lambda = params.effective_lambda;
    // uint64_t label_ct_size=params.label_ct_size;
    // assert( gamma*ell == inputs.size() );

    auto online_comp_start = std::chrono::steady_clock::now();
    std::vector<uint64_t> server_encode_us_by_thread(
        static_cast<std::size_t>(std::max(1, omp_get_max_threads())), 0ULL);
    // cout << "[TRACE][server] starting main loop with mu=" << mu << endl;
    vector<Ciphertext> indicators(mu);
    Ciphertext indicators_sum;

    EEQParams eeq_params = build_eeq_params(hw, this->enc_params->plain_modulus().value());
    vector<uint64_t> eeq_constant_slots(this->batch_encoder->slot_count());
    vector<Plaintext> eeq_root_plain(hw);
    for (uint64_t root = 0; root < hw; ++root) {
        std::fill(eeq_constant_slots.begin(), eeq_constant_slots.end(), root);
        this->batch_encoder->encode(eeq_constant_slots, eeq_root_plain[root]);
    }
    // Plaintext labels_pt;
    // this->batch_encoder->encode(vector<uint64_t>(this->batch_encoder->slot_count(), 3), labels_pt);
    Ciphertext zero_pt;
    encryptor->encrypt_zero(zero_pt);

    #pragma omp parallel for
    for (int i=0;i<mu;i++){
        const int worker = omp_get_thread_num();
        uint64_t local_encode_us = 0;
        // if (i % 50 == 0) {
        //     #pragma omp critical
        //     {
        //         cout << "[TRACE][server] processing mu index " << i << "/" << mu << endl;
        //     }
        // }
        // for (int j=0;j<gamma;j++){
            Plaintext operand_pt;
            const auto encode_values_start = std::chrono::steady_clock::now();
            vector<vector<uint64_t>> operands_vec(ell,vector<uint64_t>(bins, 0));

            for (uint64_t bin_index = 0; bin_index < bins; ++bin_index){
                uint64_t global_bin = params.client_bin_offset + bin_index;
                uint64_t element = server_get(i, global_bin, effective_lambda, bins);
                vector<uint64_t> code = get_cw(element, ell, hw, true);
                for (int l=0;l<ell;l++){
                    operands_vec[l][bin_index] = code[l];
                }
            }
            const auto encode_values_end = std::chrono::steady_clock::now();
            local_encode_us += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    encode_values_end - encode_values_start).count());

            vector<Ciphertext> _temp(ell);
            for (int k=0;k<ell;k++){
                if (accumulate(operands_vec[k].begin(), operands_vec[k].end(), 0) == 0){
                    _temp[k] = zero_pt;
                } else {
                    const auto batch_encode_start = std::chrono::steady_clock::now();
                    this->batch_encoder->encode(operands_vec[k], operand_pt);
                    const auto batch_encode_end = std::chrono::steady_clock::now();
                    local_encode_us += static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            batch_encode_end - batch_encode_start).count());
                    this->evaluator->multiply_plain(inputs[k], operand_pt, _temp[k]);
                    // debug prints removed
                }
            }

            Ciphertext _ct;
            this->evaluator->add_many(_temp, _ct);

            // 4. Evaluate prod_{j=0}^{hw-1}(dot-j) as a balanced tree.  Tasks
            // that need per-slot bits normalize by 1/hw! below; cardinality
            // removes the common scale after decryption.
            vector<Ciphertext> level;
            level.reserve(hw);
            for (uint64_t root = 0; root < hw; ++root) {
                Ciphertext factor(_ct);
                if (root != 0) {
                    this->evaluator->sub_plain_inplace(factor, eeq_root_plain[root]);
                }
                level.push_back(std::move(factor));
            }
            while (level.size() > 1) {
                vector<Ciphertext> next;
                next.reserve((level.size() + 1) / 2);
                for (size_t idx = 0; idx < level.size(); idx += 2) {
                    if (idx + 1 == level.size()) {
                        next.push_back(std::move(level[idx]));
                    } else {
                        Ciphertext product;
                        this->evaluator->multiply(level[idx], level[idx + 1], product);
                        this->evaluator->relinearize_inplace(product, *rlk_keys_server);
                        next.push_back(std::move(product));
                    }
                }
                level = std::move(next);
            }
            // Keep the falling-factorial scale hw! for every task. PSU and
            // circuitPSU remove it only after the client decrypts its masked
            // share; normalizing this deep ciphertext exhausts BFV noise.
            indicators[i] = std::move(level.front());
            server_encode_us_by_thread[static_cast<std::size_t>(worker)] += local_encode_us;

            // this->evaluator->multiply_plain_inplace(indicators[j][i], labels_pt);
            // Ciphertext __temp;
            // for (int s=0;s<params.label_ct_size-1;s++){
            //     this->evaluator->multiply_plain(indicators[j][i], labels_pt, __temp);
        // }
    }

    this->evaluator->add_many(indicators, indicators_sum);
    const uint64_t server_encode_us = *std::max_element(
        server_encode_us_by_thread.begin(), server_encode_us_by_thread.end());
    const uint64_t server_encode_ms = (server_encode_us + 999ULL) / 1000ULL;
    if (metrics) {
        metrics->metrics_["time_offline_comp"] += server_encode_ms;
        metrics->metrics_["time_offline_server_encode"] += server_encode_ms;
    }

    uint64_t num_bins = params.active_bins > 0
                        ? params.active_bins
                        : (1ULL << params.log_poly_modulus_degree);
    if (num_bins > slot_count) {
        num_bins = slot_count;
    }
    const uint64_t plain_mod = this->enc_params->plain_modulus().value();
    uint64_t factorial = 1;
    for (uint64_t i = 2; i <= hw; ++i) {
        factorial = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(factorial) * i) % plain_mod);
    }

    if (params.task == PSUca_C || params.task == PSUca_S) {
        auto online_comp_start = std::chrono::steady_clock::now();
        uint64_t b = num_bins;
        if (b == 0) {
            throw std::invalid_argument("num_bins must be positive for PSUca_C");
        }

        if (plain_mod <= 2) {
            throw std::invalid_argument("plain_modulus must be > 2 for PSUca_C shf sampling");
        }

        Ciphertext selected(indicators_sum);
        if (params.task == PSUca_C) {
            this->evaluator->negate_inplace(selected);
            std::vector<uint64_t> factorial_slots(slot_count, factorial);
            Plaintext factorial_plain;
            this->batch_encoder->encode(factorial_slots, factorial_plain);
            this->evaluator->add_plain_inplace(selected, factorial_plain);
        }

        // The client decodes and sums only the first b slots, so inactive slots
        // need no homomorphic zeroing (which would unnecessarily add noise).

        // First one-time pad: this hides the noise-exhausted EEQ slots while
        // the client decrypts and re-encrypts them. An independent final pad is
        // sampled by handle_circuit_connection after refresh and before the
        // encrypted slot permutation.
        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(0ULL, plain_mod - 1);
        psuca_refresh_mask_.assign(slot_count, 0ULL);
        for (uint64_t i = 0; i < b; ++i) {
            psuca_refresh_mask_[i] = dist(rng);
        }
        Plaintext mask_plain;
        this->batch_encoder->encode(psuca_refresh_mask_, mask_plain);
        Ciphertext ca_pkc(selected);
        this->evaluator->add_plain_inplace(ca_pkc, mask_plain);

        data_stream.str("");
        data_stream.clear();
        // This is an intermediate blinded ciphertext, not the final response.
        // The client refreshes it through the control service; that service
        // returns the independently masked and permuted final ciphertext.
        ca_pkc.save(data_stream);

    } else if (params.task == circuitPSU) {
        if (server_sy_.empty() || server_sy_prime_.empty()) {
            prepare_secret_shares(params);
        }

        // A dense per-slot XOR mask cannot safely be multiplied into the deep
        // EEQ ciphertext: its noise budget is already small.  Send an
        // additively one-time-padded EEQ value to the client.  The client will
        // decrypt and re-encrypt that masked value, after which the circuit
        // control round removes this server-only pad from a fresh ciphertext
        // and creates the XOR shares.
        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> field_dist(0ULL, plain_mod - 1ULL);
        circuit_refresh_mask_.assign(slot_count, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            circuit_refresh_mask_[i] = field_dist(rng);
        }
        Plaintext refresh_mask_plain;
        this->batch_encoder->encode(circuit_refresh_mask_, refresh_mask_plain);
        Ciphertext masked_indicator(indicators_sum);
        this->evaluator->add_plain_inplace(masked_indicator, refresh_mask_plain);
        server_shs_bits_.clear();

        data_stream.str("");
        data_stream.clear();
        this->server_public_key.save(data_stream);
        masked_indicator.save(data_stream);
        uint64_t sy_count_be = htobe64(server_sy_prime_.size());
        data_stream.write(reinterpret_cast<const char*>(&sy_count_be), sizeof(sy_count_be));
        for (uint64_t i = 0; i < server_sy_prime_.size(); ++i) {
            uint64_t word_be = htobe64(server_sy_prime_[i]);
            data_stream.write(reinterpret_cast<const char*>(&word_be), sizeof(word_be));
        }

    } else if (params.task == PSU) {
        // Do not multiply the deep EEQ ciphertext by a dense per-slot bit
        // vector: that operation consumes the remaining BFV noise budget.
        // Instead mask hw!*membership additively over Z_t.  The client sees
        // only the one-time-padded value, while Enc_pkS(mask) lets it transfer
        // the unmasked indicator to the server key without learning the mask.
        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(0ULL, plain_mod - 1ULL);
        std::vector<uint64_t> mask_slots(slot_count, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            mask_slots[i] = dist(rng);
        }
        Plaintext mask_plain;
        this->batch_encoder->encode(mask_slots, mask_plain);

        Ciphertext masked_indicator(indicators_sum);
        this->evaluator->add_plain_inplace(masked_indicator, mask_plain);

        Ciphertext encrypted_mask;
        this->server_encryptor->encrypt(mask_plain, encrypted_mask);

        results = {masked_indicator, encrypted_mask};
        data_stream.str("");
        data_stream.clear();
        this->server_public_key.save(data_stream);
        send_results(results, data_stream);
    } else {
        throw std::invalid_argument("unsupported task in server computation");
    }

    switch(params.task){
        case PSU:
            break;
        case PSUca_C:
        case PSUca_S:
            break;
        case circuitPSU:
            break;
    }

    const auto online_comp_end = std::chrono::steady_clock::now();
    const uint64_t server_protocol_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            online_comp_end - online_comp_start).count());
    const uint64_t server_online_ms = server_protocol_ms > server_encode_ms
                                    ? server_protocol_ms - server_encode_ms : 0ULL;
    if (metrics) {
        metrics->metrics_["time_online_comp"] += server_online_ms;
        metrics->metrics_["time_online_server"] += server_online_ms;
    }
    online_time.end();
    server_time.end();
    if (metrics) {
        metrics->metrics_["time_server"] += static_cast<uint64_t>(server_time.get_time_in_milliseconds());
    }

    // debug print removed

        // The second send_results call is removed as it is redundant

}

void Server::finalize_psuca_s(int64_t ca_mid, uint64_t server_set, uint64_t client_bins) {
    auto comp_start = std::chrono::steady_clock::now();
    if (!psuca_shf_valid_) {
        std::cerr << "[WARN] PSUca_S shf_sum missing; cannot finalize" << std::endl;
        return;
    }
    if (psuca_plain_mod_ == 0 || psuca_scale_inv_ == 0) {
        throw std::runtime_error("PSUca_S scale state missing");
    }
    const uint64_t masked = static_cast<uint64_t>(ca_mid);
    const uint64_t mask = static_cast<uint64_t>(psuca_shf_sum_);
    const uint64_t scaled_intersection =
        (masked + psuca_plain_mod_ - mask) % psuca_plain_mod_;
    const uint64_t intersection = static_cast<uint64_t>(
        (static_cast<unsigned __int128>(scaled_intersection) * psuca_scale_inv_)
        % psuca_plain_mod_);
    __int128 ca_wide = static_cast<__int128>(server_set)
                     + static_cast<__int128>(client_bins)
                     - static_cast<__int128>(intersection);
    if (ca_wide < 0 || ca_wide > static_cast<__int128>(std::numeric_limits<uint64_t>::max())) {
        throw std::overflow_error("PSUca_S result is outside uint64_t range");
    }
    uint64_t ca = static_cast<uint64_t>(ca_wide);
    std::cout << "[SERVER] ca = " << ca << std::endl;
    if (metrics) {
        metrics->metrics_["cardi"] = ca;
        auto comp_end = std::chrono::steady_clock::now();
        uint64_t comp_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(comp_end - comp_start).count());
        metrics->metrics_["time_online_comp"] += comp_ms;
        metrics->metrics_["time_online_server"] += comp_ms;
    }
    psuca_shf_valid_ = false;
    psuca_plain_mod_ = 0;
    psuca_scale_inv_ = 0;
}
