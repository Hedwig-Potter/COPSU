//
// Created by Administrator on 2025/9/23.
//

#include "server.h"
#include "client.h"

#include <cassert>
#include <algorithm>
#include <chrono>
#include <numeric>
// #include <algorithm>//
// #include <memory>//
#include <random>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <endian.h>
#include <unistd.h>

using namespace std;
using namespace seal;


void Server::set_client(Client* client) {
    client_ref_ = client;
}

void Server::start_psu_service(const Params& params, int num_input_cts, Metrics* metrics, bool verbose) {
    if (psu_thread_.joinable()) {
        return;
    }

    const char* port_env = std::getenv("PSU_SERVER_PORT");
    if (port_env && port_env[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(port_env, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            psu_port_ = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_SERVER_PORT='" << port_env
                      << "', fallback to " << psu_port_ << std::endl;
        }
    }

    {
        std::lock_guard<std::mutex> lock(psu_mutex_);
        psu_params_ = params;
        psu_num_input_cts_ = num_input_cts;
        psu_metrics_ = metrics;
        psu_verbose_ = verbose;
    }

    psu_stop_.store(false, std::memory_order_release);
    psu_thread_ = std::thread(&Server::serve_psu_requests, this);
}

void Server::stop_psu_service() {
    psu_stop_.store(true, std::memory_order_release);

    if (psu_listen_fd_ != -1) {
        int wake_fd = net::connect_socket(psu_host_, psu_port_);
        if (wake_fd >= 0) {
            ::close(wake_fd);
        }
    }

    if (psu_thread_.joinable()) {
        psu_thread_.join();
    }
}

void Server::start_masked_service() {
    if (masked_thread_.joinable()) {
        return;
    }

    const char* port_env = std::getenv("PSU_MASKED_PORT");
    if (port_env && port_env[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(port_env, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            masked_port_ = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_MASKED_PORT='" << port_env
                      << "', fallback to " << masked_port_ << std::endl;
        }
    }

    masked_stop_.store(false, std::memory_order_release);
    masked_thread_ = std::thread(&Server::serve_masked_requests, this);
}

void Server::stop_masked_service() {
    masked_stop_.store(true, std::memory_order_release);

    if (masked_listen_fd_ != -1) {
        int wake_fd = net::connect_socket(masked_host_, masked_port_);
        if (wake_fd >= 0) {
            ::close(wake_fd);
        }
    }

    if (masked_thread_.joinable()) {
        masked_thread_.join();
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
    auto reconstructed = receive_and_decrypt_masked(stream);
    if (std::getenv("CWPSU_VERIFY_OUTPUT")) {
        for (std::size_t group = 0; group < reconstructed.size(); ++group) {
            for (std::size_t slot = 0; slot < reconstructed[group].size(); ++slot) {
                if (reconstructed[group][slot] != 0) {
                    throw std::runtime_error("PSU output verification failed at group "
                        + std::to_string(group) + ", slot " + std::to_string(slot)
                        + ", value " + std::to_string(reconstructed[group][slot]));
                }
            }
        }
        std::cout << "[VERIFY] encrypted PSU output passed" << std::endl;
    }

    const uint64_t extract_ms = metrics ? metrics->metrics_["time_server_extract"] : 0ULL;
    const uint64_t resp_len_be = htobe64(sizeof(uint64_t));
    const uint64_t extract_ms_be = htobe64(extract_ms);
    if (!net::send_all(conn_fd, &resp_len_be, sizeof(resp_len_be)) ||
        !net::send_all(conn_fd, &extract_ms_be, sizeof(extract_ms_be))) {
        std::cerr << "[WARN] Failed to send masked ack" << std::endl;
    }
}

void Server::handle_psu_connection(int conn_fd) {
    uint64_t len_be = 0;
    if (!net::recv_all(conn_fd, &len_be, sizeof(len_be))) {
        std::cerr << "[WARN] Failed to read PSU request length" << std::endl;
        return;
    }
    uint64_t len = be64toh(len_be);

    std::string payload(len, '\0');
    if (len > 0 && !net::recv_all(conn_fd, payload.data(), payload.size())) {
        std::cerr << "[WARN] Failed to read PSU request payload" << std::endl;
        return;
    }

    Params params;
    int num_input_cts = 0;
    Metrics* metrics = nullptr;
    bool verbose = false;
    {
        std::lock_guard<std::mutex> lock(psu_mutex_);
        params = psu_params_;
        num_input_cts = psu_num_input_cts_;
        metrics = psu_metrics_;
        verbose = psu_verbose_;
    }

    std::string response(sizeof(uint32_t), '\0');
    bool setup_only = false;
    try {
        constexpr uint32_t kMagic = 0x43575031U;
        constexpr uint32_t kWireVersion = 2;
        constexpr uint32_t kSetupMessage = 1;
        constexpr uint32_t kBatchMessage = 2;
        size_t cursor = 0;
        auto get32 = [&]() {
            if (cursor + 4 > payload.size()) throw std::runtime_error("truncated request header");
            uint32_t v = 0; std::memcpy(&v, payload.data() + cursor, 4); cursor += 4; return ntohl(v);
        };
        auto get64 = [&]() {
            if (cursor + 8 > payload.size()) throw std::runtime_error("truncated request header");
            uint64_t v = 0; std::memcpy(&v, payload.data() + cursor, 8); cursor += 8; return be64toh(v);
        };
        bool standalone = payload.size() >= 4;
        if (standalone) {
            uint32_t v = 0; std::memcpy(&v, payload.data(), 4); standalone = ntohl(v) == kMagic;
        }
        if (standalone) {
            if (get32() != kMagic) throw std::runtime_error("invalid standalone wire magic");
            const uint32_t wire_version = get32();
            if (wire_version == kWireVersion) {
                const uint32_t message_type = get32();
                const uint64_t request_session_id = get64();
                if (request_session_id == 0) {
                    throw std::runtime_error("invalid standalone setup session id");
                }
                if (message_type == kSetupMessage) {
                    const uint64_t setup_size = get64();
                    if (setup_size == 0 || setup_size != payload.size() - cursor) {
                        throw std::runtime_error("invalid standalone setup length");
                    }
                    std::stringstream setup(std::string(
                        payload.data() + cursor, static_cast<size_t>(setup_size)));
                    const auto setup_start = std::chrono::steady_clock::now();
                    const uint64_t keygen_ms = load_parameters_and_keys(setup, false, verbose);
                    const auto setup_end = std::chrono::steady_clock::now();
                    const uint64_t setup_total_ms = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            setup_end - setup_start).count());
                    const uint64_t load_ms = setup_total_ms > keygen_ms
                        ? setup_total_ms - keygen_ms : 0ULL;
                    setup_session_id_ = request_session_id;
                    setup_session_valid_ = true;
                    const uint64_t load_be = htobe64(load_ms);
                    const uint64_t keygen_be = htobe64(keygen_ms);
                    response.append(reinterpret_cast<const char*>(&load_be), sizeof(load_be));
                    response.append(reinterpret_cast<const char*>(&keygen_be), sizeof(keygen_be));
                    setup_only = true;
                } else if (message_type == kBatchMessage) {
                    if (!setup_session_valid_ || request_session_id != setup_session_id_) {
                        throw std::runtime_error("unknown or expired standalone setup session");
                    }
                } else {
                    throw std::runtime_error("unsupported standalone message type");
                }
            } else if (wire_version != 1) {
                throw std::runtime_error("unsupported wire protocol version");
            }

            if (!setup_only) {
            uint32_t task = get32();
            num_input_cts = static_cast<int>(get32());
            uint64_t server_set = get64();
            uint64_t effective = get64();
            uint64_t hw = get64();
            uint64_t client_set = get64();
            uint64_t offset = get64();
            uint64_t setup_size = wire_version == 1 ? get64() : 0ULL;
            if (task != static_cast<uint32_t>(PSU)) throw std::runtime_error("standalone server supports PSU only");
            params = Params(PSU, server_set, effective, hw, client_set);
            params.client_bin_offset = offset;
            if (num_input_cts != static_cast<int>(params.ell)) throw std::runtime_error("ciphertext count mismatch");
            uint64_t setup_load_ms = 0;
            uint64_t setup_keygen_ms = 0;
            if (wire_version == 1 && setup_size > 0) {
                if (setup_size > payload.size() - cursor) {
                    throw std::runtime_error("invalid setup length");
                }
                std::stringstream setup(std::string(
                    payload.data() + cursor, static_cast<size_t>(setup_size)));
                cursor += static_cast<size_t>(setup_size);
                const auto setup_load_start = std::chrono::steady_clock::now();
                setup_keygen_ms = load_parameters_and_keys(setup, false, verbose);
                const auto setup_load_end = std::chrono::steady_clock::now();
                const uint64_t setup_total_ms = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        setup_load_end - setup_load_start).count());
                setup_load_ms = setup_total_ms > setup_keygen_ms
                    ? setup_total_ms - setup_keygen_ms : 0ULL;
                setup_session_valid_ = false;
            } else if (!context || !evaluator || !batch_encoder || !server_encryptor) {
                throw std::runtime_error("missing setup data for the first batch");
            }
            service_metrics_.metrics_.clear();
            metrics = &service_metrics_;
            psu_metrics_ = metrics;
            metrics->metrics_["time_setup_server_load_ms"] += setup_load_ms;
            metrics->metrics_["time_setup_server_keygen_ms"] += setup_keygen_ms;
            }
        }

        if (!setup_only) {
        std::stringstream stream(std::string(payload.data() + cursor, payload.size() - cursor));
        do_server_computation(stream, num_input_cts, params, metrics, verbose);
        uint64_t server_time_be = htobe64(metrics ? metrics->metrics_["time_server"] : 0);
        response.append(reinterpret_cast<const char*>(&server_time_be), sizeof(server_time_be));
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
            uint64_t value = metrics ? metrics->metrics_[name] : 0;
            value = htobe64(value);
            response.append(reinterpret_cast<const char*>(&value), sizeof(value));
        }
        std::string body = stream.str();
        response.append(body);
        }
    } catch (const std::exception& ex) {
        uint32_t status = htonl(1);
        std::memcpy(response.data(), &status, sizeof(status));
        response.append(ex.what());
        std::cerr << "[ERROR] PSU request failed: " << ex.what() << std::endl;
    }

    uint64_t resp_len_be = htobe64(response.size());
    if (!net::send_all(conn_fd, &resp_len_be, sizeof(resp_len_be))) {
        std::cerr << "[WARN] Failed to send PSU response length" << std::endl;
        return;
    }
    if (!response.empty() && !net::send_all(conn_fd, response.data(), response.size())) {
        std::cerr << "[WARN] Failed to send PSU response payload" << std::endl;
    }
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
        // if (k % 50 == 0) {
        //     cout << "[TRACE][server] decrypting group " << k << "/" << K << endl;
        // }
        vector<vector<uint64_t>> digits(m, vector<uint64_t>(D, 0));
        for (uint64_t d = 0; d < D; ++d) {
            Ciphertext ct; ct.load(*context, data_stream);
            Plaintext pt;
            vector<uint64_t> slot_vals;
            bool ok = true;
            try {
                if (ct.is_transparent()) {
                    ok = false;
                } else {
                    decryptor.decrypt(ct, pt);
                    this->batch_encoder->decode(pt, slot_vals);
                }
            } catch (...) {
                ok = false;
            }
            if (!ok) slot_vals.assign(m, 0);
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
        this->metrics->metrics_["time_server_extract"] += static_cast<uint64_t>(decrypt_timer.get_time_in_milliseconds());
    }
    return all_elements;
}

uint64_t Server::load_parameters_and_keys(stringstream& params_stream, bool debug_mode, bool _verbose)
{
    this->enc_params = new EncryptionParameters();
    this->enc_params->load(params_stream);

    this->context = new SEALContext(*enc_params);

    this->rlk_keys_server = new RelinKeys();
    this->gal_keys_server = new GaloisKeys();
    this->public_key = new PublicKey();
    this->rlk_keys_server->load(*context, params_stream);
    this->gal_keys_server->load(*context, params_stream);
    this->public_key->load(*context, params_stream);

    this->batch_encoder = new BatchEncoder(*context);
    this->encryptor = new Encryptor(*context, *public_key);
    this->evaluator = new Evaluator(*context);

    // if (debug_mode){
    //     SecretKey secret_key;
    //     secret_key.load(*context, params_stream);
        // this->noise_calculator = new Decryptor(*context, secret_key);
        // try {
    //     cout << "[DEBUG] noise_calculator initialized" << endl;
        // } catch(...){}
    // }
    if (debug_mode){
        SecretKey secret_key;
        secret_key.load(*context, params_stream);
        this->noise_calculator = new Decryptor(*context, secret_key);
    }

    // The server key pair belongs to the setup session, not to an individual
    // query batch.  Generate it once here and reuse it for every batch that
    // references this setup session.
    Timer server_keygen_timer;
    server_keygen_timer.start();
    KeyGenerator server_keygen(*context);
    this->server_secret_key = server_keygen.secret_key();
    server_keygen.create_public_key(this->server_public_key);
    this->server_encryptor = new Encryptor(*context, this->server_public_key);
    return static_cast<uint64_t>(server_keygen_timer.end_and_get());
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
    // Match FeUPSU's deterministic binned dataset exactly: row 0 contains
    // the client elements and later rows contain disjoint table entries.
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

std::vector<uint64_t> Server::request_permute_share_over_network(
    const std::vector<uint64_t>& rnd,
    const std::string& host,
    uint16_t port,
    uint64_t& request_bytes,
    uint64_t& response_bytes,
    uint64_t& remote_compute_us,
    uint64_t& osn_comm_bytes,
    uint64_t& local_compute_ms) {

    int sock_fd = net::connect_socket(host, port);
    if (sock_fd < 0) {
        throw std::runtime_error("failed to connect to permute-share service at " + host + ":" + std::to_string(port));
    }

    request_bytes = 0;
    response_bytes = 0;
    remote_compute_us = 0;
    osn_comm_bytes = 0;
    local_compute_ms = 0;

    uint16_t osn_port = permute_osn_port_;
    if (const char* env_port = std::getenv("PSU_PERMUTE_OSN_PORT"); env_port && env_port[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            osn_port = static_cast<uint16_t>(port_val);
        } else {
            ::close(sock_fd);
            throw std::runtime_error("invalid PSU_PERMUTE_OSN_PORT");
        }
    }

    uint32_t header[2] = {htonl(1), htonl(static_cast<uint32_t>(osn_port))};
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

    // Wait until the permutation holder has accepted the request. No element
    // of rnd is sent on this control channel.
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

    bcs::PartyShareOutput receiver_output;
    try {
        const std::string endpoint = host + ":" + std::to_string(osn_port);
        receiver_output = bcs::permute_share_receiver_arithmetic(
            rnd, endpoint, this->enc_params->plain_modulus().value(), 1);
    } catch (...) {
        ::close(sock_fd);
        throw;
    }
    local_compute_ms = receiver_output.compute_ms;
    osn_comm_bytes = receiver_output.comm_bytes;

    if (!net::recv_all(sock_fd, resp_header, sizeof(resp_header))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to read permute-share completion header");
    }
    response_bytes += sizeof(resp_header);
    msg_type = ntohl(resp_header[0]);
    if (msg_type != 4) {
        ::close(sock_fd);
        throw std::runtime_error("permute-share sender failed");
    }

    uint64_t compute_us_be = 0;
    if (!net::recv_all(sock_fd, &compute_us_be, sizeof(compute_us_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to read permute-share compute time");
    }
    response_bytes += sizeof(compute_us_be);
    remote_compute_us = be64toh(compute_us_be);

    uint64_t sender_comm_be = 0;
    if (!net::recv_all(sock_fd, &sender_comm_be, sizeof(sender_comm_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to read permute-share communication count");
    }
    response_bytes += sizeof(sender_comm_be);
    osn_comm_bytes += be64toh(sender_comm_be);

    ::close(sock_fd);
    const uint64_t modulus = this->enc_params->plain_modulus().value();
    for (auto& share : receiver_output.share) share %= modulus;
    return std::move(receiver_output.share);
}

void Server::do_server_computation(stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool _verbose){
    Timer server_time;
    vector<Ciphertext> inputs = load_inputs(data_stream, num_input_cts);

    vector<Ciphertext> results;//

    this->metrics = metrics;

    server_time.start();
    const auto server_protocol_start = std::chrono::steady_clock::now();

    uint64_t bins = 1 << params.log_poly_modulus_degree;
    uint64_t mu = params.mu;
    uint64_t ell = params.ell;
    uint64_t hw = params.hw;
    uint64_t effective_lambda = params.effective_lambda;
    // uint64_t label_ct_size=params.label_ct_size;
    // assert( gamma*ell == inputs.size() );

    // cout << "[TRACE][server] starting main loop with mu=" << mu << endl;
    vector<Ciphertext> indicators(mu);
    Ciphertext indicators_sum;
    std::vector<uint64_t> server_encode_us_by_thread(
        static_cast<std::size_t>(std::max(1, omp_get_max_threads())), 0ULL);

    const auto constant_encode_start = std::chrono::steady_clock::now();
    EEQParams eeq_params = build_eeq_params(hw, this->enc_params->plain_modulus().value());
    vector<Plaintext> eeq_coeff_plain(eeq_params.coefficients.size());
    vector<uint64_t> eeq_constant_slots(this->batch_encoder->slot_count());
    for (size_t idx = 0; idx < eeq_params.coefficients.size(); ++idx){
        std::fill(eeq_constant_slots.begin(), eeq_constant_slots.end(), eeq_params.coefficients[idx]);
        this->batch_encoder->encode(eeq_constant_slots, eeq_coeff_plain[idx]);
    }
    vector<Plaintext> eeq_root_plain(hw);
    for (uint64_t root = 0; root < hw; ++root) {
        std::fill(eeq_constant_slots.begin(), eeq_constant_slots.end(), root);
        this->batch_encoder->encode(eeq_constant_slots, eeq_root_plain[root]);
    }
    const auto constant_encode_end = std::chrono::steady_clock::now();
    const uint64_t constant_encode_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            constant_encode_end - constant_encode_start).count());
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

            for (int bin_index=0;bin_index<bins;bin_index++){
                uint64_t global_bin = params.client_bin_offset + static_cast<uint64_t>(bin_index);
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
                if (inputs[k].is_transparent() || accumulate(operands_vec[k].begin(), operands_vec[k].end(), 0) == 0){
                    _temp[k] = zero_pt;
                } else {
                    const auto batch_encode_start = std::chrono::steady_clock::now();
                    this->batch_encoder->encode(operands_vec[k], operand_pt);
                    const auto batch_encode_end = std::chrono::steady_clock::now();
                    local_encode_us += static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            batch_encode_end - batch_encode_start).count());
                    try {
                        this->evaluator->multiply_plain(inputs[k], operand_pt, _temp[k]);
                    } catch (const std::exception &ex) {
                        std::cerr << "[DEBUG] multiply_plain failed: " << ex.what() << std::endl;
                        throw;
                    }
                }
            }

            Ciphertext _ct;
            this->evaluator->add_many(_temp, _ct);

            // 4. EEQ(dot, hw) = prod_{j=0}^{hw-1}(dot-j) / hw!.
            // A balanced product tree has logarithmic multiplicative depth;
            // the previous Horner evaluation had depth hw and exhausted noise.
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
            // Keep the falling-factorial scale hw! here. Multiplying this deep
            // ciphertext by 1/hw! exhausts BFV noise; normalization is moved to
            // the fresh server-key ciphertext on the client side.
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
    const uint64_t server_encode_ms = constant_encode_ms
        + (server_encode_us + 999ULL) / 1000ULL;
    if (metrics) {
        metrics->metrics_["time_offline_server_encode_ms"] += server_encode_ms;
    }
    // Keep the indicator at its current level. cwPSU decrypts ind+r under the
    // client key before constructing a fresh ciphertext under the server key,
    // so forcing it to the last level is unnecessary and destroys the noise
    // budget after the EEQ polynomial.

    // 8. Compute the scaled inverse indicator hw! - indicator_sum.
    uint64_t slot_count = this->batch_encoder->slot_count();
    uint64_t factorial = 1ULL;
    for (uint64_t i = 2; i <= hw; ++i) {
        factorial = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(factorial) * i) %
            this->enc_params->plain_modulus().value());
    }
    std::vector<uint64_t> ones(slot_count, factorial);
    Plaintext ones_plain;
    this->batch_encoder->encode(ones, ones_plain);

    Ciphertext ind_cipher(indicators_sum);
    this->evaluator->negate_inplace(ind_cipher);
    this->evaluator->add_plain_inplace(ind_cipher, ones_plain);
    // {
    //     std::size_t num_bins_debug = 1ULL << params.log_poly_modulus_degree;
    //     if (num_bins_debug > slot_count) {
    //         num_bins_debug = slot_count;
    //     }
    //     Decryptor* debug_dec_ptr = nullptr;
    //     std::unique_ptr<Decryptor> debug_dec_owner;
    //     if (this->noise_calculator) {
    //         debug_dec_ptr = this->noise_calculator;
    //     } else if (this->client_ref_) {
    //         try {
    //             debug_dec_owner = std::make_unique<Decryptor>(*context, this->client_ref_->secret_key);
    //             debug_dec_ptr = debug_dec_owner.get();
    //         } catch (const std::exception &ex) {
    //             cerr << "[DEBUG] failed to construct client decryptor: " << ex.what() << endl;
    //         }
    //     }

    //     if (debug_dec_ptr) {
    //         try {
    //             Plaintext ind_plain_debug;
    //             std::vector<uint64_t> ind_slots_debug;
    //             debug_dec_ptr->decrypt(ind_cipher, ind_plain_debug);
    //                  this->batch_encoder->decode(ind_plain_debug, ind_slots_debug);
    //                  std::size_t limit = std::min(num_bins_debug, ind_slots_debug.size());
    //             std::size_t ones_count = std::count(ind_slots_debug.begin(),
    //                                                 ind_slots_debug.begin() + static_cast<std::ptrdiff_t>(limit),
    //                                                 1ULL);
    //             cout << "[DEBUG] ind plaintext ones (client key): " << ones_count
    //                  << " / " << limit << endl;
    //         } catch (const std::exception &ex) {
    //             cerr << "[DEBUG] ind plaintext decrypt failed: " << ex.what() << endl;
    //         }
    //     }
    // }

    uint64_t num_bins = 1ULL << params.log_poly_modulus_degree;
    if (num_bins > slot_count) {
        num_bins = slot_count;
    }

    uint64_t plain_mod = this->enc_params->plain_modulus().value();

    // 9. Server generates a uniform one-time mask in the BFV plaintext field.
    // The arithmetic OSN returns additive shares of pi(r) modulo plain_mod.
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> rnd_dist(0ULL, plain_mod - 1ULL);
    std::vector<uint64_t> rnd(num_bins, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        rnd[i] = rnd_dist(rng);
    }

    const char* env_host = std::getenv("PSU_PERMUTE_HOST");
    std::string ps_host = (env_host && env_host[0] != '\0') ? std::string(env_host) : permute_share_host_;
    uint16_t ps_port = permute_share_port_;
    if (const char* env_port = std::getenv("PSU_PERMUTE_PORT"); env_port && env_port[0] != '\0') {
        char* end_ptr = nullptr;
        long port_val = std::strtol(env_port, &end_ptr, 10);
        if (end_ptr && *end_ptr == '\0' && port_val > 0 && port_val <= 65535) {
            ps_port = static_cast<uint16_t>(port_val);
        } else {
            std::cerr << "[WARN] Invalid PSU_PERMUTE_PORT='" << env_port
                      << "', fallback to " << ps_port << std::endl;
        }
    }

    uint64_t request_bytes = 0;
    uint64_t response_bytes = 0;
    uint64_t remote_compute_us = 0;
    uint64_t osn_comm_bytes = 0;
    uint64_t local_compute_ms = 0;
    Timer permute_network_timer;
    permute_network_timer.start();
    std::vector<uint64_t> server_share = request_permute_share_over_network(
        rnd, ps_host, ps_port, request_bytes, response_bytes, remote_compute_us,
        osn_comm_bytes, local_compute_ms);
    const uint64_t permute_round_ms = static_cast<uint64_t>(permute_network_timer.end_and_get());
    if (metrics) {
        metrics->metrics_["time_permute_share_network_ms"] += permute_round_ms;
        metrics->metrics_["comm_permute_share_request_bytes"] += request_bytes;
        metrics->metrics_["comm_permute_share_response_bytes"] += response_bytes;
        metrics->metrics_["time_permute_share_server_compute_ms"] += local_compute_ms;
        metrics->metrics_["comm_permuteshare"] += osn_comm_bytes;
    }
    if (server_share.size() < num_bins) {
        server_share.resize(num_bins, 0ULL);
    }
    if (std::getenv("CWPSU_VERIFY_SHARES") && this->client_ref_) {
        const auto expected = bcs::apply_permutation(rnd, this->client_ref_->bcs_permutation_);
        if (this->client_ref_->bcs_client_share_.size() < num_bins || expected.size() < num_bins) {
            throw std::runtime_error("arithmetic permute-share verification data is truncated");
        }
        for (uint64_t i = 0; i < num_bins; ++i) {
            const uint64_t reconstructed =
                (this->client_ref_->bcs_client_share_[i] + server_share[i]) % plain_mod;
            if (reconstructed != expected[i] % plain_mod) {
                throw std::runtime_error("arithmetic permute-share verification failed at slot "
                    + std::to_string(i));
            }
        }
        std::cout << "[VERIFY] arithmetic Permute+Share passed for "
                  << num_bins << " slots" << std::endl;
    }
    std::vector<uint64_t> share_slots(slot_count, 0ULL);
    for (size_t i = 0; i < server_share.size() && i < share_slots.size(); ++i) {
        share_slots[i] = server_share[i] % plain_mod;
    }

    Timer batch_encrypt_timer;
    batch_encrypt_timer.start();
    Plaintext share_plain;
    this->batch_encoder->encode(share_slots, share_plain);
    Ciphertext share_cipher;
    this->server_encryptor->encrypt(share_plain, share_cipher);
    uint64_t batch_encrypt_ms = static_cast<uint64_t>(batch_encrypt_timer.end_and_get());
    if (metrics) {
        metrics->metrics_["time_permute_share_batch_encrypt_ms"] += batch_encrypt_ms;
    }

    // 13. Compute Enc_pkR(ind_inverse + r), exactly as in the protocol.
    std::vector<uint64_t> rnd_slots(slot_count, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        rnd_slots[i] = rnd[i];
    }
    Plaintext rnd_plain;
    this->batch_encoder->encode(rnd_slots, rnd_plain);

    Ciphertext ind_hat(ind_cipher);
    this->evaluator->add_plain_inplace(ind_hat, rnd_plain);
    if (std::getenv("CWPSU_VERIFY_OUTPUT") && this->client_ref_) {
        Decryptor client_decryptor(*this->context, this->client_ref_->secret_key);
        Plaintext verify_plain;
        std::vector<uint64_t> verify_slots;
        client_decryptor.decrypt(ind_hat, verify_plain);
        this->batch_encoder->decode(verify_plain, verify_slots);
        std::cout << "[VERIFY] ind_hat noise budget: "
                  << client_decryptor.invariant_noise_budget(ind_hat) << " bits" << std::endl;
        for (uint64_t i = 0; i < num_bins; ++i) {
            const uint64_t expected_ind = 0;
            const uint64_t expected = (expected_ind + rnd[i]) % plain_mod;
            if (verify_slots[i] != expected) {
                throw std::runtime_error("masked indicator verification failed at slot "
                    + std::to_string(i) + ", expected " + std::to_string(expected)
                    + ", got " + std::to_string(verify_slots[i]));
            }
        }
        std::cout << "[VERIFY] masked indicator passed" << std::endl;
    }

    data_stream.str("");
    data_stream.clear();

    this->server_public_key.save(data_stream);

    uint64_t ind_cipher_count = 1;
    data_stream.write(reinterpret_cast<const char*>(&ind_cipher_count), sizeof(ind_cipher_count));
    ind_hat.save(data_stream);

    uint64_t share_cipher_count = 1;
    data_stream.write(reinterpret_cast<const char*>(&share_cipher_count), sizeof(share_cipher_count));
    share_cipher.save(data_stream);

    const auto server_protocol_end = std::chrono::steady_clock::now();
    server_time.end();
    uint64_t server_total_ms = server_time.get_time_in_milliseconds();
    uint64_t server_online_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            server_protocol_end - server_protocol_start).count());
    server_online_ms = server_online_ms > server_encode_ms
        ? server_online_ms - server_encode_ms : 0ULL;
    server_online_ms = server_online_ms > permute_round_ms
        ? server_online_ms - permute_round_ms : 0ULL;
    if (metrics) {
        metrics->metrics_["time_server"] += server_total_ms;
        metrics->metrics_["time_online_server_comp_ms"] += server_online_ms;
    }

    // debug print removed

        // The second send_results call is removed as it is redundant

}
