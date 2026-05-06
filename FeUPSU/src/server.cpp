//
// Created by Administrator on 2025/9/23.
//

#include "server.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <endian.h>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <limits>

using namespace std;
using namespace seal;

namespace {
constexpr uint64_t kSharePadBits = 10;

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
    {
        std::lock_guard<std::mutex> lock(psu_mutex_);
        server_set = psu_params_.server_set;
    }
    finalize_psuca_s(ca_mid, server_set);

    uint64_t ack = 0;
    if (!net::send_all(conn_fd, &ack, sizeof(ack))) {
        std::cerr << "[WARN] Failed to send PSUca mid ack" << std::endl;
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

    std::stringstream stream;
    if (!payload.empty()) {
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        stream.seekg(0, std::ios::beg);
    }

    do_server_computation(stream, num_input_cts, params, metrics, verbose);

    std::string response = stream.str();
    uint64_t resp_len_be = htobe64(response.size());
    if (!net::send_all(conn_fd, &resp_len_be, sizeof(resp_len_be))) {
        std::cerr << "[WARN] Failed to send PSU response length" << std::endl;
        return;
    }
    if (!response.empty() && !net::send_all(conn_fd, response.data(), response.size())) {
        std::cerr << "[WARN] Failed to send PSU response payload" << std::endl;
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

// 接收并解密来自客户端的掩码密文（分段后的 digits），返回重构的元素值向量
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
        // 直接读取 D 个 ciphertext（按原始槽顺序），每个 ciphertext 的槽 i 对应原始第 i 个元素的该 digit
        vector<vector<uint64_t>> digits(m, vector<uint64_t>(D, 0));
        for (uint64_t d = 0; d < D; ++d) {
            Ciphertext ct; ct.load(*context, data_stream);
            Plaintext pt;
            vector<uint64_t> slot_vals;
            bool ok = true;
            try {
                if (ct.is_transparent()) ok = false;
                else { decryptor.decrypt(ct, pt); this->batch_encoder->decode(pt, slot_vals); }
            } catch(...) { ok = false; }
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

    // 打印服务器解密出的并集元素，便于调试验证
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
        this->metrics->metrics_["time_server_extract"] = static_cast<uint64_t>(decrypt_timer.get_time_in_milliseconds());
    }
    return all_elements;
}

// 从流中加载客户端发送的加密参数和密钥
void Server::load_parameters_and_keys(stringstream& params_stream, bool debug_mode, bool _verbose)
{
    this->enc_params = new EncryptionParameters();
    this->enc_params->load(params_stream); // 加载加密参数

    this->context = new SEALContext(*enc_params); // 初始化上下文

    // 加载服务器计算所需的密钥
    this->rlk_keys_server = new RelinKeys();
    this->gal_keys_server = new GaloisKeys();
    this->public_key = new PublicKey();
    this->rlk_keys_server->load(*context, params_stream);
    this->gal_keys_server->load(*context, params_stream);
    this->public_key->load(*context, params_stream);

    // 初始化服务器端的 SEAL 组件
    this->batch_encoder = new BatchEncoder(*context);
    this->encryptor = new Encryptor(*context, *public_key);
    this->evaluator = new Evaluator(*context);

    // 如果是调试模式，也加载私钥以便检查噪声
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
        this->noise_calculator = new Decryptor(*context, secret_key);
    }
}

// 从流中加载客户端的查询密文
vector<Ciphertext> Server::load_inputs(stringstream& data_stream, int num_input_cts){
    vector<Ciphertext> inputs;
    Ciphertext __ct_temp;
    for (int i=0;i<num_input_cts;i++){
        __ct_temp.load(*context, data_stream);
        inputs.push_back(__ct_temp);
    }
    data_stream.str(""); // 清空流
    return inputs;
}

// 将计算结果密文写入流，准备发回给客户端
void Server::send_results(vector<Ciphertext>& results, stringstream& data_stream){
    for (int i=0;i<results.size();i++){
        results[i].save(data_stream);
    }
}

// 模拟服务器数据集中的元素
uint64_t Server::server_get(uint64_t mu_prime, uint64_t bin_index, uint64_t effective_lambda){
    // 同样，这是一个模拟函数
    return bin_index*mu_prime % (1 << effective_lambda);
}

void Server::prepare_secret_shares(const Params& params) {
    uint64_t num_bins = 1ULL << params.log_poly_modulus_degree;
    if (batch_encoder) {
        uint64_t slot_count = batch_encoder->slot_count();
        if (num_bins > slot_count) {
            num_bins = slot_count;
        }
    }

    std::vector<uint64_t> values(num_bins, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        values[i] = server_get(1, i, params.effective_lambda);
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

// 执行服务器端的核心计算
void Server::do_server_computation(stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool _verbose){
    Timer online_time;
    Timer server_time;
    vector<Ciphertext> inputs = load_inputs(data_stream, num_input_cts);
    vector<Ciphertext> results;

    online_time.start();
    server_time.start();
    this->metrics = metrics;

    // --- 1. 服务器生成自己的密钥对 ---
    // 使用与客户端相同的加密参数来确保兼容性
    auto keygen_start = std::chrono::steady_clock::now();
    KeyGenerator server_keygen(*context);
    this->server_secret_key = server_keygen.secret_key();
    server_keygen.create_public_key(this->server_public_key);
    this->server_encryptor = new Encryptor(*context, this->server_public_key);
    auto keygen_end = std::chrono::steady_clock::now();
    if (metrics) {
        uint64_t keygen_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(keygen_end - keygen_start).count());
        if (params.task == PSU) {
            metrics->metrics_["time_offline"] += keygen_ms;
        } else if (params.task == circuitPSU) {
            metrics->metrics_["time_offline_comp"] += keygen_ms;
        }
    }

    // --- 参数提取 ---
    uint64_t bins = 1 << params.log_poly_modulus_degree;
    uint64_t mu = params.mu;
    uint64_t ell = params.ell;
    uint64_t hw = params.hw;
    uint64_t effective_lambda = params.effective_lambda;
    // uint64_t label_ct_size=params.label_ct_size;
    // assert( gamma*ell == inputs.size() );

    // --- 核心计算逻辑 ---
    auto online_comp_start = std::chrono::steady_clock::now();
    // cout << "[TRACE][server] starting main loop with mu=" << mu << endl;
    // gamma 已固定为 1，只需为每个 mu 维护一个指示器密文
    vector<Ciphertext> indicators(mu);
    Ciphertext indicators_sum;

    //新增
    EEQParams eeq_params = build_eeq_params(hw, this->enc_params->plain_modulus().value());
    vector<Plaintext> eeq_coeff_plain(eeq_params.coefficients.size());
    vector<uint64_t> eeq_constant_slots(this->batch_encoder->slot_count());
    for (size_t idx = 0; idx < eeq_params.coefficients.size(); ++idx){
        std::fill(eeq_constant_slots.begin(), eeq_constant_slots.end(), eeq_params.coefficients[idx]);
        this->batch_encoder->encode(eeq_constant_slots, eeq_coeff_plain[idx]);
    }
    // Plaintext labels_pt;
    // this->batch_encoder->encode(vector<uint64_t>(this->batch_encoder->slot_count(), 3), labels_pt);
    Ciphertext zero_pt;
    encryptor->encrypt_zero(zero_pt);

    // 使用 OpenMP 对外层循环并行化；原二维循环已合并，保留 parallel for 即可
    #pragma omp parallel for
    for (int i=0;i<mu;i++){
        // if (i % 50 == 0) {
        //     #pragma omp critical
        //     {
        //         cout << "[TRACE][server] processing mu index " << i << "/" << mu << endl;
        //     }
        // }
        // for (int j=0;j<gamma;j++){
            Plaintext operand_pt;
            vector<vector<uint64_t>> operands_vec(ell,vector<uint64_t>(bins, 0));

            // 1. 对服务器的每个元素，生成其定重码
            for (int bin_index=0;bin_index<bins;bin_index++){
                uint64_t element = server_get(i, bin_index, effective_lambda);
                vector<uint64_t> code = get_cw(element, ell, hw, true);
                for (int l=0;l<ell;l++){
                    operands_vec[l][bin_index] = code[l];
                }
            }

            // 2. 将服务器的定重码与客户端的加密定重码进行同态点积
            vector<Ciphertext> _temp(ell);
            for (int k=0;k<ell;k++){
                // 如果服务器这行为全0，则无需计算，直接用0密文
                if (accumulate(operands_vec[k].begin(), operands_vec[k].end(), 0) == 0){
                    _temp[k] = zero_pt;
                } else {
                    this->batch_encoder->encode(operands_vec[k], operand_pt);
                    // 同态乘法：客户端的加密位 C(x_i) * 服务器的明文位 y_i
                    this->evaluator->multiply_plain(inputs[k], operand_pt, _temp[k]);
                    // debug prints removed
                }
            }

            // 3. 将点积结果同态相加，得到 E(sum(x_i * y_i))
            Ciphertext _ct;
            this->evaluator->add_many(_temp, _ct);

            // 4. 使用 EEQ 多项式判等（新增，删除了上面4.）
            Ciphertext acc(zero_pt);
            this->evaluator->add_plain_inplace(acc, eeq_coeff_plain.back());
            for (int j = static_cast<int>(eeq_coeff_plain.size()) - 2; j >= 0; --j){
                this->evaluator->mod_switch_to_inplace(acc, _ct.parms_id());
                this->evaluator->multiply_inplace(acc, _ct);
                this->evaluator->relinearize_inplace(acc, *rlk_keys_server);
                this->evaluator->mod_switch_to_inplace(acc, _ct.parms_id());
                this->evaluator->add_plain_inplace(acc, eeq_coeff_plain[j]);
            }
            indicators[i] = acc;

            // 6. 对于带标签PSI或求和PSI，将指示器乘以加密的标签/值
            // this->evaluator->multiply_plain_inplace(indicators[j][i], labels_pt);
            // Ciphertext __temp;
            // for (int s=0;s<params.label_ct_size-1;s++){
            //     this->evaluator->multiply_plain(indicators[j][i], labels_pt, __temp);
        // }
    }

    // 7. 将每个 gamma 的 mu 个指示器密文相加，得到每个仓的结果
    this->evaluator->add_many(indicators, indicators_sum);
    this->evaluator->mod_switch_to_inplace(indicators_sum, this->context->last_context_data()->parms_id());


    uint64_t slot_count = this->batch_encoder->slot_count();
    uint64_t num_bins = 1ULL << params.log_poly_modulus_degree;
    if (num_bins > slot_count) {
        num_bins = slot_count;
    }

    if (params.task == PSUca_C || params.task == PSUca_S) {
        auto online_comp_start = std::chrono::steady_clock::now();
        uint64_t b = num_bins;
        if (b == 0) {
            throw std::invalid_argument("num_bins must be positive for PSUca_C");
        }

        uint64_t plain_mod = this->enc_params->plain_modulus().value();
        if (plain_mod <= 2) {
            throw std::invalid_argument("plain_modulus must be > 2 for PSUca_C shf sampling");
        }

        std::vector<uint64_t> shf(slot_count, 0ULL);
        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist(2ULL, plain_mod - 1);
        unsigned __int128 shf_sum = 0;
        for (uint64_t i = 0; i < b && i < shf.size(); ++i) {
            shf[i] = dist(rng);
            shf_sum += shf[i];
        }
    int64_t ca_prime = static_cast<int64_t>(params.server_set) - static_cast<int64_t>(shf_sum);

        Plaintext shf_plain;
        this->batch_encoder->encode(shf, shf_plain);

        std::vector<uint64_t> ones(slot_count, 1ULL);
        Plaintext ones_plain;
        this->batch_encoder->encode(ones, ones_plain);

        Ciphertext ind_ivs(indicators_sum);
        if (params.task == PSUca_C) {
            this->evaluator->negate_inplace(ind_ivs);
            this->evaluator->add_plain_inplace(ind_ivs, ones_plain);
        }

        std::vector<uint32_t> permutation(b);
        std::iota(permutation.begin(), permutation.end(), 0u);
        std::shuffle(permutation.begin(), permutation.end(), rng);

        if (!this->gal_keys_server) {
            throw std::runtime_error("missing Galois keys for PSUca_C permutation");
        }

    Ciphertext ind_ivs_pi;
        bool perm_initialized = false;
        uint64_t row_size = slot_count / 2;
        std::vector<uint64_t> mask_slots(slot_count, 0ULL);
        Plaintext mask_plain;

        for (uint64_t dest = 0; dest < b; ++dest) {
            uint32_t src = permutation[dest];
            std::fill(mask_slots.begin(), mask_slots.end(), 0ULL);
            mask_slots[src] = 1ULL;
            this->batch_encoder->encode(mask_slots, mask_plain);

            Ciphertext isolated;
            this->evaluator->multiply_plain(ind_ivs, mask_plain, isolated);

            uint64_t src_index = src;
            uint64_t dest_index = dest;
            bool src_second_row = src_index >= row_size;
            bool dest_second_row = dest_index >= row_size;
            if (src_second_row) {
                this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_server);
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
                this->evaluator->rotate_rows_inplace(isolated, rotation, *this->gal_keys_server);
            }

            if (dest_second_row) {
                this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_server);
            }

            if (!perm_initialized) {
                ind_ivs_pi = std::move(isolated);
                perm_initialized = true;
            } else {
                this->evaluator->add_inplace(ind_ivs_pi, isolated);
            }
        }

        if (!perm_initialized) {
            throw std::runtime_error("failed to build permuted ind_ivs ciphertext");
        }

        Ciphertext ca_pkc(ind_ivs_pi);
        this->evaluator->add_plain_inplace(ca_pkc, shf_plain);

        data_stream.str("");
        data_stream.clear();
        if (params.task == PSUca_C) {
            uint64_t ca_prime_be = htobe64(static_cast<uint64_t>(ca_prime));
            data_stream.write(reinterpret_cast<const char*>(&ca_prime_be), sizeof(ca_prime_be));
        } else {
            psuca_shf_sum_ = static_cast<int64_t>(shf_sum);
            psuca_shf_valid_ = true;
        }
        ca_pkc.save(data_stream);

        if ((params.task == PSUca_C || params.task == PSUca_S) && metrics) {
            auto online_comp_end = std::chrono::steady_clock::now();
            uint64_t online_comp_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(online_comp_end - online_comp_start).count());
            metrics->metrics_["time_online_comp"] += online_comp_ms;
        }
    } else if (params.task == circuitPSU) {
        if (server_sy_.empty() || server_sy_prime_.empty()) {
            prepare_secret_shares(params);
        }

        std::vector<uint64_t> ones(slot_count, 1ULL);
        Plaintext ones_plain;
        this->batch_encoder->encode(ones, ones_plain);

        Ciphertext ind_cipher(indicators_sum);
        this->evaluator->negate_inplace(ind_cipher);
        this->evaluator->add_plain_inplace(ind_cipher, ones_plain);

        std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> bit_dist(0ULL, 1ULL);
        server_shr_bits_.assign(num_bins, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            server_shr_bits_[i] = bit_dist(rng);
        }

        Plaintext shr_plain;
        std::vector<uint64_t> shr_slots(slot_count, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            shr_slots[i] = server_shr_bits_[i];
        }
        this->batch_encoder->encode(shr_slots, shr_plain);

        Plaintext two_plain;
        this->batch_encoder->encode(std::vector<uint64_t>(slot_count, 2ULL), two_plain);
        Ciphertext a_plus_b;
        Ciphertext a_mul_b;
        Ciphertext two_a_b;
        Ciphertext shs_cipher;

        this->evaluator->add_plain(ind_cipher, shr_plain, a_plus_b);
        this->evaluator->multiply_plain(ind_cipher, shr_plain, a_mul_b);
        this->evaluator->relinearize_inplace(a_mul_b, *rlk_keys_server);
        this->evaluator->multiply_plain_inplace(a_mul_b, two_plain);
        two_a_b = a_mul_b;
        this->evaluator->sub(a_plus_b, two_a_b, shs_cipher);

        data_stream.str("");
        data_stream.clear();
        this->server_public_key.save(data_stream);
        shs_cipher.save(data_stream);

        auto online_comp_end = std::chrono::steady_clock::now();
        uint64_t online_comp_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(online_comp_end - online_comp_start).count());
        if (metrics) {
            metrics->metrics_["time_online_comp"] += online_comp_ms;
        }
    } else {
        vector<uint64_t> shs(num_bins);
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> distrib(0, 1);
        for(uint64_t i = 0; i < num_bins; ++i) {
            shs[i] = distrib(gen);
        }
        vector<uint64_t> shs_prime(num_bins);
        for (uint64_t i = 0; i < num_bins; ++i) {
            shs_prime[i] = 1 - shs[i];
        }
        Plaintext shs_prime_pt;
        this->batch_encoder->encode(shs_prime, shs_prime_pt);
        std::vector<uint64_t> shs_prime_twice(shs_prime);
        for (auto &val : shs_prime_twice) {
            val *= 2;
        }
        Plaintext toshs_prime_pt;
        this->batch_encoder->encode(shs_prime_twice, toshs_prime_pt);
        Plaintext shs_pt;
        this->batch_encoder->encode(shs, shs_pt);

        vector<Ciphertext> shr_cts;
        {
            Ciphertext a_plus_b, a_mul_b, shr_ct;

            this->evaluator->add_plain(indicators_sum, shs_prime_pt, a_plus_b);

            this->evaluator->multiply_plain(indicators_sum, toshs_prime_pt, a_mul_b);
            this->evaluator->relinearize_inplace(a_mul_b, *rlk_keys_server);

            this->evaluator->sub(a_plus_b, a_mul_b, shr_ct);
            shr_cts.push_back(shr_ct);
        }

        Ciphertext shs_encrypted_by_server;
        this->server_encryptor->encrypt(shs_pt, shs_encrypted_by_server);

        results = shr_cts;
        results.push_back(shs_encrypted_by_server);

        this->server_public_key.save(data_stream);
        send_results(results, data_stream);
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

    online_time.end();
    server_time.end();
    metrics->metrics_["time_server"] = static_cast<uint64_t>(server_time.get_time_in_milliseconds());

    // debug print removed

        // The second send_results call is removed as it is redundant

}

void Server::finalize_psuca_s(int64_t ca_mid, uint64_t server_set) {
    auto comp_start = std::chrono::steady_clock::now();
    if (!psuca_shf_valid_) {
        std::cerr << "[WARN] PSUca_S shf_sum missing; cannot finalize" << std::endl;
        return;
    }
    int64_t ca = static_cast<int64_t>(server_set) - ca_mid + psuca_shf_sum_;
    std::cout << "[SERVER] ca = " << ca << std::endl;
    if (metrics) {
        metrics->metrics_["cardi"] = static_cast<uint64_t>(ca < 0 ? 0 : ca);
        auto comp_end = std::chrono::steady_clock::now();
        uint64_t comp_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(comp_end - comp_start).count());
        metrics->metrics_["time_online_comp"] += comp_ms;
    }
    psuca_shf_valid_ = false;
}
