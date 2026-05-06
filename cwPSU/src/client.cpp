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

std::vector<uint64_t> Client::execute_permute_share(const std::vector<uint64_t>& rnd_bits) {
    /*
     * permute+share 工作流程：
     *   - 输入：服务器抽样的随机比特串 rnd_bits。
     *   - 客户端利用预先生成的置换 π，在本地执行 OSN，将 rnd_bits 重新编址后拆分为双方共享。
     *   - 输出：服务器份额，通过网络发送回去；客户端份额缓存为 bcs_client_share_，后续用于抵消服务器密文。
     */
    if (bcs_permutation_.empty() || bcs_permutation_.size() != rnd_bits.size()) {
        throw std::runtime_error("permute-share requires a client-defined permutation of matching size");
    }
    bcs::PermuteShareOutput output = bcs::permute_share_bits(rnd_bits, bcs_permutation_, 1);
    if (this->metrics) {
        this->metrics->metrics_["comm_permuteshare"] += output.comm_bytes;
        this->metrics->metrics_["time_permute_share_network_ms"] += output.comm_ms;
        this->metrics->metrics_["time_permute_share_client_compute_us"] += output.client_compute_ms * 1000ULL;
    }
    bcs_client_share_ = std::move(output.client_share);
    return std::move(output.server_share);
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
        // 建立一次空连接以唤醒阻塞的 accept
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

// 设置同态加密环境
void Client::setup_crypto(uint64_t log_poly_modulus_degree, vector<Modulus> coeff_bits, uint64_t prime_bitlength, bool _verbose)
{
    // --- 参数选择 ---
    // 选择 BFV 方案并构造多项式模度，为整个协议设定计算“槽位”的数量
    this->enc_params = new EncryptionParameters(scheme_type::bfv); // 使用 BFV 方案
    this->enc_params->set_poly_modulus_degree(1 << log_poly_modulus_degree);
    this->enc_params->set_coeff_modulus(coeff_bits); // 设置系数模数，影响噪声预算与安全性
    // for (Modulus mod: this->enc_params->coeff_modulus()) {
    //     cout << mod.bit_count() << " ";
    // } cout << endl;

    // 设置明文模数，使用批处理 (Batching) 模式
    this->enc_params->set_plain_modulus(PlainModulus::Batching(1 << log_poly_modulus_degree, prime_bitlength));

    // --- 初始化 SEAL 组件 ---
    // client 端持有密钥对以及批编码器，后续 BCS 定重码都依赖批处理能力
    this->context = new SEALContext(*(this->enc_params));
    if (!this->context->parameters_set()) {
        std::ostringstream err;
        err << "invalid encryption parameters: " << this->context->parameter_error_message();
        throw std::invalid_argument(err.str());
    }
    this->keygen = new KeyGenerator(*(this->context));
    this->secret_key = keygen->secret_key(); // 生成私钥
    this->encryptor = new Encryptor(*(this->context), secret_key);
    this->batch_encoder = new BatchEncoder(*(this->context));
    this->evaluator = new Evaluator(*(this->context));
    // 重新初始化时需要释放旧的 Galois 密钥，避免内存泄漏
    if (this->gal_keys_local) {
        delete this->gal_keys_local;
        this->gal_keys_local = nullptr;
    }

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

// 将加密参数、重线性化密钥、Galois 密钥和公钥序列化到流中，准备发送给服务器
void Client::send_parameters_and_keys(bool debug_mode)
{
    // `save` 方法将对象序列化并返回写入的字节数，我们将其记录下来用于统计通信开销
    this->metrics->metrics_["comm_params"] = this->enc_params->save(this->params_stream);

    Serializable<RelinKeys> rlk_client = this->keygen->create_relin_keys();
    this->metrics->metrics_["comm_relin_keys"] = rlk_client.save(this->params_stream);

    GaloisKeys gal_keys_client;
    this->keygen->create_galois_keys(gal_keys_client);
    this->metrics->metrics_["comm_gal_keys"] = gal_keys_client.save(this->params_stream);
    if (this->gal_keys_local) {
        delete this->gal_keys_local;
    }
    this->gal_keys_local = new GaloisKeys(gal_keys_client);

    Serializable<PublicKey> public_key = this->keygen->create_public_key();
    this->metrics->metrics_["comm_pk"] = public_key.save(this->params_stream);

    if (debug_mode) this->secret_key.save(this->params_stream); // 调试模式下也传递私钥用于噪声分析
}

// 模拟客户端数据集中的元素。在实际应用中，这里应该从客户端的实际数据集中获取。
uint64_t Client::client_get(uint64_t gamma_prime, uint64_t bin_index, uint64_t effective_lambda){
    // 这是一个模拟函数，返回一个基于 bin 索引和 gamma_prime 的值
    return bin_index*gamma_prime % (1 << effective_lambda);
}

std::string Client::send_psu_request_over_network(const std::string& payload,
                                                  uint64_t& request_ms,
                                                  uint64_t& response_ms) {
    std::string host = "127.0.0.1";
    uint16_t port = 39002;
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

    auto request_start = std::chrono::steady_clock::now();
    uint64_t len_be = htobe64(payload.size());
    if (!net::send_all(sock_fd, &len_be, sizeof(len_be))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to send PSU request length");
    }
    if (!payload.empty() && !net::send_all(sock_fd, payload.data(), payload.size())) {
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
    return response;
}

void Client::send_masked_payload_over_network(const std::string& payload, uint64_t& send_ms) {
    std::string host = "127.0.0.1";
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
    auto send_end = std::chrono::steady_clock::now();
    send_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(send_end - send_start).count());

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

    ::close(sock_fd);
}

// 加密一批明文并写入数据流
void Client::encrypt_and_send(vector<Plaintext>& plaintexts, bool _verbose) {
    data_stream.str(""); // 清空数据流，确保余留的服务器响应不会污染新的查询
    std::vector<Plaintext> result;
    this->metrics->metrics_["comm_request"] = 0;
    for (int i = 0; i < plaintexts.size(); i++) {
    // 使用对称加密（因为客户端有私钥），并将序列化后的密文大小累加到通信指标中
        this->metrics->metrics_["comm_request"] += this->encryptor->encrypt_symmetric(plaintexts[i]).save(data_stream);
    }
}

// 从数据流中加载服务器响应并解密
vector<Plaintext> Client::load_and_decrypt(int num_cts, Params params, bool _verbose) {
    (void)num_cts;
    std::vector<Plaintext> result;

    this->metrics->metrics_["comm_response"] = 0;

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
    if (!this->gal_keys_local) {
        throw std::runtime_error("client missing local Galois keys for ciphertext permutation");
    }

    uint64_t slot_count = this->batch_encoder->slot_count();
    uint64_t row_size = slot_count / 2;
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

    uint64_t plain_mod = this->enc_params->plain_modulus().value();

    const Ciphertext &ind_hat_cipher = ind_hat_cts.front();
    Ciphertext ind_hat_pi_cipher;
    bool initialized_pi = false;
    std::vector<uint64_t> mask_slots(slot_count, 0ULL);
    Plaintext mask_plain;

    /*
     * 密文置换核心：
     *   - 使用单点掩码截取原密文中第 src 槽的值。
     *   - 如源或目标位于第二行，则通过列旋转在两行之间跳转，再计算需要的行旋转幅度。
     *   - 对每个目的槽 dest 重复上述过程，并累加 isolated 密文，最终得到 π(ind_hat)。
     *   - 复杂度 O(num_bins × logN) 主要由旋转和批处理乘法组成。
     */
    // cout << "[TRACE][client] applying permutation across " << num_bins << " bins" << endl;
    auto perm_loop_start = std::chrono::steady_clock::now();
    for (uint64_t dest = 0; dest < num_bins; ++dest) {
        // if (dest % 2048 == 0) {
        //     auto now = std::chrono::steady_clock::now();
        //     auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - perm_loop_start).count();
        //     cout << "[TRACE][client] permuting slot " << dest << "/" << num_bins
        //          << " (elapsed " << (elapsed_ms / 1000.0) << " s)" << endl;
        // }
        uint32_t src = bcs_permutation_[dest];
        // 构造单一槽位掩码以选出源位置对应的指示器
        std::fill(mask_slots.begin(), mask_slots.end(), 0ULL);
        mask_slots[src] = 1ULL;
        this->batch_encoder->encode(mask_slots, mask_plain);

        Ciphertext isolated;
        try {
            this->evaluator->multiply_plain(ind_hat_cipher, mask_plain, isolated);
        } catch (const std::exception &ex) {
            std::cerr << "[DEBUG] multiply_plain in permute failed: " << ex.what() << std::endl;
            throw;
        }

        uint64_t src_index = src;
        uint64_t dest_index = dest;
        bool src_second_row = src_index >= row_size;
        bool dest_second_row = dest_index >= row_size;
        if (src_second_row) {
            // 源在第二行，先旋转到第一行处理
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
            // 通过行旋转将选中的指示器移动到目的槽位
            this->evaluator->rotate_rows_inplace(isolated, rotation, *this->gal_keys_local);
        }

        if (dest_second_row) {
            // 目标需要落在第二行，再执行一次列旋转移回
            this->evaluator->rotate_columns_inplace(isolated, *this->gal_keys_local);
        }

        if (!initialized_pi) {
            ind_hat_pi_cipher = std::move(isolated);
            initialized_pi = true;
        } else {
            // 逐槽累加得到完整的置换后指示器密文
            this->evaluator->add_inplace(ind_hat_pi_cipher, isolated);
        }
    }

    if (!initialized_pi) {
        throw std::runtime_error("failed to build permuted indicator ciphertext");
    }
        // 调试：使用客户端私钥解密 ind_hat_pi_cipher 并统计其中的 1 数量（262-279）
    // if (this->server) {
    //     try {
    //         Decryptor server_debug_dec(*(this->context), this->server->server_secret_key);
    //         Plaintext ind_hat_plain;
    //         std::vector<uint64_t> ind_hat_slots;
    //         server_debug_dec.decrypt(ind_hat_pi_cipher, ind_hat_plain);
    //         this->batch_encoder->decode(ind_hat_plain, ind_hat_slots);
    //       std::size_t limit = std::min(static_cast<std::size_t>(num_bins), ind_hat_slots.size());
    //         std::size_t ones_count = std::count(ind_hat_slots.begin(),
    //                                             ind_hat_slots.begin() + static_cast<std::ptrdiff_t>(limit),
    //                                             1ULL);
    //         cout << "[DEBUG] ind_hat_pi plaintext ones (server key): "
    //              << ones_count << " / " << limit << endl;
    //     } catch (const std::exception &ex) {
    //         cerr << "[DEBUG] decrypt ind_hat_pi with server key failed: " << ex.what() << endl;
    //     }
    // }

    auto perm_loop_end = std::chrono::steady_clock::now();
    auto perm_total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(perm_loop_end - perm_loop_start).count();
    // cout << "[TRACE][client] permutation loop finished in " << (perm_total_ms / 1000.0) << " s" << endl;

    std::vector<uint64_t> s_pic_slots(slot_count, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        s_pic_slots[i] = bcs_client_share_[i] % plain_mod;
    }

    Plaintext s_pic_plain;
    this->batch_encoder->encode(s_pic_slots, s_pic_plain); // s_pic 是明文份额，保持明文编码即可

    Ciphertext server_share_cipher = server_share_cts.front();
    if (server_share_cipher.parms_id() != ind_hat_pi_cipher.parms_id()) {
        this->evaluator->mod_switch_to_inplace(server_share_cipher, ind_hat_pi_cipher.parms_id());
    }

    Ciphertext ind_cipher(ind_hat_pi_cipher);
    if (s_pic_plain.parms_id() != ind_cipher.parms_id()) {
        // BFV 模式下 Plaintext 不携带上下文层级，这里保留检查便于后续调试
    }
    try {
        this->evaluator->sub_plain_inplace(ind_cipher, s_pic_plain); // 先去掉客户端明文份额
    } catch (const std::exception &ex) {
        std::cerr << "[DEBUG] sub_plain_inplace failed: " << ex.what() << std::endl;
        throw;
    }
    try {
        this->evaluator->sub_inplace(ind_cipher, server_share_cipher); // 再去掉服务器密文份额，得到 ind_pi_pks
    } catch (const std::exception &ex) {
        std::cerr << "[DEBUG] sub_inplace failed: " << ex.what() << std::endl;
        throw;
    }

    vector<Ciphertext> ind_cts;
    ind_cts.push_back(ind_cipher);

    /*
     * digit 掩码阶段：
     *   - 将客户端元素按 bf 输出 π 排列，并按明文模数拆解成 D 个基 p 数字。
     *   - 每个 digit 与指示器密文 ind_cts[k] 做同态乘法，实现“密文筛选 + 明文伪装”。
     *   - 服务器在解密后可以通过逐 digit 还原实际元素值。
     */

    // K = final_cts.size(); num_bins = number of bins = 1 << log_poly_modulus_degree
    uint64_t K = ind_cts.size();
    if (num_bins > slot_count) num_bins = slot_count; // safety

    // 为每个组计算所需的最大 D
    uint64_t p = this->enc_params->plain_modulus().value();
    vector<vector<uint64_t>> all_elements_per_group(K, vector<uint64_t>(num_bins));
    uint64_t global_max = 0;
    for (uint64_t k = 0; k < K; ++k) {
        uint64_t gamma_prime = k;
        for (uint64_t i = 0; i < num_bins; ++i) {
            all_elements_per_group[k][i] = client_get(gamma_prime, i, params.effective_lambda);
            if (all_elements_per_group[k][i] > global_max) global_max = all_elements_per_group[k][i];
        }
    }

    uint64_t D = 1;
    uint64_t tmp_max = global_max;
    while (tmp_max >= p) { tmp_max = tmp_max / p; D++; }

    // 写入头部 K, D, m（二进制）到 data_stream，直接发送给服务器
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
        // 对客户端元素套用 π，使其与服务器解码顺序对齐
        vector<uint64_t> permuted_elements = bcs::apply_permutation(all_elements_per_group[k], bcs_permutation_);

        // 对每个 digit d，构造置换后的 digit_slots，并与 ind_cts[k] 相乘
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

            Plaintext digit_pt; this->batch_encoder->encode(digit_slots, digit_pt);

            Ciphertext masked_ct;
            try {
                this->evaluator->multiply_plain(ind_cts[k], digit_pt, masked_ct);
                // 直接保存到 data_stream（按原始顺序写入），发送给服务器进行解密与重构
                uint64_t bytes = masked_ct.save(this->data_stream);
                comm_final_response += bytes;
            } catch (const exception &e) {
                cerr << "[WARN] multiply_plain failed for group "<<k<<" digit "<<d<<": "<<e.what()<<"\n";
                try {
                    if (this->server && this->server->server_encryptor) {
                        Ciphertext zero_ct; this->server->server_encryptor->encrypt_zero(zero_ct);
                        uint64_t bytes = zero_ct.save(this->data_stream);
                        comm_final_response += bytes;
                    } else {
                        Ciphertext zero_ct; this->encryptor->encrypt_zero(zero_ct);
                        uint64_t bytes = zero_ct.save(this->data_stream);
                        comm_final_response += bytes;
                    }
                } catch (const exception &e2) {
                    cerr << "[ERROR] failed to create zero ciphertext: "<<e2.what()<<"\n";
                }
            }
        }
    }

    // 现在将 masked_stream 的内容发送给服务器并让服务器解密重构元素
    this->data_stream.clear();
    this->data_stream.seekg(0, std::ios::beg);
    this->metrics->metrics_["comm_final_response"] = comm_final_response;
    this->metrics->metrics_["comm_online_comm"] += comm_final_response;
    uint64_t send_ms = 0;
    send_masked_payload_over_network(this->data_stream.str(), send_ms);
    this->metrics->metrics_["time_masked_send_ms"] = send_ms;
    auto it_online = this->metrics->metrics_.find("time_online_comm");
    if (it_online != this->metrics->metrics_.end()) {
        it_online->second += send_ms;
    } else {
        this->metrics->metrics_["time_online_comm"] = send_ms;
    }
    // 输出部分调试信息
    // cout << "[INFO] Sent masked digits to server and received reconstructed elements (groups="<<reconstructed.size()<<")."<<endl;

    // return result;


    // Ciphertext __temp_ct;
    // Plaintext __temp_pt;
    // this->metrics->metrics_["comm_response"] = 0;
    // for (int i = 0; i < num_cts; i++) {
    //     this->metrics->metrics_["comm_response"] += __temp_ct.load(*(this->context), data_stream);
    //     decryptor.decrypt(__temp_ct, __temp_pt);
    //     if (i==0){
    //         // 打印最终密文的噪声预算，用于调试，确保解密正确
    //         cout << "Final Noise: " << decryptor.invariant_noise_budget(__temp_ct) << endl;
    //     }
    //     result.push_back(__temp_pt);
    // }


    return result;
}

// 将 Params 对象中的字段保存到 Metrics 对象中
void Client::params_to_metrics(Params params) {
    // this->metrics->metrics_["gamma"] = params.gamma;
    this->metrics->metrics_["ell"] = params.ell;
    this->metrics->metrics_["hw"] = params.hw;
    this->metrics->metrics_["log_poly_modulus_degree"] = params.log_poly_modulus_degree;
    this->metrics->metrics_["effective_lambda"] = params.effective_lambda;
    this->metrics->metrics_["mu"] = params.mu;
    this->metrics->metrics_["task"] = params.task;
}

// 运行完整的端到端协议流程
bool Client::run_protocol(Params params, bool _verbose)
{
    Timer time_setup_crypto, time_server_latency, time_extract_response;
    this->metrics = new Metrics();
    this->params_to_metrics(params); // 记录参数

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

    // --- 1. 客户端设置 ---
    time_setup_crypto.start();
    try {
        this->setup_crypto(params.log_poly_modulus_degree, params.coeff_bits, params.prime_bitlength, _verbose);
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] setup_crypto failed: " << ex.what() << std::endl;
        throw;
    }
    this->metrics->metrics_["time_setup_crypto"] = time_setup_crypto.end_and_get();

    // --- 2. 发送公共参数和密钥 ---
    try {
        this->send_parameters_and_keys(debug_mode);
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] send_parameters_and_keys failed: " << ex.what() << std::endl;
        throw;
    }
    try {
        this->server->load_parameters_and_keys(this->params_stream, debug_mode, _verbose);
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] load_parameters_and_keys failed: " << ex.what() << std::endl;
        throw;
    }

    // --- 3. 准备、编码和加密查询 ---
    Timer time_build_request;
    time_build_request.start();
    vector<Plaintext> input;

        Plaintext operand_pt;
        // 创建一个二维向量来存储所有要编码的数据
        uint64_t bin_count = 1ULL << params.log_poly_modulus_degree;
        vector<vector<uint64_t>> operands_vec(params.ell,vector<uint64_t>(bin_count, 0));

        std::mt19937_64 perm_rng(std::random_device{}());
        // BCS 置换仅由客户端持有，不再显式告知服务器
        bcs_permutation_ = bcs::generate_permutation(bin_count, perm_rng);

    // 遍历 gamma 个哈希函数
    // for (uint64_t gamma_prime=0; gamma_prime<params.gamma; gamma_prime++){
        // 遍历所有仓 (bin)
        for (int bin_index=0;bin_index<static_cast<int>(bin_count);bin_index++){
            // 获取客户端元素 (这里是模拟的)
            uint64_t element = client_get(0, bin_index, params.effective_lambda);
            // 将元素转换为定重码
            vector<uint64_t> code = get_cw(element, params.ell, params.hw, true);
            // 将定重码的每一位填充到要编码的向量中
            for (int l=0;l<params.ell;l++){
                operands_vec[l][bin_index] = code[l];
            }
        }
        // 对定重码的每一行 (l) 进行批处理编码，并添加到输入向量中
        for (int l=0;l<params.ell;l++){
            this->batch_encoder->encode(operands_vec[l], operand_pt);
            input.push_back(operand_pt);
        }
    // }

    // 加密并发送查询
    try {
        this->encrypt_and_send(input, _verbose);
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] encrypt_and_send failed: " << ex.what() << std::endl;
        throw;
    }
    uint64_t build_request_ms = time_build_request.end_and_get();
    this->metrics->metrics_["time_build_request"] = build_request_ms;

    // --- 4. 调用服务器进行计算 ---
    start_permute_share_service();
    server->start_masked_service();
    time_server_latency.start();
    try {
        this->server->start_psu_service(params, static_cast<int>(input.size()), this->metrics, _verbose);
        uint64_t request_ms = 0;
        uint64_t response_ms = 0;
        std::string response = send_psu_request_over_network(this->data_stream.str(), request_ms, response_ms);
        this->data_stream.str("");
        this->data_stream.clear();
        if (!response.empty()) {
            this->data_stream.write(response.data(), static_cast<std::streamsize>(response.size()));
        }
        this->server->stop_psu_service();
        uint64_t permute_ms = 0;
        auto it_perm_net = metrics->metrics_.find("time_permute_share_network_ms");
        if (it_perm_net != metrics->metrics_.end()) {
            permute_ms += it_perm_net->second;
        }
        auto it_perm_comp = metrics->metrics_.find("time_permute_share_client_compute_us");
        if (it_perm_comp != metrics->metrics_.end()) {
            permute_ms += (it_perm_comp->second + 999) / 1000;
        }
        uint64_t batch_encrypt_ms = 0;
        auto it_batch = metrics->metrics_.find("time_permute_share_batch_encrypt_ms");
        if (it_batch != metrics->metrics_.end()) {
            batch_encrypt_ms = it_batch->second;
        }
        uint64_t server_keygen_ms = 0;
        auto it_keygen = metrics->metrics_.find("time_server_keygen_ms");
        if (it_keygen != metrics->metrics_.end()) {
            server_keygen_ms = it_keygen->second;
        }
        if (server_keygen_ms > 0) {
            this->metrics->metrics_["time_setup_crypto"] += server_keygen_ms;
        }
        this->metrics->metrics_["time_offline"] = request_ms + permute_ms + batch_encrypt_ms + build_request_ms;
        this->metrics->metrics_["time_online_comm"] = response_ms;
    } catch (const std::exception &ex) {
        this->server->stop_psu_service();
        stop_permute_share_service();
        server->stop_masked_service();
        std::cerr << "[ERROR] do_server_computation failed: " << ex.what() << std::endl;
        throw;
    }
    (void)time_server_latency.end_and_get();
    stop_permute_share_service();

    // --- 5. 接收并解密响应 ---
    time_extract_response.start();
    int num_cts; // 根据任务类型，确定期望从服务器收到的密文数量
    switch (params.task){
        case PSU: num_cts = 2; break;
        // case PSUCardinality: num_cts = 1; break;
        // case circuitPSU: num_cts = 1; break;
    }
    // debug print removed
    // 加载并解密响应
    std::vector<Plaintext> _response_pts;
    try {
        _response_pts = this->load_and_decrypt(num_cts, params, _verbose);
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] load_and_decrypt failed: " << ex.what() << std::endl;
        throw;
    }

    // Interpret the result here
    // cout << "Example Response: " << _response_pts[0].to_string() << endl;
    uint64_t extract_ms = time_extract_response.end_and_get();
    auto it_masked_send = this->metrics->metrics_.find("time_masked_send_ms");
    if (it_masked_send != this->metrics->metrics_.end()) {
        if (it_masked_send->second <= extract_ms) {
            extract_ms -= it_masked_send->second;
        } else {
            extract_ms = 0;
        }
    }
    this->metrics->metrics_["time_extract_response"] = extract_ms;
    server->stop_masked_service();

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
    // --- 6. 将性能指标写入文件 ---
    bool write_to_file=true;
    if (write_to_file) {
        const string results_dir = "results";
        namespace fs = std::filesystem;
        try {
            fs::create_directories(results_dir);
        } catch (const std::exception &e) {
            cerr << "[WARN] unable to create results directory: " << e.what() << endl;
        }

    uint64_t effective_lambda = this->metrics->metrics_["effective_lambda"];
    uint64_t hw_val = this->metrics->metrics_["hw"];

        const char *profile_env = std::getenv("NETEM_PROFILE");
        string profile = (profile_env && profile_env[0] != '\0') ? string(profile_env) : string("native");
        for (char &ch : profile) {
            unsigned char uch = static_cast<unsigned char>(ch);
            if (!std::isalnum(uch) && ch != '_' && ch != '-') {
                ch = '_';
            }
        }

    const string prefix = "effective_" + to_string(effective_lambda) + "_hw_" + to_string(hw_val) + "_";

        static unordered_map<string, uint64_t> run_counters;
        auto counter_it = run_counters.find(prefix);
        if (counter_it == run_counters.end()) {
            uint64_t max_existing = 0;
            try {
                if (fs::exists(results_dir)) {
                    for (const auto &entry : fs::directory_iterator(results_dir)) {
                        if (!entry.is_regular_file()) continue;
                        if (entry.path().extension() != ".csv") continue;
                        string stem = entry.path().stem().string();
                        if (stem.rfind(prefix, 0) != 0) continue;
                        string remainder = stem.substr(prefix.size());
                        size_t sep = remainder.find("__");
                        string number_part = remainder.substr(0, sep);
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
                cerr << "[WARN] failed to inspect existing results: " << e.what() << endl;
            }
            counter_it = run_counters.emplace(prefix, max_existing).first;
        }
        counter_it->second += 1;
        uint64_t run_index = counter_it->second;

        string filename_string = results_dir + "/" + prefix + to_string(run_index);
        if (!profile.empty()) {
            filename_string += "__" + profile;
        }
        filename_string += ".csv";

        cout << "Writing to file " << filename_string << endl;

        ofstream outFile(filename_string);
        for (const pair<string, uint64_t> &metric : this->metrics->metrics_) {
            outFile << metric.first << "," << metric.second << endl;
        }
    }
    return true;
}