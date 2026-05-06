//
// Created by Administrator on 2025/9/23.
//

#include "client.h"
#include "server.h"
#include "bcs.h"
#include "bcs_osn.h"

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

#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

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

#ifdef ENABLE_IKNP
struct IknpOtMetrics {
    std::vector<uint64_t> sx_ot;
    uint64_t comm_ms = 0;
    uint64_t compute_ms = 0;
};

IknpOtMetrics run_iknp_ot(const std::vector<uint64_t>& sx_prime,
                          const std::vector<uint64_t>& shs_bits,
                          const std::vector<uint64_t>& shr_bits) {
    using namespace osuCrypto;
    const uint64_t num_ots = sx_prime.size();
    if (num_ots == 0) {
        return {};
    }

    const std::string endpoint = "127.0.0.1:39005";
    IOService ios;

    std::vector<uint64_t> sx_ot(num_ots, 0ULL);
    std::exception_ptr sender_ex;
    std::exception_ptr receiver_ex;
    uint64_t sender_elapsed_ms = 0;
    uint64_t receiver_elapsed_ms = 0;
    uint64_t sender_sent = 0;
    uint64_t sender_recv = 0;
    uint64_t receiver_sent = 0;
    uint64_t receiver_recv = 0;

    auto total_start = std::chrono::steady_clock::now();

    std::thread sender_thread([&]() {
        try {
            auto sender_start = std::chrono::steady_clock::now();
            Session session(ios, endpoint, SessionMode::Server);
            Channel chl = session.addChannel();
            PRNG prng(sysRandomSeed());

            IknpOtExtSender sender;
            sender.genBaseOts(prng, chl);

            std::vector<std::array<block, 2>> messages(num_ots);
            for (uint64_t i = 0; i < num_ots; ++i) {
                block sx_block = toBlock(sx_prime[i], 0ULL);
                block dummy = ZeroBlock;
                if (shs_bits[i] == 0) {
                    messages[i][0] = sx_block;
                    messages[i][1] = dummy;
                } else {
                    messages[i][0] = dummy;
                    messages[i][1] = sx_block;
                }
            }

            sender.send(messages, prng, chl);
            sender_sent = chl.getTotalDataSent();
            sender_recv = chl.getTotalDataRecv();
            chl.close();
            session.stop();
            auto sender_end = std::chrono::steady_clock::now();
            sender_elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(sender_end - sender_start).count());
        } catch (...) {
            sender_ex = std::current_exception();
        }
    });

    std::thread receiver_thread([&]() {
        try {
            auto receiver_start = std::chrono::steady_clock::now();
            Session session(ios, endpoint, SessionMode::Client);
            Channel chl = session.addChannel();
            PRNG prng(sysRandomSeed());

            IknpOtExtReceiver receiver;
            receiver.genBaseOts(prng, chl);

            BitVector choices(num_ots);
            for (uint64_t i = 0; i < num_ots; ++i) {
                choices[i] = static_cast<u8>(shr_bits[i] & 1ULL);
            }

            std::vector<block> recv_msgs(num_ots);
            receiver.receive(choices, recv_msgs, prng, chl);
            for (uint64_t i = 0; i < num_ots; ++i) {
                uint64_t val = 0;
                std::memcpy(&val, &recv_msgs[i], sizeof(uint64_t));
                sx_ot[i] = val;
            }

            receiver_sent = chl.getTotalDataSent();
            receiver_recv = chl.getTotalDataRecv();
            chl.close();
            session.stop();
            auto receiver_end = std::chrono::steady_clock::now();
            receiver_elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(receiver_end - receiver_start).count());
        } catch (...) {
            receiver_ex = std::current_exception();
        }
    });

    sender_thread.join();
    receiver_thread.join();

    if (sender_ex) {
        std::rethrow_exception(sender_ex);
    }
    if (receiver_ex) {
        std::rethrow_exception(receiver_ex);
    }

    auto total_end = std::chrono::steady_clock::now();
    uint64_t total_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start).count());

    IknpOtMetrics metrics;
    metrics.sx_ot = std::move(sx_ot);
    metrics.compute_ms = std::max(sender_elapsed_ms, receiver_elapsed_ms);
    metrics.comm_ms = (total_ms > metrics.compute_ms) ? (total_ms - metrics.compute_ms) : 0;
    uint64_t total_sent = sender_sent + receiver_sent;
    uint64_t total_recv = sender_recv + receiver_recv;
    (void)total_sent;
    (void)total_recv;
    return metrics;
}
#endif
}

Client::Client() {
    server = new Server();
    server->set_client(this);
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

// 设置同态加密环境
void Client::setup_crypto(uint64_t log_poly_modulus_degree, vector<Modulus> coeff_bits, uint64_t prime_bitlength, bool _verbose)
{
    // --- 参数选择 ---
    this->enc_params = new EncryptionParameters(scheme_type::bfv); // 使用 BFV 方案
    this->enc_params->set_poly_modulus_degree(1 << log_poly_modulus_degree);
    this->enc_params->set_coeff_modulus(coeff_bits); // 设置系数模数
    // for (Modulus mod: this->enc_params->coeff_modulus()) {
    //     cout << mod.bit_count() << " ";
    // } cout << endl;

    // 设置明文模数，使用批处理 (Batching) 模式
    this->enc_params->set_plain_modulus(PlainModulus::Batching(1 << log_poly_modulus_degree, prime_bitlength));

    // --- 初始化 SEAL 组件 ---
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
        // cout << "-------------------------- Crypto Parameters "
        //         "--------------------------"
        //      << endl
        //      << "\tPoly Mod Degree: " << this->enc_params->poly_modulus_degree() << endl
        //      << "\tPlain Modulus: " << this->enc_params->plain_modulus().value() << " ("
        //      << this->enc_params->plain_modulus().bit_count() << " bits)" << endl
        //      << "\tCiphertext Modulus Bitcount: " << coeff_bitcount << endl;
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

    if (debug_mode) this->secret_key.save(this->params_stream);
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

void Client::send_psuca_mid_over_network(int64_t ca_mid, uint64_t& send_ms) {
    std::string host = "127.0.0.1";
    uint16_t port = 39006;
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
    auto send_end = std::chrono::steady_clock::now();
    send_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(send_end - send_start).count());

    uint64_t ack = 0;
    if (!net::recv_all(sock_fd, &ack, sizeof(ack))) {
        ::close(sock_fd);
        throw std::runtime_error("failed to receive PSUca mid ack");
    }

    ::close(sock_fd);
}

std::vector<uint64_t> Client::receive_syprime_over_network(uint64_t& recv_ms) {
    std::string host = "127.0.0.1";
    uint16_t port = 39004;
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

// 加密一批明文并写入数据流
void Client::encrypt_and_send(vector<Plaintext>& plaintexts, bool _verbose) {
    data_stream.str(""); // 清空数据流
    std::vector<Plaintext> result;
    this->metrics->metrics_["comm_request"] = 0;
    for (int i = 0; i < plaintexts.size(); i++) {
        // 使用对称加密（因为客户端有私钥），并将序列化后的密文大小累加到通信指标中
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

// 从数据流中加载服务器响应并解密
vector<Plaintext> Client::load_and_decrypt(int num_cts, Params params, bool _verbose) {
    std::vector<Plaintext> result;
    Decryptor decryptor(*context, this->secret_key);

    // 使用只读副本避免原流的读写指针状态干扰后续序列化
    std::stringstream response_stream(this->data_stream.str());
    this->metrics->metrics_["comm_response"] = 0;


    if (params.task == PSUca_C || params.task == PSUca_S) {
        auto online_comp_start = std::chrono::steady_clock::now();
        int64_t ca_prime = 0;
        if (params.task == PSUca_C) {
            uint64_t ca_prime_be = 0;
            if (!response_stream.read(reinterpret_cast<char*>(&ca_prime_be), sizeof(ca_prime_be))) {
                throw std::runtime_error("failed to read ca_prime from PSUca response");
            }
            ca_prime = static_cast<int64_t>(be64toh(ca_prime_be));
            this->metrics->metrics_["comm_response"] += sizeof(ca_prime_be);
        }

        Ciphertext ca_ct;
        this->metrics->metrics_["comm_response"] += ca_ct.load(*(this->context), response_stream);
        Plaintext ca_pt;
        decryptor.decrypt(ca_ct, ca_pt);
        result.push_back(ca_pt);

        std::vector<uint64_t> slots;
        this->batch_encoder->decode(ca_pt, slots);

        uint64_t slot_count = this->batch_encoder->slot_count();
        uint64_t num_bins = 1ULL << params.log_poly_modulus_degree;
        if (num_bins > slot_count) {
            num_bins = slot_count;
        }

        int64_t ca_value = 0;
        for (uint64_t i = 0; i < num_bins && i < slots.size(); ++i) {
            ca_value += static_cast<int64_t>(slots[i]);
        }

        if (params.task == PSUca_C) {
            ca_value += ca_prime;
        }

        if (params.task == PSUca_C || params.task == PSUca_S) {
            auto online_comp_end = std::chrono::steady_clock::now();
            uint64_t online_comp_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(online_comp_end - online_comp_start).count());
            this->metrics->metrics_["time_online_comp"] += online_comp_ms;
        }

        if (params.task == PSUca_C) {
            cout << "[CLIENT] ca = " << ca_value << endl;
            this->metrics->metrics_["cardi"] = static_cast<uint64_t>(ca_value < 0 ? 0 : ca_value);
        } else {
            cout << "[CLIENT] ca_mid = " << ca_value << endl;
            uint64_t send_ms = 0;
            send_psuca_mid_over_network(ca_value, send_ms);
            auto it_online = this->metrics->metrics_.find("time_online_comm");
            if (it_online != this->metrics->metrics_.end()) {
                it_online->second += send_ms;
            } else {
                this->metrics->metrics_["time_online_comm"] = send_ms;
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
        Ciphertext shs_cipher;
        comm_response += shs_cipher.load(*(this->context), response_stream);
        this->metrics->metrics_["comm_response"] = comm_response;

        auto shs_dec_start = std::chrono::steady_clock::now();
        Plaintext shs_plain;
        decryptor.decrypt(shs_cipher, shs_plain);
        std::vector<uint64_t> shs_slots;
        this->batch_encoder->decode(shs_plain, shs_slots);
        auto shs_dec_end = std::chrono::steady_clock::now();
        uint64_t shs_dec_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(shs_dec_end - shs_dec_start).count());
        this->metrics->metrics_["time_online_comp"] += shs_dec_ms;

        uint64_t slot_count = this->batch_encoder->slot_count();
        uint64_t num_bins = 1ULL << params.log_poly_modulus_degree;
        if (num_bins > slot_count) {
            num_bins = slot_count;
        }

        std::vector<uint64_t> shs_bits(num_bins, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            shs_bits[i] = shs_slots[i] & 1ULL;
        }

        if (!this->server) {
            throw std::runtime_error("circuitPSU requires a local server reference");
        }
        if (this->server->server_shr_bits_.size() < num_bins) {
            throw std::runtime_error("server shr bits missing or truncated");
        }
        if (client_sx_.size() < num_bins || client_sx_prime_.size() < num_bins) {
            throw std::runtime_error("client x shares missing or truncated");
        }
        if (client_sy_prime_.size() < num_bins || this->server->server_sy_.size() < num_bins) {
            throw std::runtime_error("y shares missing or truncated");
        }

        std::vector<uint64_t> shr_bits(this->server->server_shr_bits_.begin(),
                                       this->server->server_shr_bits_.begin() + num_bins);
        std::vector<uint64_t> sx_prime(client_sx_prime_.begin(), client_sx_prime_.begin() + num_bins);

#ifdef ENABLE_IKNP
    IknpOtMetrics ot_metrics = run_iknp_ot(sx_prime, shs_bits, shr_bits);
    this->server->server_sx_ot_ = ot_metrics.sx_ot;
    this->metrics->metrics_["time_online_comm"] += ot_metrics.comm_ms;
    this->metrics->metrics_["time_online_comp"] += ot_metrics.compute_ms;
#else
        throw std::runtime_error("IKNP OT disabled. Rebuild with ENABLE_IKNP.");
#endif

        if (bcs_permutation_.size() != num_bins) {
            throw std::runtime_error("client permutation size mismatch for circuitPSU permute-share");
        }

        auto shs_perm_start = std::chrono::steady_clock::now();
        bcs::PermuteShareOutput shs_ps = bcs::permute_share_bits(shs_bits, bcs_permutation_, 1);
        auto shs_perm_end = std::chrono::steady_clock::now();
        uint64_t shs_perm_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(shs_perm_end - shs_perm_start).count());
        uint64_t shs_perm_comp = shs_ps.client_compute_ms + shs_ps.server_compute_ms;
        uint64_t shs_perm_comm = (shs_perm_ms > shs_perm_comp) ? (shs_perm_ms - shs_perm_comp) : 0;
        this->metrics->metrics_["time_online_comm"] += shs_perm_comm;
        this->metrics->metrics_["time_online_comp"] += shs_perm_comp;

        auto shr_perm_start = std::chrono::steady_clock::now();
        bcs::PermuteShareOutput shr_ps = bcs::permute_share_bits(shr_bits, bcs_permutation_, 1);
        auto shr_perm_end = std::chrono::steady_clock::now();
        uint64_t shr_perm_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(shr_perm_end - shr_perm_start).count());
        uint64_t shr_perm_comp = shr_ps.client_compute_ms + shr_ps.server_compute_ms;
        uint64_t shr_perm_comm = (shr_perm_ms > shr_perm_comp) ? (shr_perm_ms - shr_perm_comp) : 0;
        this->metrics->metrics_["time_online_comm"] += shr_perm_comm;
        this->metrics->metrics_["time_online_comp"] += shr_perm_comp;

        if (measure_otsss) {
            uint64_t permute_us = (shs_ps.client_compute_ms + shs_ps.server_compute_ms
                                   + shr_ps.client_compute_ms + shr_ps.server_compute_ms) * 1000ULL;
            permute_share_time_us_.fetch_add(permute_us, std::memory_order_relaxed);
            permute_share_invocations_.fetch_add(2, std::memory_order_relaxed);
            this->metrics->metrics_["comm_permuteshare"] += shs_ps.comm_bytes + shr_ps.comm_bytes;
        }

        std::vector<uint64_t> ind_perm(num_bins, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            uint64_t client_share = (shs_ps.client_share[i] ^ shr_ps.client_share[i]) & 1ULL;
            uint64_t server_share = (shs_ps.server_share[i] ^ shr_ps.server_share[i]) & 1ULL;
            ind_perm[i] = (client_share ^ server_share) & 1ULL;
        }

        std::vector<uint64_t> x_values(num_bins, 0ULL);
        std::vector<uint64_t> y_values(num_bins, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            uint64_t x_shifted = client_sx_[i] ^ sx_prime[i];
            uint64_t y_shifted = client_sy_prime_[i] ^ this->server->server_sy_[i];
            x_values[i] = x_shifted >> kSharePadBits;
            y_values[i] = y_shifted >> kSharePadBits;
        }

        std::vector<uint64_t> x_perm = bcs::apply_permutation(x_values, bcs_permutation_);
        std::vector<uint64_t> y_perm = bcs::apply_permutation(y_values, bcs_permutation_);

        std::vector<uint64_t> outputs(num_bins, 0ULL);
        for (uint64_t i = 0; i < num_bins; ++i) {
            outputs[i] = ind_perm[i] ? y_perm[i] : x_perm[i];
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
    // --- 1. 从流中加载服务器的公钥 ---
    this->server_public_key.load(*(this->context), response_stream);

    // --- 2. 加载并解密 indicator_inv ---
    // 注意：收到的密文总数是 num_cts(因为额外包含 shs)
    // 我们只解密前面的 num_cts -1 个密文
    Ciphertext __temp_ct;
    Plaintext __temp_pt;
    auto decrypt_start = std::chrono::steady_clock::now();
    for (int i = 0; i < num_cts-1; i++) {
        this->metrics->metrics_["comm_response"] += __temp_ct.load(*(this->context), response_stream);
        decryptor.decrypt(__temp_ct, __temp_pt);
        // if (i==0){
        //     cout << "Final Noise (indicator_inv): " << decryptor.invariant_noise_budget(__temp_ct) << endl;
        // }
        result.push_back(__temp_pt);
    }
    auto decrypt_end = std::chrono::steady_clock::now();

    // --- 3. 加载用服务器公钥加密的 shs （服务器自身的共享） ---

    Ciphertext shs_encrypted;
    this->metrics->metrics_["comm_response"] += shs_encrypted.load(*(this->context), response_stream);
    // cout << "[INFO] Client received encrypted server share from server." << endl;
    // --- 4. 使用客户端私钥解密 shr_cts（已放入 result），并与服务器加密的 shs 进行明-密文同态运算 ind = shr XOR shs ---
    // 此处：
    //  - result: vector<Plaintext>，包含客户端解密得到的 shr 明文（每个元素对应一个编码向量）
    //  - shs_encrypted: Ciphertext，服务器用其公钥加密的共享（编码为一个批量向量）
    // 我们将对每个 shr 明文执行以下操作（在服务器公钥下产生密文）：
    //    a_plus_b = add_plain(shs_encrypted, shr_pt)
    //    a_mul_b = multiply_plain(shs_encrypted, shr_pt)
    //    two_a_b = multiply_plain_inplace(a_mul_b, two_pt)
    //    final_ct = a_plus_b - two_a_b
    
    // 读取服务器发来的 shs 密文（已加载为 shs_encrypted）
    // 计算并序列化回 data_stream 以便发送回服务器或供后续使用
    vector<Ciphertext> ind_cts; // 每个密文均在服务器公钥下，表示 ind = shr XOR shs
    auto ind_compute_start = std::chrono::steady_clock::now();
    for (const auto& shr_pt : result) {
        Ciphertext a_plus_b_ct, a_mul_b_ct, final_ct;
        std::vector<uint64_t> shr_slots;
        this->batch_encoder->decode(shr_pt, shr_slots);
        for (auto &val : shr_slots) {
            val *= 2;
        }
        Plaintext toshr_pt;
        this->batch_encoder->encode(shr_slots, toshr_pt);

        // shs + shr
        this->evaluator->add_plain(shs_encrypted, shr_pt, a_plus_b_ct);

        // shs * (2*shr)
        this->evaluator->multiply_plain(shs_encrypted, toshr_pt, a_mul_b_ct);

        // final_ct = (shs + shr) - shs*(2*shr)
        this->evaluator->sub(a_plus_b_ct, a_mul_b_ct, final_ct);

        ind_cts.push_back(final_ct);
    }
    auto ind_compute_end = std::chrono::steady_clock::now();

    // cout << "[INFO] Client computed shs+shr-2*shs*shr for each share (ind_cts.size()=" << ind_cts.size() << ")." << endl;

    // --- 接下来：对 final_cts 中的每个 ciphertext 执行按位乘法，将客户端元素逐位乘上 final_ct，并进行分段（如果元素超过明文模数），然后随机置换并发送给服务器 ---
    // 我们将为每个 final_ct (对应一个 gamma_prime) 发送一个分组。每个分组格式为: [K(uint64_t), D(uint64_t), num_bins(uint64_t)] 头部 (写入一次), 然后对每个组写入: perm_plaintext, followed by D ciphertexts (每个 ciphertext 编码了所有槽的第 d 位数字，且已按 permuted 顺序排列)

    // K = final_cts.size(); num_bins = number of bins = 1 << log_poly_modulus_degree
    uint64_t K = ind_cts.size();
    uint64_t num_bins = (1ULL << params.log_poly_modulus_degree);
    uint64_t slot_count = this->batch_encoder->slot_count();
    if (num_bins > slot_count) num_bins = slot_count; // safety

    for (auto &ind_ct : ind_cts) {
        this->evaluator->mod_switch_to_inplace(ind_ct, this->context->last_context_data()->parms_id());
    }

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
     * 置换阶段概览：
     *   1. 使用固定的 bcs_permutation_ 对 ind_cts 进行密文置换。
     *   2. 将客户端元素按同一置换重排，再进行 digit 分段并与置换后的 ind 密文相乘。
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
            // 构造单一槽位掩码以选出源位置对应的指示器
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

            if (!permuted_initialized) {
                permuted_ind_cipher = std::move(isolated);
                permuted_initialized = true;
            } else {
                // 逐槽累加得到完整的置换后指示器密文
                this->evaluator->add_inplace(permuted_ind_cipher, isolated);
            }
        }

        if (!permuted_initialized) {
            throw std::runtime_error("failed to build permuted indicator ciphertext");
        }

    // 对每个 digit d，构造置换后的 digit_slots，并与 permuted_ind_cipher 相乘
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
            try {
                // 乘上掩码后的指示器以隐藏真实位置的明文 digit
                this->evaluator->multiply_plain(permuted_ind_cipher, digit_pt, masked_ct);
                // 直接保存到 data_stream（按原始顺序写入），发送给服务器进行解密与重构
                uint64_t bytes = masked_ct.save(this->data_stream);
                comm_otsss_bytes += bytes;
            } catch (const exception &e) {
                cerr << "[WARN] multiply_plain failed for group "<<k<<" digit "<<d<<": "<<e.what()<<"\n";
                try {
                    if (this->server && this->server->server_encryptor) {
                        Ciphertext zero_ct; this->server->server_encryptor->encrypt_zero(zero_ct);
                        uint64_t bytes = zero_ct.save(this->data_stream);
                        comm_otsss_bytes += bytes;
                    } else {
                        Ciphertext zero_ct; this->encryptor->encrypt_zero(zero_ct);
                        uint64_t bytes = zero_ct.save(this->data_stream);
                        comm_otsss_bytes += bytes;
                    }
                } catch (const exception &e2) {
                    cerr << "[ERROR] failed to create zero ciphertext: "<<e2.what()<<"\n";
                }
            }
        }
    }
    auto permute_mask_end = std::chrono::steady_clock::now();
    this->metrics->metrics_["time_extract_permute_mask"] = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(permute_mask_end - permute_mask_start).count());

    // 现在将 masked_stream 的内容发送给服务器并让服务器解密重构元素
    // 注意：server->receive_and_decrypt_masked 直接从流中读取二进制头和密文
    // 将读指针重置到流首部，确保服务器按正确顺序读取掩码数据
    this->data_stream.clear();
    this->data_stream.seekg(0, std::ios::beg);
    this->metrics->metrics_["comm_final_response"] = comm_otsss_bytes;
    uint64_t send_ms = 0;
    send_masked_payload_over_network(this->data_stream.str(), send_ms);
    auto it_online = this->metrics->metrics_.find("time_online_comm");
    if (it_online != this->metrics->metrics_.end()) {
        it_online->second += send_ms;
    } else {
        this->metrics->metrics_["time_online_comm"] = send_ms;
    }
    pending_masked_response_ = false;
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
}

// 将 Params 对象中的字段保存到 Metrics 对象中
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

// 运行完整的端到端协议流程
bool Client::run_protocol(Params params, bool _verbose)
{
    Timer time_setup_crypto, time_server_latency, time_extract_response;
    this->metrics = new Metrics();
    this->params_to_metrics(params); // 记录参数
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

    // --- 1. 客户端设置 ---
    time_setup_crypto.start();
        this->setup_crypto(params.log_poly_modulus_degree, params.coeff_bits, params.prime_bitlength, _verbose);
    this->metrics->metrics_["time_setup_crypto"] = time_setup_crypto.end_and_get();

    // --- 2. 发送公共参数和密钥 ---
    this->send_parameters_and_keys(debug_mode);
    this->server->load_parameters_and_keys(this->params_stream, debug_mode, _verbose);

    // --- 3. 准备、编码和加密查询 ---
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
            bcs_permutation_ = bcs::generate_permutation(permutation_bins, perm_rng);
        } else {
            bcs_permutation_.clear();
        }

    // 遍历 gamma 个哈希函数
    // for (uint64_t gamma_prime=0; gamma_prime<params.gamma; gamma_prime++){
        // 遍历所有仓 (bin)
        for (uint64_t bin_index=0;bin_index<bin_count;bin_index++){
            // 获取客户端元素 (这里是模拟的)
            uint64_t element = client_get(0, bin_index, params.effective_lambda);
            client_elements[bin_index] = element;
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

    if (params.task == circuitPSU) {
        auto shares = make_secret_shares(client_elements, kSharePadBits);
        client_sx_ = std::move(shares.first);
        client_sx_prime_ = std::move(shares.second);
    }

    // 加密并发送查询
    if (params.task == circuitPSU) {
        auto offline_comp_start = std::chrono::steady_clock::now();
        this->encrypt_and_send(input, _verbose);
        auto offline_comp_end = std::chrono::steady_clock::now();
        uint64_t offline_comp_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(offline_comp_end - offline_comp_start).count());
        this->metrics->metrics_["time_offline_comp"] += offline_comp_ms;
    } else if (params.task == PSU || params.task == PSUca_C) {
        auto offline_start = std::chrono::steady_clock::now();
        this->encrypt_and_send(input, _verbose);
        auto offline_end = std::chrono::steady_clock::now();
        uint64_t offline_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(offline_end - offline_start).count());
        this->metrics->metrics_["time_offline"] += offline_ms;
    } else if (params.task == PSUca_S) {
        auto offline_start = std::chrono::steady_clock::now();
        this->encrypt_and_send(input, _verbose);
        auto offline_end = std::chrono::steady_clock::now();
        uint64_t offline_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(offline_end - offline_start).count());
        this->metrics->metrics_["time_offline"] += offline_ms;
        this->metrics->metrics_["comm_offline"] += this->metrics->metrics_["comm_request"];
    } else {
        this->encrypt_and_send(input, _verbose);
    }

    if (params.task == circuitPSU) {
        this->server->prepare_secret_shares(params);
        this->server->start_syprime_service();
        uint64_t syprime_ms = 0;
        try {
            client_sy_prime_ = receive_syprime_over_network(syprime_ms);
            this->server->stop_syprime_service();
        } catch (...) {
            this->server->stop_syprime_service();
            throw;
        }
        this->metrics->metrics_["time_offline_comm"] += syprime_ms;
    }

    // --- 4. 调用服务器进行计算 ---
    bool need_permute_service = (params.task == circuitPSU);
    bool need_masked_service = (params.task != PSUca_C && params.task != PSUca_S);
    bool need_ca_mid_service = (params.task == PSUca_S);
    if (need_permute_service) {
        start_permute_share_service();
    }
    if (need_masked_service) {
        server->start_masked_service();
    }
    if (need_ca_mid_service) {
        server->start_psuca_mid_service();
    }
    time_server_latency.start();
    try {
        this->server->start_psu_service(params, static_cast<int>(input.size()), this->metrics, _verbose);
        uint64_t request_ms = 0;
        uint64_t response_ms = 0;
        std::string response = send_psu_request_over_network(this->data_stream.str(), request_ms, response_ms);
        this->data_stream.str(response);
        this->data_stream.clear();
        this->server->stop_psu_service();
        if (params.task == PSU || params.task == PSUca_C || params.task == PSUca_S) {
            this->metrics->metrics_["time_offline"] += request_ms;
        } else {
            this->metrics->metrics_["time_offline_comm"] += request_ms;
        }
        this->metrics->metrics_["time_online_comm"] = response_ms;
    } catch (...) {
        this->server->stop_psu_service();
        if (need_permute_service) {
            stop_permute_share_service();
        }
        if (need_masked_service) {
            server->stop_masked_service();
        }
        if (need_ca_mid_service) {
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
    if (need_permute_service) {
        stop_permute_share_service();
    }

    // --- 5. 接收并解密响应 ---
    int num_cts; // 根据任务类型，确定期望从服务器收到的密文数量
    switch (params.task){
        case PSU: num_cts = 2; break;
        case PSUca_C: num_cts = 1; break;
        case circuitPSU: num_cts = 1; break;
        default: num_cts = 1; break;
    }
    // debug print removed
    // 加载并解密响应
    time_extract_response.start();
    std::vector<Plaintext> _response_pts = this->load_and_decrypt(num_cts, params, _verbose);
    this->metrics->metrics_["time_extract_response"] = time_extract_response.end_and_get();
    finalize_masked_response();

    if (need_masked_service) {
        server->stop_masked_service();
    }
    if (need_ca_mid_service) {
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