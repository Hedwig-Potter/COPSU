//
// Created by Administrator on 2025/9/23.
//

#include "server.h"
#include "client.h"

#include <cassert>
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

// 服务端主要负责加载客户端密钥、构造自身密钥、执行同态定重码匹配并生成
// permute-share 协议所需的随机份额。这里的注释按照协议流程分步说明关键逻辑。

// 建立回调引用，以便在 permute-share 阶段调用客户端逻辑
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
    receive_and_decrypt_masked(stream);

    uint64_t resp_len_be = 0;
    if (!net::send_all(conn_fd, &resp_len_be, sizeof(resp_len_be))) {
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

// 接收并解密来自客户端的掩码密文（分段后的 digits），返回重构的元素值向量
vector<vector<uint64_t>> Server::receive_and_decrypt_masked(stringstream& data_stream) {
    Timer decrypt_timer;
    uint64_t K, D, m;
    data_stream.read(reinterpret_cast<char*>(&K), sizeof(K));
    data_stream.read(reinterpret_cast<char*>(&D), sizeof(D));
    data_stream.read(reinterpret_cast<char*>(&m), sizeof(m));

    // all_elements[k][i] 对应第 k 个分组、第 i 个仓的重构值
    vector<vector<uint64_t>> all_elements(K, vector<uint64_t>(m, 0));
    Decryptor decryptor(*context, this->server_secret_key);
    decrypt_timer.start();
    for (uint64_t k = 0; k < K; ++k) {
        // if (k % 50 == 0) {
        //     cout << "[TRACE][server] decrypting group " << k << "/" << K << endl;
        // }
        // 直接读取 D 个 ciphertext（按原始槽顺序），每个 ciphertext 的槽 i 对应原始第 i 个元素的该 digit
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
// 解析客户端发来的所有 SEAL 参数与密钥，并初始化上下文
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
    //     cout << "[DEBUG] noise_calculator initialized" << endl;
        // } catch(...){}
    // }
    if (debug_mode){
        SecretKey secret_key;
        secret_key.load(*context, params_stream);
        this->noise_calculator = new Decryptor(*context, secret_key);
    }
}

// 从流中加载客户端的查询密文
// 读取客户端加密的定重码向量
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
// 将服务器计算出的密文写入 data_stream，供网络发送
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
// 同态核心：计算服务器集合成员是否出现在客户端集合中，并生成 permute-share 所需份额
void Server::do_server_computation(stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool _verbose){
    Timer server_time;
    vector<Ciphertext> inputs = load_inputs(data_stream, num_input_cts);

    vector<Ciphertext> results;//

    this->metrics = metrics;

    // --- 1. 服务器生成自己的密钥对 ---
    // 使用与客户端相同的加密参数来确保兼容性
    Timer server_keygen_timer;
    server_keygen_timer.start();
    KeyGenerator server_keygen(*context);
    this->server_secret_key = server_keygen.secret_key();
    server_keygen.create_public_key(this->server_public_key);
    this->server_encryptor = new Encryptor(*context, this->server_public_key);
    uint64_t server_keygen_ms = static_cast<uint64_t>(server_keygen_timer.end_and_get());
    if (metrics) {
        metrics->metrics_["time_server_keygen_ms"] = server_keygen_ms;
    }

    server_time.start();

    // --- 参数提取 ---
    uint64_t bins = 1 << params.log_poly_modulus_degree;
    uint64_t mu = params.mu;
    uint64_t ell = params.ell;
    uint64_t hw = params.hw;
    uint64_t effective_lambda = params.effective_lambda;
    // uint64_t label_ct_size=params.label_ct_size;
    // assert( gamma*ell == inputs.size() );

    // --- 核心计算逻辑 ---
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
                uint64_t element = server_get(i+1, bin_index, effective_lambda);
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
                    try {
                        this->evaluator->multiply_plain(inputs[k], operand_pt, _temp[k]);
                    } catch (const std::exception &ex) {
                        std::cerr << "[DEBUG] multiply_plain failed: " << ex.what() << std::endl;
                        throw;
                    }
                }
            }

            // 3. 将点积结果同态相加，得到 E(sum(x_i * y_i))
            Ciphertext _ct;
            this->evaluator->add_many(_temp, _ct);

            // 4. 使用 EEQ 多项式判等（新增，删除了上面4.）
            Ciphertext acc(zero_pt);
            // 初始化多项式累加器：在最高层先加上常数项
            try {
                this->evaluator->add_plain_inplace(acc, eeq_coeff_plain.back());
            } catch (const std::exception &ex) {
                std::cerr << "[DEBUG] add_plain_inplace(init) failed: " << ex.what() << std::endl;
                throw;
            }
            for (int j = static_cast<int>(eeq_coeff_plain.size()) - 2; j >= 0; --j){
                this->evaluator->mod_switch_to_inplace(acc, _ct.parms_id());
                try {
                    this->evaluator->multiply_inplace(acc, _ct);
                } catch (const std::exception &ex) {
                    std::cerr << "[DEBUG] multiply_inplace poly failed: " << ex.what() << std::endl;
                    throw;
                }
                this->evaluator->relinearize_inplace(acc, *rlk_keys_server);
                this->evaluator->mod_switch_to_inplace(acc, _ct.parms_id());
                Plaintext coeff_at_level = eeq_coeff_plain[j];
                try {
                    this->evaluator->add_plain_inplace(acc, coeff_at_level);
                } catch (const std::exception &ex) {
                    std::cerr << "[DEBUG] add_plain_inplace poly failed: " << ex.what() << std::endl;
                    throw;
                }
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

    // 8. 计算 ind = 1 - indicator_sum（明文 1 与密文指示器的同态运算）
    uint64_t slot_count = this->batch_encoder->slot_count();
    std::vector<uint64_t> ones(slot_count, 1ULL);
    Plaintext ones_plain;
    this->batch_encoder->encode(ones, ones_plain);

    Ciphertext ind_cipher(indicators_sum);
    this->evaluator->negate_inplace(ind_cipher);
    this->evaluator->add_plain_inplace(ind_cipher, ones_plain);
    // 调试打印：使用客户端私钥解密 ind_cipher 并统计其中的 1 数量（295-330）
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

    // 9. server 生成随机向量 rnd，作为 permute-share 的输入并用于 ind_hat
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> rnd_dist(0ULL, plain_mod - 1ULL);
    std::vector<uint64_t> rnd(num_bins, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        rnd[i] = rnd_dist(rng);
    }

    // 10. 通过网络请求客户端执行 permute+share，并返回服务器份额
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
    Timer permute_network_timer;
    permute_network_timer.start();
    std::vector<uint64_t> server_share = request_permute_share_over_network(
        rnd, ps_host, ps_port, request_bytes, response_bytes, remote_compute_us);
    if (metrics) {
        metrics->metrics_["time_permute_share_network_ms"] = static_cast<uint64_t>(permute_network_timer.end_and_get());
        metrics->metrics_["comm_permute_share_request_bytes"] = request_bytes;
        metrics->metrics_["comm_permute_share_response_bytes"] = response_bytes;
        metrics->metrics_["time_permute_share_client_compute_us"] = remote_compute_us;
    }
    if (server_share.size() < num_bins) {
        server_share.resize(num_bins, 0ULL);
    }
    std::vector<uint64_t> share_slots(slot_count, 0ULL);
    for (size_t i = 0; i < server_share.size() && i < share_slots.size(); ++i) {
        share_slots[i] = server_share[i] % plain_mod;
    }

    // 12. server 对 s_pis 进行 batching 并使用自身公钥 pk_s 加密，得到 s_pis_pks
    Timer batch_encrypt_timer;
    batch_encrypt_timer.start();
    Plaintext share_plain;
    this->batch_encoder->encode(share_slots, share_plain);
    Ciphertext share_cipher;
    this->server_encryptor->encrypt(share_plain, share_cipher);
    uint64_t batch_encrypt_ms = static_cast<uint64_t>(batch_encrypt_timer.end_and_get());
    if (metrics) {
        metrics->metrics_["time_permute_share_batch_encrypt_ms"] = batch_encrypt_ms;
    }

    // 13. 计算 ind_hat = ind + rnd（密文 + 明文，同态加法）
    std::vector<uint64_t> rnd_slots(slot_count, 0ULL);
    for (uint64_t i = 0; i < num_bins; ++i) {
        rnd_slots[i] = rnd[i];
    }
    Plaintext rnd_plain;
    this->batch_encoder->encode(rnd_slots, rnd_plain);

    Ciphertext ind_hat(ind_cipher);
    this->evaluator->add_plain_inplace(ind_hat, rnd_plain);

    // -------------------- 网络打包 --------------------
    data_stream.str("");
    data_stream.clear();

    uint64_t ind_cipher_count = 1;
    data_stream.write(reinterpret_cast<const char*>(&ind_cipher_count), sizeof(ind_cipher_count));
    ind_hat.save(data_stream);

    uint64_t share_cipher_count = 1;
    data_stream.write(reinterpret_cast<const char*>(&share_cipher_count), sizeof(share_cipher_count));
    share_cipher.save(data_stream);

    // 记录服务器端总耗时，方便调试和性能分析
    server_time.end();
    uint64_t server_total_ms = server_time.get_time_in_milliseconds();
    uint64_t server_adjusted_ms = server_total_ms;
    if (batch_encrypt_ms <= server_adjusted_ms) {
        server_adjusted_ms -= batch_encrypt_ms;
    } else {
        server_adjusted_ms = 0;
    }
    metrics->metrics_["time_server"] = server_adjusted_ms;

    // debug print removed

        // The second send_results call is removed as it is redundant

}
