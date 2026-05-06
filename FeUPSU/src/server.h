//
// Created by Administrator on 2025/9/23.
//

#ifndef MAIN_SERVER_H
#define MAIN_SERVER_H

#include "bcs.h"
#include "bcs_osn.h"
#include "seal/seal.h"
#include "utils.h"

#include <cstdint>
#include <atomic>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

class Client;

class Server {
public:
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    // SEAL 同态加密库的对象
    seal::EncryptionParameters* enc_params; // 加密参数
    seal::SEALContext* context;             // SEAL 上下文
    seal::Evaluator* evaluator;             // 评估器 (用于密文计算)
    seal::RelinKeys* rlk_keys_server;     // 重线性化密钥
    seal::GaloisKeys* gal_keys_server;    // Galois 密钥 (用于密文旋转)
    seal::PublicKey* public_key;            // 公钥 (用于加密)
    seal::Encryptor* encryptor;             // 加密器 (使用公钥)
    seal::BatchEncoder* batch_encoder;      // 批处理器
    seal::PublicKey server_public_key;
    seal::SecretKey server_secret_key;
    seal::Encryptor* server_encryptor;
    Metrics* metrics = nullptr;            // 指向当前会话的指标记录器

    // circuitPSU secret sharing buffers
    std::vector<uint64_t> server_sy_;
    std::vector<uint64_t> server_sy_prime_;
    std::vector<uint64_t> server_shr_bits_;
    std::vector<uint64_t> server_sx_ot_;
    int64_t psuca_shf_sum_ = 0;
    bool psuca_shf_valid_ = false;

    // 仅在调试模式下可用，用于检查密文中的噪声
    seal::Decryptor* noise_calculator;

    Client* client_ref_ = nullptr;

    // --- 核心方法 ---
    void initialize(uint64_t poly_modulus_degree = 8192);
    void initialize_params_with_input(stringstream& parms_stream);
    // 从流中加载加密参数和密钥
    void load_parameters_and_keys(stringstream& params_stream, bool debug_mode=false, bool _verbose=true);
    // 从流中加载客户端加密的输入数据
    vector<seal::Ciphertext> load_inputs(stringstream& data_stream, int num_input_cts);
    // 将计算结果序列化并写入数据流
    void send_results(vector<seal::Ciphertext>& results, stringstream& data_stream);
    // 接收并解密客户端发送的掩码密文（分割后的 digits），返回重构的元素值向量
    vector<vector<uint64_t>> receive_and_decrypt_masked(stringstream& data_stream);
    // 模拟服务器数据集中的元素
    uint64_t server_get(uint64_t mu_prime, uint64_t bin_index, uint64_t effective_lambda);
    // 执行服务器端的核心同态计算
    void do_server_computation(stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool);
    seal::Plaintext sample_cardinality_mask(uint64_t active_slots, uint64_t server_set);
    void prepare_secret_shares(const Params& params);
    void finalize_psuca_s(int64_t ca_mid, uint64_t server_set);

    void set_client(Client* client);
    void start_psu_service(const Params& params, int num_input_cts, Metrics* metrics, bool verbose);
    void stop_psu_service();
    void start_masked_service();
    void stop_masked_service();
    void start_syprime_service();
    void stop_syprime_service();
    void start_psuca_mid_service();
    void stop_psuca_mid_service();

private:
    std::vector<uint64_t> request_permute_share_over_network(
        const std::vector<uint64_t>& rnd,
        const std::string& host,
        uint16_t port,
        uint64_t& request_bytes,
        uint64_t& response_bytes,
        uint64_t& remote_compute_us);

    std::string permute_share_host_ = "127.0.0.1";
    uint16_t permute_share_port_ = 39001;

    std::atomic<bool> psu_stop_{false};
    std::thread psu_thread_;
    int psu_listen_fd_ = -1;
    uint16_t psu_port_ = 39002;
    std::string psu_host_ = "127.0.0.1";
    Params psu_params_{};
    int psu_num_input_cts_ = 0;
    bool psu_verbose_ = false;
    Metrics* psu_metrics_ = nullptr;
    std::mutex psu_mutex_;

    std::atomic<bool> masked_stop_{false};
    std::thread masked_thread_;
    int masked_listen_fd_ = -1;
    uint16_t masked_port_ = 39003;
    std::string masked_host_ = "127.0.0.1";

    std::atomic<bool> syprime_stop_{false};
    std::thread syprime_thread_;
    int syprime_listen_fd_ = -1;
    uint16_t syprime_port_ = 39004;
    std::string syprime_host_ = "127.0.0.1";

    std::atomic<bool> psuca_mid_stop_{false};
    std::thread psuca_mid_thread_;
    int psuca_mid_listen_fd_ = -1;
    uint16_t psuca_mid_port_ = 39006;
    std::string psuca_mid_host_ = "127.0.0.1";

    void serve_psu_requests();
    void handle_psu_connection(int conn_fd);
    void serve_masked_requests();
    void handle_masked_connection(int conn_fd);
    void serve_syprime_requests();
    void handle_syprime_connection(int conn_fd);
    void serve_psuca_mid_requests();
    void handle_psuca_mid_connection(int conn_fd);
};


#endif //MAIN_SERVER_H