//
// Created by Administrator on 2025/9/23.
//

#ifndef FEUPSU_CLIENT_H
#define FEUPSU_CLIENT_H

#include "seal/seal.h"
#include "utils.h"
#include "server.h"
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <sstream>

class Client {
public:
    // SEAL 同态加密库的对象
    seal::EncryptionParameters* enc_params; // 加密参数
    seal::SEALContext* context;             // SEAL 上下文
    seal::KeyGenerator* keygen;             // 密钥生成器
    seal::SecretKey secret_key;             // 私钥 (客户端持有)
    seal::Evaluator* evaluator;             // 评估器 (用于密文计算)
    seal::Encryptor* encryptor;             // 加密器
    seal::BatchEncoder* batch_encoder;      // 批处理器 (用于将多个数打包到一个明文中)
    seal::GaloisKeys* gal_keys_local;       // 客户端持有的 Galois 密钥，支持在密文中执行行/列旋转实现槽置换
    // --- 新增成员变量 ---
    // 用于存储服务器发送过来的公钥
    seal::PublicKey server_public_key;
    // 字符串流，用于序列化和传输数据
    std::stringstream params_stream; // 用于传输加密参数和公钥
    std::stringstream data_stream;   // 用于传输加密的数据

    // 指向服务器对象的指针
    Server* server;
    // 指向性能指标对象的指针
    Metrics* metrics;

    std::vector<uint32_t> bcs_permutation_;
    std::vector<uint64_t> bcs_client_share_;
    std::vector<uint64_t> execute_permute_share(const std::vector<uint64_t>& rnd_bits);

    // --- 构造函数 ---
    Client(){
        gal_keys_local = nullptr; // 初始化本地 Galois 密钥指针
        server = new Server();
        if (server) {
            server->set_client(this);
        }
    }

    Client(Server* _server){
        gal_keys_local = nullptr; // 初始化本地 Galois 密钥指针
        server = _server;
        if (server) {
            server->set_client(this);
        }
    }

    // --- 核心方法 ---
    // 将协议参数记录到性能指标中
    void params_to_metrics(Params params);
    // 客户端生成元素值的函数 (模拟)
    uint64_t client_get(uint64_t gamma_prime, uint64_t bin_index, uint64_t effective_lambda);
    // 设置同态加密环境
    void setup_crypto(uint64_t log_poly_modulus_degree, vector<seal::Modulus> coeff_bits, uint64_t prime_bitlength=20, bool _verbose = true);
    // 序列化并发送加密参数和公钥给服务器
    void send_parameters_and_keys(bool debug_mode=false);
    // 加密明文向量并将其序列化到数据流中
    void encrypt_and_send(vector<seal::Plaintext>& plaintexts, bool _verbose);
    // 运行完整的 PSI 协议流程
    bool run_protocol(Params params, bool _verbose = true);
    // 从数据流中加载服务器的响应密文并解密，并在需要时使用 params 信息构建 client 元素
    vector<seal::Plaintext> load_and_decrypt(int num_cts, Params params, bool _verbose = false);

    void start_permute_share_service();
    void stop_permute_share_service();

private:
    void serve_permute_share_requests();
    void handle_permute_share_connection(int conn_fd);
    std::string send_psu_request_over_network(const std::string& payload,
                                              uint64_t& request_ms,
                                              uint64_t& response_ms);
    void send_masked_payload_over_network(const std::string& payload, uint64_t& send_ms);

    uint16_t permute_share_port_ = 39001;
    std::thread permute_share_thread_;
    std::atomic<bool> permute_share_stop_{false};
    int permute_listen_fd_ = -1;
};


#endif //FEUPSU_CLIENT_H