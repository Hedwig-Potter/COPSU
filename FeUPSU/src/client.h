#ifndef FEUPSU_CLIENT_H
#define FEUPSU_CLIENT_H

#include "seal/seal.h"
#include "utils.h"
#include "config.hpp"
#include "network.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

class Server;

class Client {
public:
    std::unique_ptr<seal::EncryptionParameters> enc_params;
    std::shared_ptr<seal::SEALContext> context;
    std::unique_ptr<seal::KeyGenerator> keygen;
    seal::SecretKey secret_key;
    std::unique_ptr<seal::Evaluator> evaluator;
    std::unique_ptr<seal::Encryptor> encryptor;
    std::unique_ptr<seal::BatchEncoder> batch_encoder;
    std::unique_ptr<seal::GaloisKeys> gal_keys_local;

    seal::PublicKey server_public_key;
    std::stringstream params_stream;
    std::stringstream data_stream;

    Server* server = nullptr;
    Metrics* metrics = nullptr;

    std::vector<uint32_t> bcs_permutation_;
    std::vector<uint64_t> bcs_client_share_;
    std::vector<uint64_t> client_sx_;
    std::vector<uint64_t> client_sx_prime_;
    std::vector<uint64_t> client_sy_prime_;
    std::vector<uint64_t> circuit_output_share_;

    Client();
    explicit Client(Server* _server);
    ~Client();
    void set_server_endpoint(const std::string& host, uint16_t psu_port = 39002);

    void params_to_metrics(Params params);
    uint64_t client_get(uint64_t gamma_prime, uint64_t bin_index, uint64_t effective_lambda);
    void setup_crypto(uint64_t log_poly_modulus_degree, std::vector<seal::Modulus> coeff_bits, uint64_t prime_bitlength = 20, bool _verbose = true);
    void send_parameters_and_keys(bool debug_mode = false);
    void encrypt_and_send(std::vector<seal::Plaintext>& plaintexts, bool _verbose);
    bool run_protocol(Params params, bool _verbose = true);
    std::vector<seal::Plaintext> load_and_decrypt(int num_cts, Params params, bool _verbose = false);

    std::vector<uint64_t> execute_permute_share(const std::vector<uint64_t>& rnd_bits);
    void start_permute_share_service();
    void stop_permute_share_service();
    void serve_permute_share_requests();

private:
    psu::config::NetworkConfig net_cfg_;
    bool remote_server_ = false;
    uint64_t setup_session_id_ = 0;
    std::unique_ptr<psu::network::SocketServer> permute_server_;
    int permute_listen_fd_ = -1;
    std::atomic<bool> permute_share_stop_{false};

    uint64_t decode_cardinality(const seal::Plaintext& pt, uint64_t num_bins);
    std::string send_psu_request_over_network(const std::string& payload, uint64_t& request_ms, uint64_t& response_ms);
    uint64_t send_setup_over_network(uint64_t& setup_round_ms);
    void send_masked_payload_over_network(const std::string& payload, uint64_t& send_ms);
    void send_psuca_mid_over_network(int64_t ca_mid, uint64_t& send_ms);
    std::vector<uint64_t> receive_syprime_over_network(uint64_t& recv_ms);
    void finalize_masked_response();
    void finalize_phase_metrics(Params params);
    
    void handle_permute_share_connection(int conn_fd);

    std::atomic<uint64_t> permute_share_time_us_{0};
    std::atomic<uint64_t> permute_share_invocations_{0};
    std::chrono::steady_clock::time_point otsss_start_;
    bool pending_masked_response_ = false;
    bool pending_otsss_timing_ = false;
    bool record_otsss_time_ = false;
};

#endif // FEUPSU_CLIENT_H
