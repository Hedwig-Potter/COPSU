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
    seal::EncryptionParameters* enc_params;
    seal::SEALContext* context;
    seal::KeyGenerator* keygen;
    seal::SecretKey secret_key;
    std::unique_ptr<seal::GaloisKeys> gal_keys_local;
    seal::Evaluator* evaluator;
    seal::Encryptor* encryptor;
    seal::BatchEncoder* batch_encoder;
    seal::PublicKey server_public_key;
    std::stringstream params_stream;
    std::stringstream data_stream;

    Server* server;
    Metrics* metrics;

    std::vector<uint32_t> bcs_permutation_;
    std::vector<uint64_t> bcs_client_share_;

    Client(){
        server = nullptr;
        remote_server_ = true;
    }

    void set_server_endpoint(const std::string& host, uint16_t psu_port = 39002);

    Client(Server* _server){
        server = _server;
        if (server) {
            server->set_client(this);
        }
    }

    void params_to_metrics(Params params);
    uint64_t client_get(uint64_t gamma_prime, uint64_t bin_index, uint64_t effective_lambda);
    void setup_crypto(uint64_t log_poly_modulus_degree, vector<seal::Modulus> coeff_bits, uint64_t prime_bitlength=20, bool _verbose = true);
    void send_parameters_and_keys(bool debug_mode=false);
    void encrypt_and_send(vector<seal::Plaintext>& plaintexts, bool _verbose);
    bool run_protocol(Params params, bool _verbose = true);
    vector<seal::Plaintext> load_and_decrypt(int num_cts, Params params, bool _verbose = false);

    void start_permute_share_service();
    void stop_permute_share_service();

private:
    void serve_permute_share_requests();
    void handle_permute_share_connection(int conn_fd);
    std::string send_psu_request_over_network(const std::string& payload,
                                              uint64_t& request_ms,
                                              uint64_t& response_ms);
    void send_setup_over_network(uint64_t& setup_round_ms,
                                 uint64_t& server_load_ms,
                                 uint64_t& server_keygen_ms);
    void send_masked_payload_over_network(const std::string& payload, uint64_t& send_ms);

    uint16_t permute_share_port_ = 39001;
    uint16_t permute_osn_port_ = 39004;
    std::thread permute_share_thread_;
    std::atomic<bool> permute_share_stop_{false};
    int permute_listen_fd_ = -1;
    std::string server_host_ = "127.0.0.1";
    uint16_t server_port_ = 39002;
    bool remote_server_ = false;
    uint64_t setup_session_id_ = 0;
    Params current_request_params_{};
};


#endif //FEUPSU_CLIENT_H
