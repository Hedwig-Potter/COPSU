//
// Created by Administrator on 2025/9/23.
//

#ifndef MAIN_SERVER_H
#define MAIN_SERVER_H

#include "seal/seal.h"
#include "utils.h"
#include "bcs.h"
#include "bcs_osn.h"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <vector>
#include <sstream>

using namespace std;

class Client;

class Server {
public:
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    seal::EncryptionParameters* enc_params;
    seal::SEALContext* context;
    seal::Evaluator* evaluator;
    seal::RelinKeys* rlk_keys_server;
    seal::GaloisKeys* gal_keys_server;
    seal::PublicKey* public_key;
    seal::Encryptor* encryptor;
    seal::BatchEncoder* batch_encoder;
    seal::PublicKey server_public_key;
    seal::SecretKey server_secret_key;
    seal::Encryptor* server_encryptor;
    seal::Decryptor* noise_calculator;
    Metrics* metrics = nullptr;

    Client* client_ref_ = nullptr;

    void initialize(uint64_t poly_modulus_degree = 8192);
    void initialize_params_with_input(stringstream& parms_stream);
    uint64_t load_parameters_and_keys(stringstream& params_stream, bool debug_mode=false, bool _verbose=true);
    vector<seal::Ciphertext> load_inputs(stringstream& data_stream, int num_input_cts);
    void send_results(vector<seal::Ciphertext>& results, stringstream& data_stream);
    vector<vector<uint64_t>> receive_and_decrypt_masked(stringstream& data_stream);
    uint64_t server_get(uint64_t mu_prime, uint64_t bin_index,
                        uint64_t effective_lambda, uint64_t bin_count);
    void do_server_computation(stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool);

    void set_client(Client* client);
    void start_psu_service(const Params& params, int num_input_cts, Metrics* metrics, bool verbose);
    void stop_psu_service();
    void start_masked_service();
    void stop_masked_service();

private:
    std::vector<uint64_t> request_permute_share_over_network(
        const std::vector<uint64_t>& rnd,
        const std::string& host,
        uint16_t port,
        uint64_t& request_bytes,
        uint64_t& response_bytes,
        uint64_t& remote_compute_us,
        uint64_t& osn_comm_bytes,
        uint64_t& local_compute_ms);

    std::string permute_share_host_ = "127.0.0.1";
    uint16_t permute_share_port_ = 39001;
    uint16_t permute_osn_port_ = 39004;

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
    Metrics service_metrics_;
    uint64_t setup_session_id_ = 0;
    bool setup_session_valid_ = false;

    std::atomic<bool> masked_stop_{false};
    std::thread masked_thread_;
    int masked_listen_fd_ = -1;
    uint16_t masked_port_ = 39003;
    std::string masked_host_ = "127.0.0.1";

    void serve_psu_requests();
    void handle_psu_connection(int conn_fd);
    void serve_masked_requests();
    void handle_masked_connection(int conn_fd);
};


#endif //MAIN_SERVER_H
