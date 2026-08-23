#ifndef MAIN_SERVER_H
#define MAIN_SERVER_H

#include "bcs.h"
#include "bcs_osn.h"
#include "seal/seal.h"
#include "utils.h"
#include "config.hpp"
#include "network.hpp"

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

class Client;

class Server {
public:
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    std::unique_ptr<seal::EncryptionParameters> enc_params;
    std::shared_ptr<seal::SEALContext> context;
    std::unique_ptr<seal::Evaluator> evaluator;
    std::unique_ptr<seal::RelinKeys> rlk_keys_server;
    std::unique_ptr<seal::GaloisKeys> gal_keys_server;
    std::unique_ptr<seal::PublicKey> public_key;
    std::unique_ptr<seal::Encryptor> encryptor;
    std::unique_ptr<seal::BatchEncoder> batch_encoder;
    
    seal::PublicKey server_public_key;
    seal::SecretKey server_secret_key;
    std::unique_ptr<seal::Encryptor> server_encryptor;
    std::unique_ptr<seal::Decryptor> noise_calculator;

    Metrics* metrics = nullptr;

    std::vector<uint64_t> server_sy_;
    std::vector<uint64_t> server_sy_prime_;
    std::vector<uint64_t> server_shs_bits_;
    // Per-slot additive pad used by the circuitPSU ciphertext-refresh round.
    // It is server-only and is replaced for every protocol invocation.
    std::vector<uint64_t> circuit_refresh_mask_;
    std::vector<uint64_t> circuit_output_share_;
    std::vector<uint64_t> circuit_pre_shuffle_share_; // retained only for local test-mode checks
    int64_t psuca_shf_sum_ = 0;
    uint64_t psuca_plain_mod_ = 0;
    uint64_t psuca_scale_inv_ = 0;
    bool psuca_shf_valid_ = false;
    // One-time pad used only to let the client refresh a noise-exhausted EEQ
    // ciphertext without learning its slots. Replaced by an independent final
    // pad before the shuffled ciphertext is returned.
    std::vector<uint64_t> psuca_refresh_mask_;

    Client* client_ref_ = nullptr;

    Server() = default;
    ~Server();

    void initialize(uint64_t poly_modulus_degree = 8192);
    void initialize_params_with_input(std::stringstream& parms_stream);
    uint64_t load_parameters_and_keys(std::stringstream& params_stream, bool debug_mode = false, bool _verbose = true);
    std::vector<seal::Ciphertext> load_inputs(std::stringstream& data_stream, int num_input_cts);
    void send_results(std::vector<seal::Ciphertext>& results, std::stringstream& data_stream);
    std::vector<std::vector<uint64_t>> receive_and_decrypt_masked(std::stringstream& data_stream);
    uint64_t server_get(uint64_t mu_prime, uint64_t bin_index,
                        uint64_t effective_lambda, uint64_t bin_count = 0);
    void do_server_computation(std::stringstream& data_stream, int num_input_cts, Params params, Metrics* metrics, bool verbose);
    seal::Plaintext sample_cardinality_mask(uint64_t active_slots, uint64_t server_set);
    void prepare_secret_shares(const Params& params);
    void finalize_psuca_s(int64_t ca_mid, uint64_t server_set, uint64_t client_bins);

    void set_client(Client* client);

    void start_psu_service(const Params& params, int num_input_cts, Metrics* metrics, bool verbose);
    void stop_psu_service();
    void start_masked_service();
    void stop_masked_service();
    void start_syprime_service();
    void stop_syprime_service();
    void start_psuca_mid_service();
    void stop_psuca_mid_service();
    void start_circuit_service();
    void stop_circuit_service();

private:
    psu::config::NetworkConfig net_cfg_;
    void serve_psu_requests();
    void serve_masked_requests();
    void serve_syprime_requests();
    void serve_psuca_mid_requests();

    // Apply a server-chosen arbitrary random permutation without decrypting
    // the BFV ciphertext. The returned ciphertext remains under the client's
    // key. Call this only on the refreshed PSUca ciphertext.
    seal::Ciphertext permute_psuca_slots(const seal::Ciphertext& input,
                                         uint64_t active_slots);

    std::unique_ptr<psu::network::SocketServer> psu_server_;
    std::unique_ptr<psu::network::SocketServer> masked_server_;
    std::unique_ptr<psu::network::SocketServer> syprime_server_;
    std::unique_ptr<psu::network::SocketServer> psuca_mid_server_;
    std::unique_ptr<psu::network::SocketServer> circuit_server_;
    std::thread syprime_thread_;
    std::thread psuca_mid_thread_;
    std::mutex psu_mutex_;
    Metrics service_metrics_;
    uint64_t setup_session_id_ = 0;
    bool setup_session_valid_ = false;
    std::atomic<bool> syprime_stop_{false};
    std::atomic<bool> psuca_mid_stop_{false};
    int psu_listen_fd_ = -1;
    int masked_listen_fd_ = -1;
    int syprime_listen_fd_ = -1;
    int psuca_mid_listen_fd_ = -1;
    std::atomic<bool> psu_stop_{false};
    std::atomic<bool> masked_stop_{false};
    std::string syprime_host_ = "127.0.0.1";
    std::string psuca_mid_host_ = "127.0.0.1";
    uint16_t psu_port_ = 39002;
    uint16_t masked_port_ = 39003;
    uint16_t syprime_port_ = 39005;
    uint16_t psuca_mid_port_ = 39006;

    Params psu_params_{};
    int psu_num_input_cts_ = 0;
    bool psu_verbose_ = false;
    Metrics* psu_metrics_ = nullptr;

    std::vector<uint64_t> request_permute_share_over_network(
        const std::vector<uint64_t>& rnd,
        const std::string& host,
        uint16_t port,
        uint64_t& request_bytes,
        uint64_t& response_bytes,
        uint64_t& remote_compute_us);

    void handle_psu_connection(int conn_fd);
    void handle_masked_connection(int conn_fd);
    void handle_syprime_connection(int conn_fd);
    void handle_psuca_mid_connection(int conn_fd);
    void handle_circuit_connection(int conn_fd);
};

#endif // MAIN_SERVER_H
