//
// Created by Administrator on 2025/9/23.
//

#ifndef FEUPSU_UTILS_H
#define FEUPSU_UTILS_H

#include "seal/seal.h"
#include "omp.h"
#include <cstdint>
#include <string>

using namespace std;

class Timer {
public:
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point end_;
    Timer();
    void start();
    void end();
    long double end_and_get();
    void reset();
    long double get_time_in_milliseconds();
};

class Metrics{
public:
    map<string, uint64_t> metrics_;
};

enum Task{
    PSU=0,
    PSUCardinality=1,
    circuitPSU=2,
};

float log2_choose(uint64_t n, uint64_t k);
vector<uint64_t> get_cw(uint64_t __number, uint64_t encoding_size, uint64_t hamming_weight, bool __verbose);

struct EEQParams {
    uint64_t hw;
    uint64_t L;
    uint64_t H;
    vector<uint64_t> coefficients;
};

EEQParams build_eeq_params(uint64_t hw, uint64_t plain_modulus);



class Params{
public:
    uint64_t log_poly_modulus_degree;
    vector<seal::Modulus> coeff_bits;
    uint64_t prime_bitlength;

    Task task;
    uint64_t mu;
    uint64_t effective_lambda;
    uint64_t hw;

    uint64_t ell;
    uint64_t server_set;
    uint64_t client_set;
    uint64_t client_bin_offset;

    Params();
    Params(Task task, uint64_t server_set, uint64_t effective_lambda, uint64_t hw, uint64_t client_set = 0);
};

namespace net {
int create_listen_socket(uint16_t port, int backlog = 1);
int accept_client(int listen_fd);
int connect_socket(const std::string& host, uint16_t port);
bool send_all(int fd, const void* data, size_t len);
bool recv_all(int fd, void* data, size_t len);
}

#endif //FEUPSU_UTILS_H
