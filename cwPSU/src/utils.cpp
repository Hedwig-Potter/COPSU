//
// Created by Administrator on 2025/9/23.
//

#include "utils.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;
using namespace seal;

Timer::Timer(){
    start_ = chrono::steady_clock::now();
    end_ = chrono::steady_clock::now();
}

void Timer::start(){
    start_ = chrono::steady_clock::now();
}

void Timer::end(){
    end_ = chrono::steady_clock::now();
}

long double Timer::end_and_get(){
    end_ = chrono::steady_clock::now();
    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end_ - start_);
    return elapsed.count();
}

long double Timer::get_time_in_milliseconds(){
    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end_ - start_);
    return elapsed.count();
}

float log2_choose(uint64_t n, uint64_t k) {
    if (k > n) {
        return 0;
    }
    float r = 0.0;
    for (uint64_t d = 1; d <= k; ++d) {
        r += log2(n--)-log2(d);
    }
    return r;
}

// Saturate at 2^64. The fixed-weight code space may be 128 bits, while the
// element rank is uint64_t; values above this threshold must not wrap around.
unsigned __int128 choose(uint64_t n, uint64_t k) {
    if (k > n) {
        return 0;
    }
    constexpr unsigned __int128 limit = static_cast<unsigned __int128>(UINT64_MAX) + 1;
    unsigned __int128 r = 1;
    for (uint64_t d = 1; d <= k; ++d) {
        r *= n--;
        r /= d;
        if (r >= limit) return limit;
    }
    return r;
}

vector<uint64_t> get_cw(uint64_t __number, uint64_t encoding_size, uint64_t hamming_weight, bool __verbose){
    vector<uint64_t> ans(encoding_size, 0ULL);
    unsigned __int128 mod_size = choose(encoding_size, hamming_weight);
    unsigned __int128 rank = __number;
    if (rank >= mod_size){
        if (__verbose){
            cout << "Overflow occurred, everything okay?" << endl;
            cout << __number << " code-space-too-small" << endl;
        }
        rank %= mod_size;
    }
    unsigned __int128 remainder = rank;
    uint64_t k_prime = hamming_weight;
    for (long pointer=encoding_size-1; pointer>=0; pointer--){
        if (remainder >= choose(pointer, k_prime)){
            ans[pointer] = 1ULL;
            remainder -= choose(pointer, k_prime);
            k_prime -= 1;
            if (k_prime == 0) break;
        }
    }
    return ans;
}
namespace {
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t mod){
    uint64_t res = a + b;
    if (res >= mod) res -= mod;
    return res;
}

uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t mod){
    if (a >= b) return a - b;
    return mod - (b - a);
}

uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t mod){
    unsigned __int128 prod = static_cast<unsigned __int128>(a) * b;
    return static_cast<uint64_t>(prod % mod);
}

uint64_t mod_inv(uint64_t a, uint64_t mod){
    int64_t t = 0, new_t = 1;
    int64_t r = static_cast<int64_t>(mod), new_r = static_cast<int64_t>(a % mod);
    while (new_r != 0){
        int64_t q = r / new_r;
        int64_t temp_t = t - q * new_t;
        int64_t temp_r = r - q * new_r;
        t = new_t;
        new_t = temp_t;
        r = new_r;
        new_r = temp_r;
    }
    if (r != 1){
        throw invalid_argument("modular inverse does not exist");
    }
    if (t < 0) t += static_cast<int64_t>(mod);
    return static_cast<uint64_t>(t);
}

pair<uint64_t,uint64_t> eeq_schedule(uint64_t hw){
    if (hw <= 6) return {1,1};
    if (hw == 7) return {2,2};
    if (hw >= 8 && hw <= 11) return {3,2};
    if (hw >= 12 && hw <= 15) return {4,2};
    if (hw >= 16 && hw <= 19) return {5,2};
    if (hw >= 20 && hw <= 23) return {6,2};
    return {static_cast<uint64_t>(max<uint64_t>(1, hw/4)), 2};
}

vector<uint64_t> build_equality_polynomial(uint64_t hw, uint64_t mod){
    vector<uint64_t> coeffs(1, 1);
    for (uint64_t i = 0; i < hw; ++i){
        vector<uint64_t> next(coeffs.size() + 1, 0);
        for (size_t j = 0; j < next.size(); ++j){
            uint64_t carry = (j > 0) ? coeffs[j - 1] : 0;
            uint64_t stay = (j < coeffs.size()) ? coeffs[j] : 0;
            uint64_t term = carry;
            if (stay){
                term = mod_sub(term, mod_mul(stay, i, mod), mod);
            }
            next[j] = term;
        }
        coeffs.swap(next);
    }

    uint64_t factorial = 1;
    for (uint64_t i = 2; i <= hw; ++i){
        factorial = mod_mul(factorial, i, mod);
    }
    uint64_t inv_fact = mod_inv(factorial, mod);
    for (auto &c : coeffs){
        c = mod_mul(c, inv_fact, mod);
    }
    return coeffs;
}
}

EEQParams build_eeq_params(uint64_t hw, uint64_t plain_modulus){
    if (plain_modulus < 2){
        throw invalid_argument("plain modulus too small for EEQ");
    }
    EEQParams params;
    params.hw = hw;
    tie(params.L, params.H) = eeq_schedule(hw);
    params.coefficients = build_equality_polynomial(hw, plain_modulus);
    return params;
}
Params::Params()
        : log_poly_modulus_degree(0),
            prime_bitlength(0),
            task(PSUCardinality),
            mu(0),
            effective_lambda(0),
            hw(0),
            ell(0),
            server_set(0),
            client_set(0),
            client_bin_offset(0) {}

Params::Params(Task task, uint64_t server_set, uint64_t effective_lambda, uint64_t hw, uint64_t client_set){

    this->task = task;
    // this->mu = mu;
    // this->gamma = gamma;
    this->effective_lambda = effective_lambda;
    this->server_set = server_set;
    this->hw = hw;
    this->client_set = client_set;
    this->client_bin_offset = 0;

    this->ell = hw;
    while (log2_choose(this->ell, this->hw) < this->effective_lambda){
        this->ell++;
    }

    if (hw <= 1){ // q=72
        log_poly_modulus_degree = 12;
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {36,36});
    } else if(hw <= 2){ // q=48*3=144
        log_poly_modulus_degree = 13;
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {48,48,48});
    } else if(hw <= 4){ // increased modulus bits to provide larger noise budget
        log_poly_modulus_degree = 13;
        // previously {48,36,36,48} -> total ~168 bits
        // increase to {60,48,48,60} -> total ~216 bits to allow deeper multiplications
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {60,48,48,60});
    } else if(hw <= 8){ // q=55*2+36*3=218 (SEAL's N=8192 security limit)
        log_poly_modulus_degree = 13;
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {55,36,36,36,55});
    } else if(hw <= 16){ // q=48*2+36*4=240
        log_poly_modulus_degree = 14;
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {48,36,36,36,36,48});
    } else if(hw <= 32){ // q=48*2+36*5=276
        log_poly_modulus_degree = 14;
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {48,36,36,36,36,36,48});
    } else if(hw <= 64){ // q=48*2+36*6=312
        log_poly_modulus_degree = 14;
        coeff_bits = CoeffModulus::Create(1 << log_poly_modulus_degree, {48,36,36,36,36,36,36,48});
    } else {
        throw invalid_argument("unsupported hamming weight for parameter selection");
    }
    uint64_t num_bins = 1 << log_poly_modulus_degree;
    uint64_t num_balls = 3 * server_set;
    uint64_t mu = ceil((float)num_balls / num_bins + 2 * sqrt((float)num_balls * log2(num_bins) / num_bins));
    this->mu = mu;

    // effective_lambda describes the encoded element domain, not the BFV
    // plaintext modulus. Elements are already constant-weight encoded and the
    // final raw values are split into base-p digits, so a 20-bit batching prime
    // is sufficient and matches the FeUPSU comparison configuration.
    uint64_t min_bits = 20;
    auto try_pick = [&](uint64_t bits) -> bool {
        if (bits < 2 || bits > 60) return false;
        try {
            auto modulus_candidate = PlainModulus::Batching(1 << log_poly_modulus_degree, static_cast<int>(bits));
            this->prime_bitlength = static_cast<uint64_t>(bits);
            if (modulus_candidate.bit_count() != static_cast<int>(bits)) {
                this->prime_bitlength = modulus_candidate.bit_count();
            }
            return true;
        } catch (const std::invalid_argument &) {
            return false;
        } catch (const std::logic_error &) {
            return false;
        }
    };

    bool found_plain_modulus = false;
    for (uint64_t bits = min_bits; bits <= 60; ++bits) {
        if (try_pick(bits)) {
            found_plain_modulus = true;
            break;
        }
    }
    if (!found_plain_modulus) {
        uint64_t bits = min_bits;
        while (bits > 2) {
            --bits;
            if (try_pick(bits)) {
                found_plain_modulus = true;
                break;
            }
        }
    }
    if (!found_plain_modulus) {
        throw invalid_argument("failed to choose plain modulus bit-size for batching");
    }

};

namespace net {
namespace {
bool set_reuseaddr(int fd) {
    int opt = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0;
}
}

int create_listen_socket(uint16_t port, int backlog) {
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return -1;
    }

    set_reuseaddr(listen_fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(listen_fd);
        return -1;
    }

    if (::listen(listen_fd, backlog) < 0) {
        ::close(listen_fd);
        return -1;
    }

    return listen_fd;
}

int accept_client(int listen_fd) {
    for (;;) {
        int conn_fd = ::accept(listen_fd, nullptr, nullptr);
        if (conn_fd >= 0) {
            return conn_fd;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

int connect_socket(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0) {
        return -1;
    }

    int sock_fd = -1;
    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        int fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            sock_fd = fd;
            break;
        }
        ::close(fd);
    }

    ::freeaddrinfo(result);
    return sock_fd;
}

bool send_all(int fd, const void* data, size_t len) {
    const uint8_t* cursor = static_cast<const uint8_t*>(data);
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = ::send(fd, cursor + total_sent, len - total_sent, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

bool recv_all(int fd, void* data, size_t len) {
    uint8_t* cursor = static_cast<uint8_t*>(data);
    size_t total_recv = 0;
    while (total_recv < len) {
        ssize_t recvd = ::recv(fd, cursor + total_recv, len - total_recv, 0);
        if (recvd == 0) {
            return false;
        }
        if (recvd < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        total_recv += static_cast<size_t>(recvd);
    }
    return true;
}
} // namespace net
