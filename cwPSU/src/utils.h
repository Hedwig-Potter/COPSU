//
// Created by Administrator on 2025/9/23.
//

#ifndef FEUPSU_UTILS_H
#define FEUPSU_UTILS_H

#include "seal/seal.h" // 引入 SEAL 同态加密库
#include "omp.h"       // 引入 OpenMP，用于多线程并行计算
#include <cstdint>
#include <string>

using namespace std;

// === 计时器类 ===
// 用于测量代码块的执行时间
class Timer {
public:
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point end_;
    Timer();
    void start(); // 开始计时
    void end();   // 结束计时
    long double end_and_get(); // 结束计时并返回毫秒数
    void reset();
    long double get_time_in_milliseconds(); // 获取毫秒数
};

// === 指标类 ===
// 用于收集和存储性能指标，如执行时间、通信量等
class Metrics{
public:
    map<string, uint64_t> metrics_;
};

// === 任务枚举 ===
// 定义协议可以执行的不同类型的 PSI 任务
enum Task{
    PSU=0,            // 标准 PSU (计算并集)
    PSUCardinality=1,    // PSU基数 (计算并集的大小)
    circuitPSU=2,       // 电路 PSU (计算并集的分享)
};

// === 数学工具函数 ===
// 计算组合数的对数 log2(n choose k)
float log2_choose(uint64_t n, uint64_t k);
// 生成定重码 (Constant-Weight Code)
// 将一个数字 __number 编码成一个长度为 encoding_size、汉明权重 (hamming_weight) 为 hw 的二进制向量
vector<uint64_t> get_cw(uint64_t __number, uint64_t encoding_size, uint64_t hamming_weight, bool __verbose);

//新增
struct EEQParams {
    uint64_t hw;
    uint64_t L;
    uint64_t H;
    vector<uint64_t> coefficients;
};

EEQParams build_eeq_params(uint64_t hw, uint64_t plain_modulus);



// === 参数类 ===
// 封装协议所需的所有参数，方便在不同组件间传递
class Params{
public:
    // HE (同态加密) 相关参数
    uint64_t log_poly_modulus_degree; // 多项式模度数的对数log N
    vector<seal::Modulus> coeff_bits; // 系数模数q
    uint64_t prime_bitlength;         // 明文模数的比特长度t？

    // 协议相关参数
    Task task;                  // PSU 任务类型
    uint64_t mu;                // Cuckoo Hashing 的仓（bin）的最大负载
    // uint64_t gamma;             // 客户端将元素分桶的数量因子
    uint64_t effective_lambda;  // 有效的安全参数/比特长度
    uint64_t hw;                // 定重码的汉明权重

    // 根据上述参数派生出的参数
    uint64_t ell;               // 定重码的码长 (code length)
    uint64_t server_set;      // 服务器集合大小

    Params();
    // 构造函数，根据核心参数自动计算和设置所有其他参数
    Params(Task task, uint64_t server_set, uint64_t effective_lambda, uint64_t hw);
};

namespace net {
int create_listen_socket(uint16_t port, int backlog = 1);
int accept_client(int listen_fd);
int connect_socket(const std::string& host, uint16_t port);
bool send_all(int fd, const void* data, size_t len);
bool recv_all(int fd, void* data, size_t len);
}

#endif //FEUPSU_UTILS_H