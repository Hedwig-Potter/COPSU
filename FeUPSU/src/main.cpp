#include <iostream>
#include <getopt.h> // 用于解析命令行参数
#include "utils.h"
#include "client.h"
#include "server.h"

using namespace std;

int main(int argc, char * argv[]) {
    omp_set_num_threads(32); // 设置 OpenMP 使用的线程数

    // --- 默认参数 ---
    uint64_t effective_bitlength = 32;
    uint64_t server_set = 1ULL << 20;
    uint64_t hw = 4;

    Task task = PSU;
    bool time_otsss = false;

    static struct option long_options[] = {
        {"server_set", required_argument, nullptr, 's'},
        {"effective_bitlength", required_argument, nullptr, 'l'},
        {"hamming_weight", required_argument, nullptr, 'h'},
        {"task", required_argument, nullptr, 't'},
        {"time_OTSSS", no_argument, nullptr, 'o'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "s:l:h:t:o", long_options, &option_index)) != -1) {
        switch (c) {
            case 's':
                if (optarg) {
                    server_set = strtoull(optarg, nullptr, 10);
                }
                break;
            case 'l':
                if (optarg) {
                    effective_bitlength = strtoull(optarg, nullptr, 10);
                }
                break;
            case 'h':
                if (optarg) {
                    hw = strtoull(optarg, nullptr, 10);
                }
                break;
            case 't':
                if (optarg) {
                    string task_str(optarg);
                    if (task_str == "PSU") task = PSU;
                    else if (task_str == "PSUca_C") task = PSUca_C;
                    else if (task_str == "PSUca_S") task = PSUca_S;
                    else if (task_str == "PSUCardinality") task = PSUca_C;
                    else if (task_str == "circuitPSU") task = circuitPSU;
                    else {
                        cerr << "[WARN] 未识别的任务类型 '" << task_str << "'，使用默认 PSU" << endl;
                        task = PSU;
                    }
                }
                break;
            case 'o':
                time_otsss = true;
                break;
            default:
                break;
        }
    }

    // --- 设置服务器和客户端 ---
    Server* server = new Server();
    Client client(server);

    // --- 预计算的最优汉明权重 (hw) ---
    // 这是论文中的一个重要贡献：针对不同的有效比特长度，预先计算出最优的汉明权重
    // 以平衡通信和计算开销。
    // best_comm_hw 是为了优化通信而选择的 hw
    // vector<uint64_t> best_comm_hw({
    //     // ... (数据来自实验) ...
    //     8, 8, 12, 13, 13, 14, 15, 15, 16, 16, 15, 15, 16, 16,
    //     // ...
    // });
    // // best_comp_hw 是为了优化计算而选择的 hw
    // vector<uint64_t> best_comp_hw({
    //     // ... (数据来自实验) ...
    //     4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 6,
    //     // ...
    // });

    // --- 运行协议 ---
    // 使用所有配置好的参数创建一个 Params 对象
    Params params(task, server_set, effective_bitlength, hw);
    params.time_otsss = time_otsss;
    // 启动客户端运行协议
    client.run_protocol(params);

}