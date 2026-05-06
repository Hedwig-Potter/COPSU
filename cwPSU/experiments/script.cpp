#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <fstream>

using namespace std;

/*
 * 该脚本用于估计 cwPSU 构造中哈希桶的最大负载：
 * - 通过抛 "balls into bins" 模型近似服务器参数选择的最坏情况；
 * - 采用 OpenMP 对大量 Monte Carlo 轮次并行取样；
 * - 将阶段性结果追加写入 simulation.csv，便于与论文理论公式比对。
 */

void run_max_load(){
    uint64_t RUNS = ((uint64_t)1 << 30);

    uint64_t bins[] = {8192, 8192, 8192, 16384, 16384, 16384, 16384};
    uint64_t balls[] = {3145728,50331648,805306368,786432,3145728,12582912,50331648};

    int pairs = 6;

    int answer[pairs];
    for (int i=0;i<pairs;i++){
        answer[i] = 0;
    }
    uint64_t runned = 0;
    uint64_t milestone = 1;
    #pragma omp parallel
    {
        // 每个线程使用独立随机数引擎，避免竞争
        std::random_device rd;  // 为随机引擎生成独立种子
        std::mt19937 gen(rd()); // 使用 Mersenne Twister 获取稳定统计
        #pragma omp for
        for (int run=0;run < RUNS;run++){
            if (runned == milestone){
                #pragma omp critical
                {
                    if (runned == milestone){
                        // 记录阶段性里程碑，输出到终端与 CSV
                        cout << "Reached the mile stone " << milestone << endl;
                        milestone *= 2;
                        ofstream result_file;
                        result_file.open("simulation.csv", ios::app);
                        for (int i=0;i<pairs;i++){
                            result_file << milestone << ","
                                        << bins[i] << "," 
                                        << balls[i] << "," 
                                        << answer[i] << endl;
                        }
                        result_file.close();
                    }
                }
            }
            for (int i=0;i<pairs;i++){
                uint64_t NUM_BINS=bins[i];
                uint64_t NUM_BALLS=balls[i];

                std::uniform_int_distribution<> distrib(0, NUM_BINS-1);
                // 初始化所有桶，记录本轮的最大负载
                vector<int> bins(NUM_BINS,0);
                for (int j=0;j<NUM_BALLS;j++){
                    bins[distrib(gen)]++;
                }
                int this_max_load = *max_element(begin(bins), end(bins));
                #pragma omp critical
                {
                    if (this_max_load > answer[i])
                        answer[i] = this_max_load;
                }
            }
            #pragma omp critical
            {
                // 累计 Monte Carlo 次数
                runned += 1;
            }
        }
    }
}

int main(){
    // 仅运行最大负载模拟；更多分析由 Python 脚本负责整理输出来图
    run_max_load();
}