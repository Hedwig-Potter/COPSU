#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <fstream>

using namespace std;

// 估算不同球-桶配置下的最大装载量，模拟哈希装载的最坏情况
void run_max_load(){
    uint64_t RUNS = ((uint64_t)1 << 30);
    // 以 2^30 次实验近似无限重复，从而逼近最大值

    uint64_t bins[] = {8192, 8192, 8192, 16384, 16384, 16384, 16384};
    uint64_t balls[] = {3145728,50331648,805306368,786432,3145728,12582912,50331648};
    // bins/balls 对应论文中的各类参数设置，下标一致表示一组试验

    int pairs = 6;

    int answer[pairs];
    // answer[i] 保存第 i 组配置目前观察到的最大桶装载量
    for (int i=0;i<pairs;i++){
        answer[i] = 0;
    }
    uint64_t runned = 0;
    uint64_t milestone = 1;
    #pragma omp parallel
    {
        std::random_device rd;  //Will be used to obtain a seed for the random number engine
        std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
        #pragma omp for
        for (int run=0;run < RUNS;run++){
            // 每当全局迭代数达到 milestone 时输出进度并写入中间结果
            if (runned == milestone){
                #pragma omp critical
                {
                    if (runned == milestone){
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
                vector<int> bins(NUM_BINS,0);
                // 随机将 NUM_BALLS 个球投到 NUM_BINS 个桶中
                for (int j=0;j<NUM_BALLS;j++){
                    bins[distrib(gen)]++;
                }
                int this_max_load = *max_element(begin(bins), end(bins));
                #pragma omp critical
                {
                    // 更新当前配置的历史最大值
                    if (this_max_load > answer[i])
                        answer[i] = this_max_load;
                }
            }
            #pragma omp critical
            {
                // 维护全局已运行次数，供进度判断
                runned += 1;
            }
        }
    }
}

int main(){
    // 直接调用模拟函数
    run_max_load();
}