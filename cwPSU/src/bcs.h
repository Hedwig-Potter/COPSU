#ifndef CWPSU_BCS_H
#define CWPSU_BCS_H

#include <cstdint>
#include <random>
#include <vector>

namespace bcs {

// 生成大小为 n 的随机置换，使用提供的随机数引擎
std::vector<uint32_t> generate_permutation(std::size_t n, std::mt19937_64 &rng);

// 对 data 按照置换 permutation 重新排列，permutation[i] 表示位置 i 映射到的原索引
std::vector<uint64_t> apply_permutation(const std::vector<uint64_t> &data,
                                        const std::vector<uint32_t> &permutation);

// 求 permutation 的逆置换，使得 inverse[permutation[i]] = i
std::vector<uint32_t> invert_permutation(const std::vector<uint32_t> &permutation);

}

#endif // CWPSU_BCS_H
