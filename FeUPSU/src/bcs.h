#ifndef FEUPSU_BCS_H
#define FEUPSU_BCS_H

#include <cstdint>
#include <random>
#include <vector>

namespace bcs {

std::vector<uint32_t> generate_permutation(std::size_t n, std::mt19937_64 &rng);

std::vector<uint64_t> apply_permutation(const std::vector<uint64_t> &data,
                                        const std::vector<uint32_t> &permutation);

std::vector<uint32_t> invert_permutation(const std::vector<uint32_t> &permutation);

} // namespace bcs

#endif // FEUPSU_BCS_H
