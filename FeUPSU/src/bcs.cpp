#include "bcs.h"

#include <algorithm>
#include <numeric>

namespace bcs {

std::vector<uint32_t> generate_permutation(std::size_t n, std::mt19937_64 &rng) {
    std::vector<uint32_t> perm(n);
    std::iota(perm.begin(), perm.end(), 0U);
    std::shuffle(perm.begin(), perm.end(), rng);
    return perm;
}

std::vector<uint64_t> apply_permutation(const std::vector<uint64_t> &data,
                                        const std::vector<uint32_t> &permutation) {
    std::vector<uint64_t> result(permutation.size(), 0ULL);
    const std::size_t n = permutation.size();
    for (std::size_t i = 0; i < n; ++i) {
        uint32_t src_index = permutation[i];
        if (src_index < data.size()) {
            result[i] = data[src_index];
        }
    }
    return result;
}

std::vector<uint32_t> invert_permutation(const std::vector<uint32_t> &permutation) {
    std::vector<uint32_t> inverse(permutation.size(), 0U);
    for (std::size_t i = 0; i < permutation.size(); ++i) {
        uint32_t dest = permutation[i];
        if (dest < inverse.size()) {
            inverse[dest] = static_cast<uint32_t>(i);
        }
    }
    return inverse;
}

} // namespace bcs
