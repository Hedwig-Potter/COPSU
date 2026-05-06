#pragma once

#include <cstdint>
#include <vector>

namespace upsica::ds {

struct PolynomialLink {
    std::vector<uint64_t> coefficients;
};

PolynomialLink BuildRootPolynomial(const std::vector<uint64_t>& roots);
PolynomialLink BuildRootPolynomialMod(const std::vector<uint64_t>& roots, uint64_t modulus);
PolynomialLink BuildInterpolationPolynomial(const std::vector<uint64_t>& x, const std::vector<uint64_t>& y);
PolynomialLink BuildInterpolationPolynomialMod(const std::vector<uint64_t>& x, const std::vector<uint64_t>& y, uint64_t modulus);
uint64_t EvaluatePolynomialAt(const PolynomialLink& link, uint64_t x);
uint64_t EvaluatePolynomialAtMod(const PolynomialLink& link, uint64_t x, uint64_t modulus);

}  // namespace upsica::ds
