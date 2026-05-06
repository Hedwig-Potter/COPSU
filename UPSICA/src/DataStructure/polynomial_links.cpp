#include "upsica/polynomial_links.h"

#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include <stdexcept>

namespace upsica::ds {

namespace {

uint64_t MulMod2Pow64(uint64_t a, uint64_t b) {
    return static_cast<uint64_t>(a * b);
}

uint64_t AddMod(uint64_t a, uint64_t b, uint64_t modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulus must be non-zero");
    }
    return static_cast<uint64_t>((static_cast<unsigned __int128>(a % modulus) + (b % modulus)) % modulus);
}

uint64_t MulMod(uint64_t a, uint64_t b, uint64_t modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulus must be non-zero");
    }
    return static_cast<uint64_t>((static_cast<unsigned __int128>(a % modulus) * (b % modulus)) % modulus);
}

uint64_t PowMod(uint64_t base, uint64_t exp, uint64_t modulus) {
    uint64_t result = 1 % modulus;
    uint64_t x = base % modulus;
    while (exp > 0) {
        if (exp & 1ULL) {
            result = MulMod(result, x, modulus);
        }
        x = MulMod(x, x, modulus);
        exp >>= 1ULL;
    }
    return result;
}

uint64_t ModInversePrime(uint64_t value, uint64_t modulus) {
    if ((value % modulus) == 0) {
        throw std::invalid_argument("non-invertible element in modulus field");
    }
    // For prime modulus: a^(p-2) mod p.
    return PowMod(value, modulus - 2, modulus);
}

}  // namespace

PolynomialLink BuildRootPolynomial(const std::vector<uint64_t>& roots) {
    // Build coefficients of P(x) = Π (x - r_i) over uint64 ring.
    PolynomialLink link;
    link.coefficients = {1};

    for (uint64_t r : roots) {
        std::vector<uint64_t> next(link.coefficients.size() + 1, 0);
        for (size_t i = 0; i < link.coefficients.size(); ++i) {
            // x * coeff
            next[i + 1] = static_cast<uint64_t>(next[i + 1] + link.coefficients[i]);
            // (-r) * coeff == (2^64 - r) * coeff in mod 2^64 ring
            uint64_t neg_r = static_cast<uint64_t>(0 - r);
            next[i] = static_cast<uint64_t>(next[i] + MulMod2Pow64(link.coefficients[i], neg_r));
        }
        link.coefficients.swap(next);
    }

    return link;
}

PolynomialLink BuildRootPolynomialMod(const std::vector<uint64_t>& roots, uint64_t modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulus must be non-zero");
    }

    // Build coefficients of P(x) = Π (x - r_i) over Z_modulus.
    PolynomialLink link;
    link.coefficients = {1 % modulus};

    for (uint64_t r : roots) {
        uint64_t r_mod = r % modulus;
        uint64_t neg_r = (modulus - r_mod) % modulus;

        std::vector<uint64_t> next(link.coefficients.size() + 1, 0);
        for (size_t i = 0; i < link.coefficients.size(); ++i) {
            // x * coeff
            next[i + 1] = AddMod(next[i + 1], link.coefficients[i], modulus);
            // (-r) * coeff
            next[i] = AddMod(next[i], MulMod(link.coefficients[i], neg_r, modulus), modulus);
        }
        link.coefficients.swap(next);
    }

    return link;
}

PolynomialLink BuildInterpolationPolynomial(const std::vector<uint64_t>& x, const std::vector<uint64_t>& y) {
    // Placeholder interpolation carrier; stores paired points.
    PolynomialLink link;
    link.coefficients.reserve(x.size() + y.size());
    link.coefficients.insert(link.coefficients.end(), x.begin(), x.end());
    link.coefficients.insert(link.coefficients.end(), y.begin(), y.end());
    return link;
}

PolynomialLink BuildInterpolationPolynomialMod(const std::vector<uint64_t>& x,
                                               const std::vector<uint64_t>& y,
                                               uint64_t modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulus must be non-zero");
    }
    if (x.size() != y.size()) {
        throw std::invalid_argument("x and y size mismatch");
    }
    if (x.empty()) {
        return PolynomialLink{{0}};
    }

    // Deduplicate x-values (keep first), avoiding singular denominators.
    std::vector<uint64_t> xs;
    std::vector<uint64_t> ys;
    xs.reserve(x.size());
    ys.reserve(y.size());
    std::unordered_map<uint64_t, size_t> seen;
    for (size_t i = 0; i < x.size(); ++i) {
        uint64_t xi = x[i] % modulus;
        if (seen.find(xi) == seen.end()) {
            seen[xi] = xs.size();
            xs.push_back(xi);
            ys.push_back(y[i] % modulus);
        }
    }

    const size_t n = xs.size();
    PolynomialLink link;
    link.coefficients.assign(n, 0);

    for (size_t i = 0; i < n; ++i) {
        // Build basis polynomial Li(x) numerator and denominator.
        std::vector<uint64_t> basis = {1};
        uint64_t denom = 1;
        for (size_t j = 0; j < n; ++j) {
            if (i == j) {
                continue;
            }
            std::vector<uint64_t> next(basis.size() + 1, 0);
            uint64_t neg_xj = (modulus - xs[j]) % modulus;
            for (size_t k = 0; k < basis.size(); ++k) {
                next[k + 1] = AddMod(next[k + 1], basis[k], modulus);
                next[k] = AddMod(next[k], MulMod(basis[k], neg_xj, modulus), modulus);
            }
            basis.swap(next);
            denom = MulMod(denom, AddMod(xs[i], (modulus - xs[j]) % modulus, modulus), modulus);
        }

        uint64_t scale = MulMod(ys[i], ModInversePrime(denom, modulus), modulus);
        for (size_t k = 0; k < basis.size(); ++k) {
            link.coefficients[k] = AddMod(link.coefficients[k], MulMod(scale, basis[k], modulus), modulus);
        }
    }

    return link;
}

uint64_t EvaluatePolynomialAt(const PolynomialLink& link, uint64_t x) {
    uint64_t value = 0;
    for (auto it = link.coefficients.rbegin(); it != link.coefficients.rend(); ++it) {
        value = static_cast<uint64_t>(value * x + *it);
    }
    return value;
}

uint64_t EvaluatePolynomialAtMod(const PolynomialLink& link, uint64_t x, uint64_t modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("modulus must be non-zero");
    }

    uint64_t x_mod = x % modulus;
    uint64_t value = 0;
    for (auto it = link.coefficients.rbegin(); it != link.coefficients.rend(); ++it) {
        value = AddMod(MulMod(value, x_mod, modulus), *it, modulus);
    }
    return value;
}

}  // namespace upsica::ds
