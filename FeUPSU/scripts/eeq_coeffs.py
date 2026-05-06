"""生成 EEQ 多项式系数，便于嵌入 C++ 实现。

算法思路：直接构造
    f_h(k) = prod_{i=0}^{h-1} (k - i) / h!
它满足 f_h(k) = 0 (0 <= k < h)，且 f_h(h) = 1。
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import factorial


def equality_poly_coeffs(h: int) -> list[Fraction]:
    coeffs = [Fraction(1)]  # 初始多项式 1
    for i in range(h):
        # 乘以 (k - i)
        next_coeffs = [Fraction(0)] * (len(coeffs) + 1)
        for power, coef in enumerate(coeffs):
            next_coeffs[power] -= coef * i
            next_coeffs[power + 1] += coef
        coeffs = next_coeffs
    denom = Fraction(factorial(h))
    return [c / denom for c in coeffs]


def to_common_denominator(vals: list[Fraction]) -> tuple[int, list[int]]:
    common_den = 1
    for v in vals:
        common_den = lcm(common_den, v.denominator)
    integers = [int(v * common_den) for v in vals]
    g = abs(integers[0])
    for x in integers[1:]:
        g = gcd(g, abs(x))
    if g > 1:
        integers = [x // g for x in integers]
        common_den //= g
    return common_den, integers


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b)


def main() -> None:
    print("# h degree denominator coefficients(low→high)")
    for h in range(1, 65):
        coeffs = equality_poly_coeffs(h)
        denom, ints = to_common_denominator(coeffs)
        print(h, len(ints) - 1, denom, " ".join(str(v) for v in ints))


if __name__ == "__main__":
    main()
