"""Recreate the visualizations and CSVs from plots.ipynb without Jupyter."""

from __future__ import annotations

from math import ceil, factorial, log2
from pathlib import Path

import matplotlib


matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


N_AND_Q_H = [
    (12, 72),
    (13, 144),
    (13, 192),
    (13, 208),
    (14, 240),
    (14, 288),
    (14, 348),
]

OPTIONS = [
    (16, 3, 16),
    (19, 3, 16),
    (32, 7, 28),
    (48, 11, 40),
]


def log_find(log_x: float, k: int) -> int:
    ans = max(int(factorial(k) ** (1 / k) * 2 ** (log_x / k)), k)
    comp = 0.0
    for i in range(k):
        comp += log2(ans - i) - log2(i + 1)
    while comp < log_x:
        comp += log2(ans + 1) - log2(ans - k + 1)
        ans += 1
    return ans


def regenerate_tables(base_dir: Path) -> None:
    for effective_lambda, start, end in OPTIONS:
        hamming_weights = range(start, end)
        code_length = [log_find(effective_lambda, h) for h in hamming_weights]
        length_times_weight = [
            code_length[i] * N_AND_Q_H[ceil(log2(h))][1] * N_AND_Q_H[ceil(log2(h))][0]
            for i, h in enumerate(hamming_weights)
        ]

        df = pd.DataFrame(
            {
                "HammingWeight": list(hamming_weights),
                "CodeLength": code_length,
                "CodeLengthWeight": length_times_weight,
                "OptLength": [effective_lambda for _ in hamming_weights],
            }
        )
        df.to_csv(base_dir / f"output-{effective_lambda}.csv", index=False)

        plt.figure()
        plt.plot(hamming_weights, length_times_weight, "o-")
        plt.title(f"Effective lambda = {effective_lambda}")
        plt.xlabel("Hamming weight")
        plt.ylabel("Constant-weight code proxy")
        plt.tight_layout()
        plt.savefig(base_dir / f"plot-lambda-{effective_lambda}.png", dpi=300)
        plt.close()


def regenerate_best_hamming(base_dir: Path) -> None:
    best_weights: list[int] = []
    best_lengths: list[int] = []
    effective_lambdas = range(4, 64)
    for effective_lambda in effective_lambdas:
        start = effective_lambda // 4
        end = 3 * effective_lambda // 4
        candidates = []
        for h in range(start, end):
            code_length = log_find(effective_lambda, h)
            idx = ceil(log2(h))
            proxy = code_length * N_AND_Q_H[idx][1] * N_AND_Q_H[idx][0]
            candidates.append((proxy, h))
        best_length, best_weight = min(candidates)
        best_weights.append(best_weight)
        best_lengths.append(best_length)

    df = pd.DataFrame(
        {
            "EffectiveBitlength": list(effective_lambdas),
            "BestHammingWeight": best_weights,
            "BestCodeLength": best_lengths,
        }
    )
    df.to_csv(base_dir / "best-hamming.csv", index=False)

    plt.figure()
    plt.plot(list(effective_lambdas), best_weights, "o-")
    plt.xlabel("Effective bitlength")
    plt.ylabel("Best Hamming weight")
    plt.tight_layout()
    plt.savefig(base_dir / "plot-best-hamming.png", dpi=300)
    plt.close()


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    regenerate_tables(base_dir)
    regenerate_best_hamming(base_dir)


if __name__ == "__main__":
    main()