#!/usr/bin/env python3
"""Run the corrected fixed-weight-code hw search.

Original element length is converted to the effective comparison-key length:
  32-bit:  32 - ceil(log2(N))
  128-bit: 40 + ceil(log2(mu))
The actual CW code length (OptLength) is then selected by Params so that
C(OptLength, hw) covers that effective length.
"""

from __future__ import annotations

import csv
import math
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "main2"
RAW_DIR = ROOT / "experiments" / "results_corrected"
SUMMARY = ROOT / "experiments" / "corrected_hw_summary.csv"
DEFAULT_SERVER_SETS = (1 << 18, 1 << 20, 1 << 22, 1 << 28)
PLAIN_MODULUS_BITS = 20
REPEATS = int(os.environ.get("RUNS", "1"))


def parse_int_list(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    value = os.environ.get(name)
    if not value:
        return default
    return tuple(int(item.strip(), 0) for item in value.split(",") if item.strip())


SERVER_SETS = parse_int_list("SERVER_SETS", DEFAULT_SERVER_SETS)
ORIGINALS = parse_int_list("ORIGINALS", (32, 128))
DROP_SERVER_SETS = set(parse_int_list("DROP_SERVER_SETS", ()))
MERGE_SUMMARY = os.environ.get("MERGE_SUMMARY", "0") not in ("", "0", "false", "False")


def log_n_for_hw(hw: int) -> int:
    if hw <= 1:
        return 12
    if hw <= 8:
        return 13
    return 14


def compute_mu(server_set: int, log_n: int) -> int:
    n = 1 << log_n
    balls = 3 * server_set
    return math.ceil(balls / n + 2 * math.sqrt(balls * math.log2(n) / n))


def valid_hw(effective: int, hw: int) -> bool:
    return hw >= 1 and hw <= effective / 2 and effective / hw <= 13


def read_metrics(path: Path) -> dict[str, int]:
    with path.open(newline="") as handle:
        return {key: int(value) for key, value in csv.reader(handle)}


def cases():
    # Retain the useful ranges from the previous experiments.
    if 32 in ORIGINALS:
        for hw in range(3, 16):
            log_n = log_n_for_hw(hw)
            effective = 32 - log_n
            if valid_hw(effective, hw):
                yield 32, 0, log_n, 0, effective, hw

    if 128 in ORIGINALS:
        for server_set in SERVER_SETS:
            for hw in range(4, 33):
                log_n = log_n_for_hw(hw)
                mu = compute_mu(server_set, log_n)
                effective = 40 + math.ceil(math.log2(mu))
                if valid_hw(effective, hw):
                    yield 128, server_set, log_n, mu, effective, hw


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, int]] = []
    env = os.environ.copy()
    env["FEUPSU_HW_BENCHMARK"] = "1"

    for original, target_server, log_n, target_mu, effective, hw in cases():
        for repeat in range(1, REPEATS + 1):
            name = (
                f"original_{original}_server_{target_server}_N_{1 << log_n}_"
                f"mu_{target_mu}_effective_{effective}_hw_{hw}_run_{repeat}.csv"
            )
            result = RAW_DIR / name
            print(
                f"original={original} server={target_server} N={1 << log_n} "
                f"mu={target_mu} effective={effective} hw={hw} run={repeat}/{REPEATS}",
                flush=True,
            )
            run_env = env.copy()
            run_env["PSU_RESULTS_FILE"] = str(result)
            # server_set=3 activates the existing mu=1 microbenchmark path.
            subprocess.run(
                [str(BIN), "--server_set", "3", "--effective_bitlength", str(effective),
                 "--hamming_weight", str(hw), "--plain_modulus_bits", str(PLAIN_MODULUS_BITS)],
                cwd=ROOT / "experiments", env=run_env, check=True,
            )
            metrics = read_metrics(result)
            per_mu = metrics["time_server"]
            rows.append({
                "OriginalBitlength": original,
                "ServerSet": target_server,
                "PolyModulusDegree": 1 << log_n,
                "Mu": target_mu,
                "EffectiveBitlength": effective,
                "HammingWeight": hw,
                "OptLength": metrics["ell"],
                "time_server_per_mu1_ms": per_mu,
                "time_server_scaled_ms": per_mu * (target_mu if target_mu else 1),
                "comm_request": metrics["comm_request"],
                "plain_modulus_bits": metrics["plain_modulus_bits"],
                "run": repeat,
            })

    output_rows: list[dict[str, int] | dict[str, str]] = rows
    if MERGE_SUMMARY and SUMMARY.exists():
        with SUMMARY.open(newline="") as handle:
            existing_rows = list(csv.DictReader(handle))
        selected_server_sets = set(SERVER_SETS)
        output_rows = [
            row for row in existing_rows
            if not (
                int(row["OriginalBitlength"]) in ORIGINALS
                and (
                    int(row["ServerSet"]) in selected_server_sets
                    or int(row["ServerSet"]) in DROP_SERVER_SETS
                )
            )
        ]
        output_rows.extend(rows)

    with SUMMARY.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(output_rows)
    print(f"summary: {SUMMARY}")


if __name__ == "__main__":
    main()
