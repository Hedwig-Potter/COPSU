#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/run_hw19_hw4.sh [repetitions]
# Default repetitions per network profile is 3.

REPETITIONS="${1:-3}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

PROFILES=(lan wan-1 wan-10 wan-100)
PATTERN="$RESULTS_DIR/bitlength_*hw_4_*.csv"
SERVER_SETS=($((1<<18)) $((1<<20)) $((1<<22)))

cleanup() {
  scripts/run.sh --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for profile in "${PROFILES[@]}"; do
  for ((rep = 1; rep <= REPETITIONS; ++rep)); do
    idx=$(( (rep - 1) % ${#SERVER_SETS[@]} ))
    server_set=${SERVER_SETS[$idx]}
    echo "=== profile=$profile repetition=$rep server_set=$server_set ==="

    latest_before=""
    if compgen -G "$PATTERN" >/dev/null; then
      latest_before=$(ls -1t -- $PATTERN | head -n 1)
    fi

    scripts/run.sh \
      --profile "$profile" \
      --iface "${NETEM_IFACE:-lo}" \
      -- \
      --server_set "$server_set" \
      --effective_bitlength 19 \
      --hamming_weight 4

    if ! compgen -G "$PATTERN" >/dev/null; then
      echo "[WARN] 未生成 bitlength_*hw_4_* 结果文件" >&2
      continue
    fi

    latest_after=$(ls -1t -- $PATTERN | head -n 1)
    if [ -n "$latest_before" ] && [ "$latest_after" = "$latest_before" ]; then
      echo "[WARN] 未检测到新的结果文件 (仍为 ${latest_after##*/})" >&2
      continue
    fi

    target_path="$latest_after"
    if [[ "$target_path" != *"__${profile}.csv" ]]; then
      new_path="${target_path%.csv}__${profile}.csv"
      mv "$target_path" "$new_path"
      target_path="$new_path"
    fi

    echo "保存结果: $target_path"
  done
  echo
done

echo "全部实验完成。结果保存在 $RESULTS_DIR"
