#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/run_hw19_hw6_hw114_hw26.sh [cycles]
# Each cycle runs every SERVER_SET once per network profile.

CYCLES="${1:-1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

PROFILES=(lan wan-1 wan-10 wan-100)
SERVER_SETS=($((1<<18)) $((1<<20)) $((1<<22)))
CONFIGS=("19:6" "114:26")

cleanup() {
  scripts/run.sh --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for cfg in "${CONFIGS[@]}"; do
  IFS=':' read -r EFFECTIVE HW <<<"$cfg"
  PATTERN="$RESULTS_DIR/bitlength_*hw_${HW}_*.csv"

  echo "==== effective_bitlength=$EFFECTIVE, hamming_weight=$HW ===="

  for profile in "${PROFILES[@]}"; do
    echo "-- profile: $profile"

    for ((cycle = 1; cycle <= CYCLES; ++cycle)); do
      for idx in "${!SERVER_SETS[@]}"; do
        server_set="${SERVER_SETS[$idx]}"
        run_idx=$(( (cycle - 1) * ${#SERVER_SETS[@]} + idx + 1 ))
        echo "=== run #$run_idx (profile=$profile, server_set=$server_set) ==="

        latest_before=""
        if compgen -G "$PATTERN" >/dev/null; then
          latest_before=$(ls -1t -- $PATTERN | head -n 1)
        fi

        scripts/run.sh \
          --profile "$profile" \
          --iface "${NETEM_IFACE:-lo}" \
          -- \
          --server_set "$server_set" \
          --effective_bitlength "$EFFECTIVE" \
          --hamming_weight "$HW"

        if ! compgen -G "$PATTERN" >/dev/null; then
          echo "[WARN] 未生成 bitlength_*hw_${HW}_* 结果文件" >&2
          continue
        fi

        latest_after=$(ls -1t -- $PATTERN | head -n 1)
        if [ -n "$latest_before" ] && [ "$latest_after" = "$latest_before" ]; then
          echo "[WARN] 未检测到新的结果文件 (仍为 ${latest_after##*/})" >&2
          continue
        fi

        target_path="$latest_after"
        suffix="__${profile}.csv"
        if [[ "$target_path" != *"$suffix" ]]; then
          new_path="${target_path%.csv}${suffix}"
          mv "$target_path" "$new_path"
          target_path="$new_path"
        fi

        echo "保存结果: ${target_path##*/}"
      done
    done

    echo
  done

done

echo "全部实验完成。结果保存在 $RESULTS_DIR"
