#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/run_hw114_hw19.sh [cycles]
# Each cycle iterates over all server_set values for every network profile.

CYCLES="${1:-1}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

PROFILES=(lan wan-100 wan-10 wan-1)
SERVER_SETS=($((1<<18)) $((1<<20)) $((1<<22)))
EFFECTIVE=114
HW=19
PATTERN="$RESULTS_DIR/bitlength_*hw_${HW}_*.csv"

cleanup() {
  scripts/run.sh --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for profile in "${PROFILES[@]}"; do
  echo "==== profile=$profile ===="

  for ((cycle = 1; cycle <= CYCLES; ++cycle)); do
    for idx in "${!SERVER_SETS[@]}"; do
      server_set="${SERVER_SETS[$idx]}"
      run_idx=$(( (cycle - 1) * ${#SERVER_SETS[@]} + idx + 1 ))
      echo "--- run #$run_idx (server_set=$server_set) ---"

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
        echo "[WARN] No bitlength_*hw_${HW}_* result file was generated" >&2
        continue
      fi

      latest_after=$(ls -1t -- $PATTERN | head -n 1)
      if [ -n "$latest_before" ] && [ "$latest_after" = "$latest_before" ]; then
        echo "[WARN] No new result file was detected (still ${latest_after##*/})" >&2
        continue
      fi

      target_path="$latest_after"
      suffix="__${profile}.csv"
      if [[ "$target_path" != *"$suffix" ]]; then
        new_path="${target_path%.csv}${suffix}"
        mv "$target_path" "$new_path"
        target_path="$new_path"
      fi

      echo "Saved result: ${target_path##*/}"
    done
  done

  echo

done

echo "All experiments completed. Results are stored in $RESULTS_DIR"
