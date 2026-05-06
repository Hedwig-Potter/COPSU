#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_SCRIPT="$ROOT/scripts/run.sh"

profiles=(lan wan-100 wan-10 wan-1)
server_sets=($((1<<18)) $((1<<20)) $((1<<22)))
workloads=(
  "114 19"
  "19 7"
)

cleanup() {
  "$RUN_SCRIPT" --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for profile in "${profiles[@]}"; do
  for server_set in "${server_sets[@]}"; do
    for workload in "${workloads[@]}"; do
      read -r bitlength hw <<<"$workload"
      echo "=== $profile | server_set=$server_set | bitlength=$bitlength | hw=$hw ==="
      "$RUN_SCRIPT" \
        --profile "$profile" \
        --iface "${NETEM_IFACE:-lo}" \
        -- \
        --server_set "$server_set" \
        --effective_bitlength "$bitlength" \
        --hamming_weight "$hw"
    done
  done
done
