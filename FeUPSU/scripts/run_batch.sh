#!/usr/bin/env bash
set -euo pipefail

profiles=(lan wan-100 wan-10 wan-1)
server_sets=($((1<<18)) $((1<<20)) $((1<<22)))
workloads=(
  "19 4"
  "19 7"
  "114 32"
)

results_dir="results"
mkdir -p "$results_dir"

cleanup() {
  scripts/run.sh --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for profile in "${profiles[@]}"; do
  for server_set in "${server_sets[@]}"; do
    for workload in "${workloads[@]}"; do
      read -r bitlength hw <<<"$workload"
      echo "=== $profile | server_set=$server_set | bitlength=$bitlength | hw=$hw ==="

      before_latest=""
      if compgen -G "$results_dir"/*.csv >/dev/null; then
        before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
      fi

      scripts/run.sh \
        --profile "$profile" \
        --iface "${NETEM_IFACE:-lo}" \
        -- \
        --server_set "$server_set" \
        --effective_bitlength "$bitlength" \
        --hamming_weight "$hw"

      if ! compgen -G "$results_dir"/*.csv >/dev/null; then
        echo "[WARN] 未生成结果文件" >&2
        continue
      fi

      latest_file=$(ls -1t "$results_dir"/*.csv | head -n 1)
      if [ "$latest_file" = "$before_latest" ]; then
        echo "[WARN] 未检测到新的结果文件" >&2
        continue
      fi

      base_name="$(basename "$latest_file" .csv)"
      renamed_file="$results_dir/${base_name}__${profile}.csv"
      mv "$latest_file" "$renamed_file"
      echo "    -> 结果存为 $renamed_file"
    done
  done
done