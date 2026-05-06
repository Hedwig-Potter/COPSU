#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/run_circuit_psu_batch.sh
# Runs FeUPSU circuitPSU (task=2) for the specified parameter grid.
# Profiles, server_set values, and workloads follow scripts/run_batch.sh semantics.
# lan: 10 Gbps, RTT≈0.2 ms; wan-100/10/1: RTT≈80 ms

profiles=(lan wan-100 wan-10 wan-1)
server_sets=($((1<<18)) $((1<<20)) $((1<<22)))
workloads=(
  "32 7"
  "32 8"
  "128 31"
  "128 32"
)

results_dir="results"
mkdir -p "$results_dir"

SUDO_KEEPALIVE_PID=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[INFO] 预热 sudo 权限用于 tc 配置..." >&2
    sudo -v
    (while true; do sleep 60; sudo -n true; done) &
    SUDO_KEEPALIVE_PID=$!
  fi
fi

cleanup() {
  if [ -n "${SUDO_KEEPALIVE_PID:-}" ]; then
    kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
  fi
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
  --task circuitPSU \
        --time_OTSSS \
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

      suffix="__${profile}.csv"
      if [[ "$latest_file" != *"$suffix" ]]; then
        renamed_file="${latest_file%.csv}${suffix}"
        if mv -f "$latest_file" "$renamed_file"; then
          latest_file="$renamed_file"
        else
          echo "[WARN] 重命名 $latest_file 失败" >&2
        fi
      fi
      echo "    -> 结果存为 $latest_file"
    done
  done
  echo
done

echo "全部实验完成。结果保存在 $results_dir"
