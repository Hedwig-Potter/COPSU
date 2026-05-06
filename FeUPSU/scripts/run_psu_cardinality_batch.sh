#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/run_psu_cardinality_batch.sh
# Runs PSUCardinality tasks (task=1 and task=2) for the specified parameter grid.
# Profiles and workloads mirror scripts/run_batch.sh (Release build assumed).

profiles=(
  "lan:lan"
  # "wan-1Mbps:wan-1"
  # "wan-10Mbps:wan-10"
  # "wan-100Mbps:wan-100"
)
tasks=(PSUca_C PSUca_S)
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

for profile_entry in "${profiles[@]}"; do
  IFS=':' read -r profile_label profile_name <<<"$profile_entry"
  for task in "${tasks[@]}"; do
    for server_set in "${server_sets[@]}"; do
      for workload in "${workloads[@]}"; do
        read -r bitlength hw <<<"$workload"
        echo "=== $profile_label | task=$task | server_set=$server_set | bitlength=$bitlength | hw=$hw ==="

        before_latest=""
        if compgen -G "$results_dir"/*.csv >/dev/null; then
          before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
        fi

        scripts/run.sh \
          --profile "$profile_name" \
          --iface "${NETEM_IFACE:-lo}" \
          -- \
          --task "$task" \
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

  suffix="__${profile_label}.csv"
        if [[ "$latest_file" != *"$suffix" ]]; then
          name_prefix=""
          if [ "$task" = "PSUca_S" ]; then
            name_prefix="ca_S_"
          elif [ "$task" = "PSUca_C" ]; then
            name_prefix="ca_R_"
          fi
          base_name="$(basename "${latest_file%.csv}")"
          renamed_file="$results_dir/${name_prefix}${base_name}_server_${server_set}${suffix}"
          if mv -f "$latest_file" "$renamed_file"; then
            latest_file="$renamed_file"
          else
            echo "[WARN] 重命名 $latest_file 失败" >&2
          fi
        fi
        echo "    -> 结果存为 $latest_file"
      done
    done
  done
  echo
done

echo "全部实验完成。结果保存在 $results_dir"
