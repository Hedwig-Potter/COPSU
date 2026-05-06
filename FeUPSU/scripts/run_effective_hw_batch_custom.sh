#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# LAN: 10 Gbps, RTT≈0.2 ms; WAN: 100/10/1 Mbps with RTT≈80 ms (applied in scripts/run.sh)
profiles=("lan" "wan-100" "wan-10" "wan-1")
profile_labels=("lan" "wan-100Mbps" "wan-10Mbps" "wan-1Mbps")

workloads=(
  "32 7 $((1<<18))"
  "32 7 $((1<<20))"
  "32 7 $((1<<22))"
  "32 8 $((1<<18))"
  "32 8 $((1<<20))"
  "32 8 $((1<<22))"
  "128 31 $((1<<18))"
  "128 31 $((1<<20))"
  "128 31 $((1<<22))"
  "128 32 $((1<<18))"
  "128 32 $((1<<20))"
  "128 32 $((1<<22))"
)

results_dir="$ROOT/results"
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
  "$ROOT/scripts/run.sh" --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[INFO] building Release..." >&2
"$ROOT/scripts/build.sh" --type Release

for idx in "${!profiles[@]}"; do
  profile="${profiles[$idx]}"
  label="${profile_labels[$idx]}"

  for workload in "${workloads[@]}"; do
    read -r effective_lambda hw server_set <<<"$workload"
    echo "=== $profile | server_set=$server_set | effective_lambda=$effective_lambda | hw=$hw ==="

    before_latest=""
    if compgen -G "$results_dir"/*.csv >/dev/null; then
      before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
    fi

    if ! "$ROOT/scripts/run.sh" \
      --profile "$profile" \
      --iface "${NETEM_IFACE:-lo}" \
      -- \
      --server_set "$server_set" \
      --effective_bitlength "$effective_lambda" \
      --hamming_weight "$hw"; then
      echo "[WARN] 运行失败，跳过该组合" >&2
      continue
    fi

    if ! compgen -G "$results_dir"/*.csv >/dev/null; then
      echo "[WARN] 未生成结果文件" >&2
      continue
    fi

    latest_file=$(ls -1t "$results_dir"/*.csv | head -n 1 || true)
    if [ -z "${latest_file:-}" ] || [ ! -f "$latest_file" ]; then
      echo "[WARN] 未找到最新结果文件" >&2
      continue
    fi
    if [ "$latest_file" = "$before_latest" ]; then
      echo "[WARN] 未检测到新的结果文件" >&2
      continue
    fi

    count=1
    while :; do
      candidate="$results_dir/effective_${effective_lambda}hw${hw}${label}${count}.csv"
      if [ ! -e "$candidate" ]; then
        renamed_file="$candidate"
        break
      fi
      count=$((count + 1))
    done

    if mv "$latest_file" "$renamed_file"; then
      echo "    -> 结果存为 $renamed_file"
    else
      echo "[WARN] 重命名失败，保留原文件: $latest_file" >&2
    fi
  done
  echo
done
