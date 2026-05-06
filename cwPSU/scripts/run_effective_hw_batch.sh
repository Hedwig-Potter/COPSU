#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cmake -S "$ROOT/src" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/build" -j

profiles=("lan" "wan-100" "wan-10" "wan-1")
profile_labels=("lan" "wan-100Mbps" "wan-10Mbps" "wan-1Mbps")

server_sets=($((1<<18)) $((1<<20)) $((1<<22)))

workloads=(
  "32 7"
  "128 19"
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

is_port_free() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -ltn "sport = :$port" | grep -q ":$port "
  elif command -v netstat >/dev/null 2>&1; then
    ! netstat -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$port$"
  else
    return 0
  fi
}

find_port_block() {
  local base=39002
  local max=39100
  while [ $((base + 2)) -le "$max" ]; do
    if is_port_free "$base" && is_port_free "$((base + 1))" && is_port_free "$((base + 2))"; then
      echo "$base"
      return 0
    fi
    base=$((base + 3))
  done
  return 1
}

for idx in "${!profiles[@]}"; do
  profile="${profiles[$idx]}"
  label="${profile_labels[$idx]}"

  for server_set in "${server_sets[@]}"; do
    for workload in "${workloads[@]}"; do
      read -r effective_lambda hw <<<"$workload"
      echo "=== $profile | server_set=$server_set | effective_lambda=$effective_lambda | hw=$hw ==="

      before_latest=""
      if compgen -G "$results_dir"/*.csv >/dev/null; then
        before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
      fi

      success=0
      for attempt in 1 2 3; do
        base_port=$(find_port_block || true)
        if [ -z "${base_port:-}" ]; then
          echo "[WARN] 未找到可用端口段，等待重试..." >&2
          sleep 2
          continue
        fi
        export PSU_SERVER_PORT="$base_port"
        export PSU_MASKED_PORT="$((base_port + 1))"
        export PSU_PERMUTE_PORT="$((base_port + 2))"

        echo "[INFO] 使用端口: server=$PSU_SERVER_PORT masked=$PSU_MASKED_PORT permute=$PSU_PERMUTE_PORT (attempt $attempt)"

        if "$ROOT/scripts/run.sh" \
          --profile "$profile" \
          --iface "${NETEM_IFACE:-lo}" \
          -- \
          --server_set "$server_set" \
          --effective_bitlength "$effective_lambda" \
          --hamming_weight "$hw"; then
          success=1
          break
        fi

        echo "[WARN] 运行失败，等待重试..." >&2
        sleep $((attempt * 2))
      done

      if [ "$success" -ne 1 ]; then
        echo "[ERROR] 重试多次仍失败，跳过该组合" >&2
        continue
      fi

      if ! compgen -G "$results_dir"/*.csv >/dev/null; then
        echo "[WARN] 未生成结果文件" >&2
        continue
      fi

      latest_file=$(ls -1t "$results_dir"/*.csv | head -n 1)
      if [ "$latest_file" = "$before_latest" ]; then
        echo "[WARN] 未检测到新的结果文件" >&2
        continue
      fi

      count=1
      while :; do
        candidate="$results_dir/effective_${effective_lambda}_hw_${hw}_${label}_${count}.csv"
        if [ ! -e "$candidate" ]; then
          renamed_file="$candidate"
          break
        fi
        count=$((count + 1))
      done

      mv "$latest_file" "$renamed_file"
      echo "    -> 结果存为 $renamed_file"
    done
  done
  echo
done
