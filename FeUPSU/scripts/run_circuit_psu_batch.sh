#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Usage: scripts/run_circuit_psu_batch.sh
# Runs FeUPSU circuitPSU (Task enum value 3) for the specified parameter grid.
# server_set values and workloads follow scripts/run_batch.sh semantics.
# This batch intentionally runs only LAN: 10 Gbps, RTT≈0.2 ms.

profiles=(lan)
workloads=(
  # original_bits effective_lambda hw server_set
  "32 19 6 $((1<<18))"
  "32 19 6 $((1<<20))"
  "32 19 6 $((1<<22))"
  "128 47 14 $((1<<18))"
  "128 49 15 $((1<<20))"
  "128 50 15 $((1<<22))"
)

log_poly_modulus_degree_for_hw() {
  local hw="$1"
  if [ "$hw" -le 1 ]; then
    echo 12
  elif [ "$hw" -le 8 ]; then
    echo 13
  elif [ "$hw" -le 64 ]; then
    echo 14
  else
    echo "unsupported hw: $hw" >&2
    return 1
  fi
}

results_dir="$ROOT/results"
mkdir -p "$results_dir"
failed_cases=()

SUDO_KEEPALIVE_PID=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[INFO] Warming the sudo credential cache for tc configuration..." >&2
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

echo "[INFO] configuring and building Release..." >&2
"$ROOT/scripts/configure.sh" --type Release
"$ROOT/scripts/build.sh" --type Release

for profile in "${profiles[@]}"; do
  for workload in "${workloads[@]}"; do
      read -r original_bitlength effective_lambda hw server_set <<<"$workload"
      log_poly_modulus_degree="$(log_poly_modulus_degree_for_hw "$hw")"
      client_set="$((1 << log_poly_modulus_degree))"
      completed_pattern="$results_dir/effective_${effective_lambda}_hw_${hw}_server_${server_set}_*__${profile}.csv"
      if [ "${RESUME:-0}" = "1" ] && compgen -G "$completed_pattern" >/dev/null; then
        echo "[INFO] RESUME=1: an existing $profile result was found; skipping effective=$effective_lambda hw=$hw server_set=$server_set"
        continue
      fi
      # The OSN Benes implementation accepts arbitrary sizes. Do not round the
      # combined input up to a power of two: 2^22 + N would otherwise become
      # 2^23 and almost double the memory footprint.
      shuffle_count=$((client_set + server_set))
      level_bound=1
      shuffle_log=0
      while [ "$level_bound" -lt "$shuffle_count" ]; do
        level_bound=$((level_bound << 1))
        shuffle_log=$((shuffle_log + 1))
      done
      switch_count=$(((2 * shuffle_log - 1) * (shuffle_count / 2)))
      estimated_core_gib=$(((switch_count * 160 + (1 << 30) - 1) / (1 << 30)))
      available_kib=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
      available_gib=$((available_kib / 1024 / 1024))
      required_gib=$((estimated_core_gib + 6))
      echo "=== $profile | original_bitlength=$original_bitlength | server_set=$server_set | effective_lambda=$effective_lambda | hw=$hw | logN=$log_poly_modulus_degree | client_set=$client_set ==="
      echo "    circuit shuffle_count=$shuffle_count | Benes switches=$switch_count | OSN core arrays roughly >=${estimated_core_gib} GiB | MemAvailable=${available_gib} GiB"
      if [ "$available_gib" -lt "$required_gib" ]; then
        echo "[ERROR] Insufficient memory: this case requires at least ${required_gib} GiB, but approximately ${available_gib} GiB is available; skipping to avoid OOM." >&2
        failed_cases+=("$profile bits=$original_bitlength server_set=$server_set effective=$effective_lambda hw=$hw (insufficient memory)")
        continue
      fi
      if [ "$estimated_core_gib" -ge 12 ]; then
        echo "[WARN] This OSN is very large; peak memory also includes OT/network buffers and share vectors." >&2
      fi

      before_latest=""
      if compgen -G "$results_dir"/*.csv >/dev/null; then
        before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
      fi

      if ! "$ROOT/scripts/run.sh" \
          --profile "$profile" \
          --iface "${NETEM_IFACE:-lo}" \
          -- \
          --task circuitPSU \
          --time_OTSSS \
          --server_set "$server_set" \
          --client_set "$client_set" \
          --effective_bitlength "$effective_lambda" \
          --hamming_weight "$hw"; then
        failed_cases+=("$profile bits=$original_bitlength server_set=$server_set effective=$effective_lambda hw=$hw")
        echo "[WARN] Run failed; recording this case and continuing。" >&2
        continue
      fi

      if ! compgen -G "$results_dir"/*.csv >/dev/null; then
        echo "[WARN] No result file was generated" >&2
        continue
      fi

      latest_file=$(ls -1t "$results_dir"/*.csv | head -n 1)
      if [ "$latest_file" = "$before_latest" ]; then
        echo "[WARN] No new result file was detected" >&2
        continue
      fi

      suffix="__${profile}.csv"
      if [[ "$latest_file" != *"$suffix" ]]; then
        renamed_file="${latest_file%.csv}${suffix}"
        if mv -f "$latest_file" "$renamed_file"; then
          latest_file="$renamed_file"
        else
          echo "[WARN] Failed to rename $latest_file" >&2
        fi
      fi
      echo "    -> Result saved to $latest_file"
  done
  echo
done

echo "All experiments completed. Results are stored in $results_dir"
if [ "${#failed_cases[@]}" -gt 0 ]; then
  echo "[ERROR] The following ${#failed_cases[@]} experiment cases failed:" >&2
  printf '  - %s\n' "${failed_cases[@]}" >&2
  exit 1
fi
