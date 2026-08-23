#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Usage: scripts/run_psu_cardinality_batch.sh
# Runs PSUCardinality tasks (task=1 and task=2) for the specified parameter grid.
# Profiles and workloads mirror scripts/run_batch.sh.

profiles=(
  "lan:lan"
  # "wan-1Mbps:wan-1"
  # "wan-10Mbps:wan-10"
  # "wan-100Mbps:wan-100"
)
tasks=(PSUca_C PSUca_S)
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

for profile_entry in "${profiles[@]}"; do
  IFS=':' read -r profile_label profile_name <<<"$profile_entry"
  for task in "${tasks[@]}"; do
    for workload in "${workloads[@]}"; do
        read -r original_bitlength effective_lambda hw server_set <<<"$workload"
        log_poly_modulus_degree="$(log_poly_modulus_degree_for_hw "$hw")"
        client_set="$((1 << log_poly_modulus_degree))"
        echo "=== $profile_label | task=$task | original_bitlength=$original_bitlength | server_set=$server_set | effective_lambda=$effective_lambda | hw=$hw | logN=$log_poly_modulus_degree | client_set=$client_set ==="

        before_latest=""
        if compgen -G "$results_dir"/*.csv >/dev/null; then
          before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
        fi

        "$ROOT/scripts/run.sh" \
          --profile "$profile_name" \
          --iface "${NETEM_IFACE:-lo}" \
          -- \
          --task "$task" \
          --server_set "$server_set" \
          --client_set "$client_set" \
          --effective_bitlength "$effective_lambda" \
          --hamming_weight "$hw"

        if ! compgen -G "$results_dir"/*.csv >/dev/null; then
          echo "[WARN] No result file was generated" >&2
          continue
        fi

        latest_file=$(ls -1t "$results_dir"/*.csv | head -n 1)
        if [ "$latest_file" = "$before_latest" ]; then
          echo "[WARN] No new result file was detected" >&2
          continue
        fi

        suffix="__${profile_label}.csv"
        if [[ "$latest_file" != *"$suffix" ]]; then
          base_name="$(basename "${latest_file%.csv}")"
          renamed_file="$results_dir/${base_name}${suffix}"
          if mv -f "$latest_file" "$renamed_file"; then
            latest_file="$renamed_file"
          else
            echo "[WARN] Failed to rename $latest_file" >&2
          fi
        fi
        echo "    -> Result saved to $latest_file"
    done
  done
  echo
done

echo "All experiments completed. Results are stored in $results_dir"
