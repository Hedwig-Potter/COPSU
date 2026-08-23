#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

profiles=("lan" "wan-100" "wan-10" "wan-1")
profile_labels=("lan" "wan-100Mbps" "wan-10Mbps" "wan-1Mbps")

workloads=(
  "32 19 6"
)

server_sets=(
  "$((1<<28))"
)

client_factors=(1 2)

results_dir="$ROOT/results"
mkdir -p "$results_dir"

log_poly_degree_for_hw() {
  local hw="$1"
  if [ "$hw" -le 1 ]; then
    echo 12
  elif [ "$hw" -le 2 ]; then
    echo 13
  elif [ "$hw" -le 4 ]; then
    echo 13
  elif [ "$hw" -le 8 ]; then
    echo 13
  elif [ "$hw" -le 16 ]; then
    echo 14
  elif [ "$hw" -le 32 ]; then
    echo 14
  elif [ "$hw" -le 64 ]; then
    echo 14
  else
    echo "unsupported hw: $hw" >&2
    return 1
  fi
}

sudo_keepalive_pid=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  echo "[INFO] Warming the sudo credential cache to avoid repeated password prompts..." >&2
  sudo -v
  (while true; do sleep 60; sudo -n true; done) &
  sudo_keepalive_pid=$!
fi

cleanup() {
  if [ -n "${sudo_keepalive_pid:-}" ]; then
    kill "$sudo_keepalive_pid" >/dev/null 2>&1 || true
  fi
  "$ROOT/scripts/run.sh" --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[INFO] building Release..." >&2
"$ROOT/scripts/build.sh" --type Release

for profile_idx in "${!profiles[@]}"; do
  profile="${profiles[$profile_idx]}"
  label="${profile_labels[$profile_idx]}"

  for workload in "${workloads[@]}"; do
    read -r original_bitlength effective_lambda hw <<<"$workload"
    log_poly_degree="$(log_poly_degree_for_hw "$hw")"
    base_client_set="$((1 << log_poly_degree))"

    for server_set in "${server_sets[@]}"; do
      for client_factor in "${client_factors[@]}"; do
        client_set="$((client_factor * base_client_set))"
        echo "=== $profile | original_bitlength=$original_bitlength | server_set=$server_set | effective_lambda=$effective_lambda | hw=$hw | logN=$log_poly_degree | client_set=$client_set ==="

        before_latest=""
        if compgen -G "$results_dir"/*.csv >/dev/null; then
          before_latest=$(ls -1t "$results_dir"/*.csv | head -n 1)
        fi

        if ! "$ROOT/scripts/run.sh" \
          --profile "$profile" \
          --iface "${NETEM_IFACE:-lo}" \
          -- \
          --server_set "$server_set" \
          --client_set "$client_set" \
          --effective_bitlength "$effective_lambda" \
          --hamming_weight "$hw"; then
          echo "[WARN] Run failed; skipping this configuration" >&2
          continue
        fi

        if ! compgen -G "$results_dir"/*.csv >/dev/null; then
          echo "[WARN] No result file was generated" >&2
          continue
        fi

        latest_file=$(ls -1t "$results_dir"/*.csv | head -n 1 || true)
        if [ -z "${latest_file:-}" ] || [ ! -f "$latest_file" ]; then
          echo "[WARN] No latest result file was found" >&2
          continue
        fi
        if [ "$latest_file" = "$before_latest" ]; then
          echo "[WARN] No new result file was detected" >&2
          continue
        fi

        count=1
        while :; do
          candidate="$results_dir/effective_${effective_lambda}_hw${hw}_server${server_set}_client${client_factor}x_${label}_${count}.csv"
          if [ ! -e "$candidate" ]; then
            renamed_file="$candidate"
            break
          fi
          count=$((count + 1))
        done

        if mv "$latest_file" "$renamed_file"; then
          echo "    -> Result saved to $renamed_file"
        else
          echo "[WARN] Rename failed; keeping the original file: $latest_file" >&2
        fi
      done
    done
  done
  echo
done
