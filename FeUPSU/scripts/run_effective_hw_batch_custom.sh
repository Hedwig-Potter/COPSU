#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# LAN: 10 Gbps, RTT≈0.2 ms; WAN: 100/10/1 Mbps with RTT≈80 ms (applied in scripts/run.sh)
profiles=("lan" "wan-100" "wan-10" "wan-1")
profile_labels=("lan" "wan-100Mbps" "wan-10Mbps" "wan-1Mbps")

workloads=(
  # original_bits effective_lambda hw server_set
  # 32-bit: effective_lambda = 32 - log2(N) = 32 - 13 = 19.
  "32 19 6 $((1<<18))"
  "32 19 6 $((1<<20))"
  "32 19 6 $((1<<22))"
  # 128-bit: effective_lambda = 40 + ceil(log2(mu)); for N=16384,
  # mu is 100, 296 and 976 for the three server-set sizes below.
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

echo "[INFO] building Release..." >&2
"$ROOT/scripts/build.sh" --type Release

for idx in "${!profiles[@]}"; do
  profile="${profiles[$idx]}"
  label="${profile_labels[$idx]}"

  for workload in "${workloads[@]}"; do
    read -r original_bitlength effective_lambda hw server_set <<<"$workload"
    log_poly_modulus_degree="$(log_poly_modulus_degree_for_hw "$hw")"
    client_set="$((1 << log_poly_modulus_degree))"
    echo "=== $profile | original_bitlength=$original_bitlength | server_set=$server_set | effective_lambda=$effective_lambda | hw=$hw | logN=$log_poly_modulus_degree | client_set=$client_set ==="

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
      candidate="$results_dir/effective_${effective_lambda}hw${hw}${label}${count}.csv"
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
  echo
done
