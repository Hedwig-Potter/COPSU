#!/usr/bin/env bash
set -euo pipefail

profiles=("lan" "wan-1" "wan-10" "wan-100")
profile_labels=("lan" "wan-1Mbps" "wan-10Mbps" "wan-100Mbps")

workloads=(
  "19 4 $((1<<18))"
  "19 4 $((1<<20))"
  "19 4 $((1<<22))"
  "19 7 $((1<<18))"
  "19 7 $((1<<20))"
  "19 7 $((1<<22))"
  "47 8 $((1<<18))"
  "49 8 $((1<<20))"
  "50 8 $((1<<22))"
)

results_dir="results"
mkdir -p "$results_dir"

cleanup() {
  scripts/run.sh --profile off --iface "${NETEM_IFACE:-lo}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

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

    scripts/run.sh \
      --profile "$profile" \
      --iface "${NETEM_IFACE:-lo}" \
      -- \
      --server_set "$server_set" \
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

    count=1
    while :; do
      candidate="$results_dir/effective_${effective_lambda}_hw${hw}_${label}_${count}.csv"
      if [ ! -e "$candidate" ]; then
        renamed_file="$candidate"
        break
      fi
      count=$((count + 1))
    done
    mv "$latest_file" "$renamed_file"
    echo "    -> Result saved to $renamed_file"
  done
  echo
done
