#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build"
CLIENT_BIN="$BUILD_DIR/feupsu_client"
SERVER_BIN="$BUILD_DIR/feupsu_server"
RESULTS_DIR="$ROOT/results"
IFACE="${NETEM_IFACE:-lo}"
SERVER_SET=$((1 << 28))
EFFECTIVE_BITLENGTH=32
RUNS="${RUNS:-1}"

profiles=(lan wan-100 wan-10 wan-1)
profile_labels=(lan wan-100Mbps wan-10Mbps wan-1Mbps)
hws=(7 8)
client_factors=(1 2)

sudo_keepalive_pid=""
server_pid=""

run_tc() {
  if [ "$(id -u)" -eq 0 ]; then
    tc "$@"
  else
    sudo -n tc "$@"
  fi
}

clear_profile() {
  run_tc qdisc del dev "$IFACE" root >/dev/null 2>&1 || true
}

apply_profile() {
  local profile="$1"
  clear_profile
  case "$profile" in
    lan)
      run_tc qdisc replace dev "$IFACE" root handle 1: netem \
        delay 0.1ms rate 10gbit limit 100000
      ;;
    wan-100)
      run_tc qdisc replace dev "$IFACE" root handle 1: netem \
        delay 40ms rate 100mbit limit 50000
      ;;
    wan-10)
      run_tc qdisc replace dev "$IFACE" root handle 1: netem \
        delay 40ms rate 10mbit limit 50000
      ;;
    wan-1)
      run_tc qdisc replace dev "$IFACE" root handle 1: netem \
        delay 40ms rate 1mbit limit 50000
      ;;
    *)
      echo "[FATAL] unknown network profile: $profile" >&2
      return 1
      ;;
  esac
}

stop_server() {
  if [ -z "${server_pid:-}" ] || ! kill -0 "$server_pid" >/dev/null 2>&1; then
    return
  fi
  kill -TERM "$server_pid" >/dev/null 2>&1 || true
  for _ in {1..20}; do
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      wait "$server_pid" 2>/dev/null || true
      server_pid=""
      return
    fi
    sleep 0.1
  done
  kill -KILL "$server_pid" >/dev/null 2>&1 || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  stop_server
  clear_profile
  if [ -n "${sudo_keepalive_pid:-}" ]; then
    kill "$sudo_keepalive_pid" >/dev/null 2>&1 || true
    wait "$sudo_keepalive_pid" 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[FATAL] tc requires root or sudo" >&2
    exit 1
  fi
  echo "[INFO] acquiring sudo credentials once for the complete batch..." >&2
  sudo -v
  (
    while true; do
      sleep 45
      sudo -n -v || exit 1
    done
  ) &
  sudo_keepalive_pid=$!
fi

mkdir -p "$RESULTS_DIR"

echo "[INFO] configuring and building Release binaries..." >&2
"$ROOT/scripts/configure.sh" --type Release
"$ROOT/scripts/build.sh" --type Release

if [ ! -x "$CLIENT_BIN" ] || [ ! -x "$SERVER_BIN" ]; then
  echo "[FATAL] standalone binaries were not produced in $BUILD_DIR" >&2
  exit 1
fi

server_log="$RESULTS_DIR/two_process_server.log"
: >"$server_log"
"$SERVER_BIN" >>"$server_log" 2>&1 &
server_pid=$!

for _ in {1..100}; do
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    echo "[FATAL] server exited during startup; see $server_log" >&2
    exit 1
  fi
  if ss -ltn 2>/dev/null | grep -q ':39002 '; then
    break
  fi
  sleep 0.1
done
if ! ss -ltn 2>/dev/null | grep -q ':39002 '; then
  echo "[FATAL] server did not listen on port 39002; see $server_log" >&2
  exit 1
fi

echo "[WARN] server_set=2^30 derives a very large mu and can require extreme CPU time and memory." >&2

for profile_index in "${!profiles[@]}"; do
  profile="${profiles[$profile_index]}"
  profile_label="${profile_labels[$profile_index]}"
  echo "[INFO] applying $profile_label to $IFACE" >&2
  apply_profile "$profile"

  for hw in "${hws[@]}"; do
    # Must stay synchronized with Params::Params in src/utils.cpp.
    log_poly_modulus_degree=13
    base_client_set=$((1 << log_poly_modulus_degree))

    for client_factor in "${client_factors[@]}"; do
      client_set=$((base_client_set * client_factor))

      for ((repeat = 1; repeat <= RUNS; ++repeat)); do
        result_file="$RESULTS_DIR/effective_${EFFECTIVE_BITLENGTH}_hw_${hw}_logN_${log_poly_modulus_degree}_server_${SERVER_SET}_client_${client_set}_${profile_label}_run_${repeat}.csv"
        echo "=== profile=$profile_label hw=$hw logN=$log_poly_modulus_degree server=$SERVER_SET client=$client_set run=$repeat/$RUNS ==="

        PSU_RESULTS_FILE="$result_file" \
          "$CLIENT_BIN" \
            --server-host 127.0.0.1 \
            --server-set "$SERVER_SET" \
            --client-set "$client_set" \
            --effective-bitlength "$EFFECTIVE_BITLENGTH" \
            --hamming-weight "$hw"

        if [ ! -s "$result_file" ]; then
          echo "[FATAL] result was not created: $result_file" >&2
          exit 1
        fi
        echo "    -> $result_file"
      done
    done
  done
done

echo "All experiments completed. Results: $RESULTS_DIR"
