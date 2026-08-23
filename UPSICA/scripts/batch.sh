#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BINARY=${BINARY:-"$PROJECT_ROOT/build/upsica-vbf"}
RESULTS_DIR=${RESULTS_DIR:-"$PROJECT_ROOT/results"}
NETEM_IFACE=${NETEM_IFACE:-lo}
PORT=${PORT:-19090}
RECEIVER_SIZE=${RECEIVER_SIZE:-8192}
INTERSECTION=${INTERSECTION:-16}
BIN_COUNT=${BIN_COUNT:-32768}
ALPHA=${ALPHA:-4}
POLY_DEGREE=${POLY_DEGREE:-8192}
RESUME=${RESUME:-1}

BIT_LENGTHS=(32 128)
SENDER_SIZES=($((1<<18)) $((1<<20)) $((1<<22)))
NETWORKS=(lan wan-100Mbps wan-10Mbps wan-1Mbps)

server_pid=""
sudo_keepalive_pid=""

cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    sudo tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
    if [[ -n "$sudo_keepalive_pid" ]]; then
        kill "$sudo_keepalive_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

sudo -v
while true; do
    sudo -n true 2>/dev/null || exit
    sleep 50
done &
sudo_keepalive_pid=$!

apply_network() {
    local network=$1
    sudo tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
    case "$network" in
        lan) sudo tc qdisc add dev "$NETEM_IFACE" root netem rate 10gbit delay 0.1ms ;;
        wan-100Mbps) sudo tc qdisc add dev "$NETEM_IFACE" root netem rate 100mbit delay 40ms ;;
        wan-10Mbps) sudo tc qdisc add dev "$NETEM_IFACE" root netem rate 10mbit delay 40ms ;;
        wan-1Mbps) sudo tc qdisc add dev "$NETEM_IFACE" root netem rate 1mbit delay 40ms ;;
        *) echo "Unknown network: $network" >&2; exit 2 ;;
    esac
}

[[ -x "$BINARY" ]] || { echo "Missing executable: $BINARY" >&2; exit 1; }
mkdir -p "$RESULTS_DIR/.parts"

for network in "${NETWORKS[@]}"; do
    apply_network "$network"
    for bits in "${BIT_LENGTHS[@]}"; do
        for sender_size in "${SENDER_SIZES[@]}"; do
            name="element_${bits}_server_${sender_size}_${network}"
            output="$RESULTS_DIR/${name}.csv"
            if [[ "$RESUME" == 1 && -s "$output" ]]; then
                echo "[resume] skip $name"
                continue
            fi
            server_part="$RESULTS_DIR/.parts/${name}.server.csv"
            client_part="$RESULTS_DIR/.parts/${name}.client.csv"
            echo "[run] $name"
            "$BINARY" --role server --port "$PORT" --sender-set "$sender_size" \
                --receiver-set "$RECEIVER_SIZE" --intersection "$INTERSECTION" \
                --element-bits "$bits" --bins "$BIN_COUNT" --alpha "$ALPHA" \
                --poly-degree "$POLY_DEGREE" --results "$server_part" &
            server_pid=$!
            "$BINARY" --role client --host 127.0.0.1 --port "$PORT" \
                --sender-set "$sender_size" --receiver-set "$RECEIVER_SIZE" \
                --intersection "$INTERSECTION" --element-bits "$bits" \
                --bins "$BIN_COUNT" --alpha "$ALPHA" --poly-degree "$POLY_DEGREE" \
                --results "$client_part"
            wait "$server_pid"
            server_pid=""
            "$SCRIPT_DIR/merge_metrics.sh" "$server_part" "$client_part" "$output"
        done
    done
done

echo "UPSICA experiments completed: $RESULTS_DIR"
