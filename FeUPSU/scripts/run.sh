#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run.sh [--profile lan|wan-100|wan-10|wan-1|off] [--iface <interface>] [--] [program arguments...]

Example:
  scripts/run.sh --profile lan -- --effective_bitlength 114 --hw 32

Network profiles:
  lan     : 10 Gbps, RTT approximately 0.2 ms (0.1 ms one way)
  wan-100 : 100 Mbps, RTT approximately 80 ms (40 ms one way)
  wan-10  : 10 Mbps, RTT approximately 80 ms (40 ms one way)
  wan-1   : 1 Mbps, RTT approximately 80 ms (40 ms one way)
  off     : remove the current tc configuration and exit

Set the default interface with NETEM_IFACE (default: lo).
EOF
  exit 0
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

declare -a candidate_bins=(
  "$ROOT/build/main"
  "$ROOT/src/build/main"
)

BINARY=""
for cand in "${candidate_bins[@]}"; do
  if [ -f "$cand" ]; then
    BINARY="$cand"
    break
  fi
done

if [ -z "$BINARY" ]; then
  echo "Binary not found. Please run scripts/configure.sh && scripts/build.sh first." >&2
  exit 1
fi

IFACE="${NETEM_IFACE:-lo}"
PROFILE=""
PASSTHRU=()

while (($#)); do
  case "$1" in
    --profile)
      if (($# < 2)); then
        echo "--profile requires an argument" >&2
        exit 1
      fi
      PROFILE="$2"
      shift 2
      ;;
    --iface)
      if (($# < 2)); then
        echo "--iface requires an argument" >&2
        exit 1
      fi
      IFACE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      ;;
    --)
      shift
      PASSTHRU+=("$@")
      break
      ;;
    *)
      PASSTHRU+=("$1")
      shift
      ;;
  esac
done

SUDO="sudo"
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
fi

clear_profile() {
  local iface="$1"
  ${SUDO:+$SUDO }tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
}

apply_profile() {
  local profile="$1"
  local iface="$2"
  case "$profile" in
    ""|off)
      clear_profile "$iface"
      return
      ;;
    lan)
      clear_profile "$iface"
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 0.1ms rate 10gbit limit 100000
      ;;
    wan-100)
      clear_profile "$iface"
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 40ms rate 100mbit limit 50000
      ;;
    wan-10)
      clear_profile "$iface"
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 40ms rate 10mbit limit 50000
      ;;
    wan-1)
      clear_profile "$iface"
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 40ms rate 1mbit limit 50000
      ;;
    *)
      echo "Unknown network profile: $profile" >&2
      exit 1
      ;;
  esac
}

APPLIED_PROFILE=0
cleanup() {
  if [ "$APPLIED_PROFILE" -eq 1 ]; then
    clear_profile "$IFACE"
  fi
}
trap cleanup EXIT INT TERM

if [ -n "$PROFILE" ] && [ "$PROFILE" != "off" ]; then
  echo "[run.sh] Applying network profile '$PROFILE' to interface '$IFACE'" >&2
  apply_profile "$PROFILE" "$IFACE"
  APPLIED_PROFILE=1
elif [ "$PROFILE" = "off" ]; then
  apply_profile "off" "$IFACE"
  exit 0
fi

"$BINARY" "${PASSTHRU[@]}"
