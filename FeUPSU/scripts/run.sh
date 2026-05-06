#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法: scripts/run.sh [--profile lan|wan-100|wan-10|wan-1|off] [--iface <网卡>] [--] [程序参数...]

示例:
  scripts/run.sh --profile lan -- --effective_bitlength 114 --hw 32

可用网络配置:
  lan     : 模拟 10 Gbps, RTT≈0.2 ms (单向 0.1 ms)
  wan-100 : 模拟 100 Mbps, RTT≈80 ms (单向 40 ms)
  wan-10  : 模拟 10 Mbps, RTT≈80 ms (单向 40 ms)
  wan-1   : 模拟 1 Mbps, RTT≈80 ms (单向 40 ms)
  off     : 仅清除现有的 tc 设置

可通过环境变量 NETEM_IFACE 指定默认网卡 (默认为 lo)。
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
        echo "--profile 需要一个参数" >&2
        exit 1
      fi
      PROFILE="$2"
      shift 2
      ;;
    --iface)
      if (($# < 2)); then
        echo "--iface 需要一个参数" >&2
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
      echo "未知的网络配置: $profile" >&2
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
  echo "[run.sh] 应用网络配置 '$PROFILE' 于接口 '$IFACE'" >&2
  apply_profile "$PROFILE" "$IFACE"
  APPLIED_PROFILE=1
elif [ "$PROFILE" = "off" ]; then
  apply_profile "off" "$IFACE"
  exit 0
fi

"$BINARY" "${PASSTHRU[@]}"
