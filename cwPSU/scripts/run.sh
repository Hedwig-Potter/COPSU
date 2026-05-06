#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法: scripts/run.sh [--profile lan|wan-100|wan-10|wan-1|off] [--iface <网卡>] [--] [程序参数...]
示例: scripts/run.sh --profile lan -- --effective_bitlength 114 --hamming_weight 19

可选网络配置:
  lan     : 10 Gbps, RTT ≈ 0.2 ms (单向 0.1 ms)
  wan-100 : 100 Mbps, RTT ≈ 80 ms (单向 40 ms)
  wan-10  : 10 Mbps, RTT ≈ 80 ms (单向 40 ms)
  wan-1   : 1 Mbps, RTT ≈ 80 ms (单向 40 ms)
  off     : 清理当前 tc 设置后退出

可通过环境变量 NETEM_IFACE 指定默认网卡 (默认 lo)。
EOF
  exit 0
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/build/main-cwpsu"
if [ ! -f "$BINARY" ]; then
  echo "Binary not found: $BINARY" >&2
  echo "请先运行 cmake && ninja 构建 main-cwpsu" >&2
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
  clear_profile "$iface"
  case "$profile" in
    lan)
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 0.1ms rate 10gbit limit 100000
      ;;
    wan-100)
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 40ms rate 100mbit limit 50000
      ;;
    wan-10)
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 40ms rate 10mbit limit 50000
      ;;
    wan-1)
      ${SUDO:+$SUDO }tc qdisc replace dev "$iface" root handle 1:0 \
        netem delay 40ms rate 1mbit limit 50000
      ;;
    off|"")
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
  clear_profile "$IFACE"
  exit 0
fi

profile_tag="$PROFILE"
if [ -z "$profile_tag" ]; then
  profile_tag="${NETEM_PROFILE:-native}"
fi
if [ -z "$profile_tag" ]; then
  profile_tag="native"
fi

NETEM_PROFILE="$profile_tag" "$BINARY" "${PASSTHRU[@]}"
