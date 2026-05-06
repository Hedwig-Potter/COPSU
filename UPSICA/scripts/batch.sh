#!/bin/bash

# ==========================================
# UPSI-CA Benchmark 自动化测试脚本
# ==========================================

# 确保脚本遇到错误时停止执行
set -e

# 如果用户按 Ctrl+C，自动执行清理网卡规则的函数
trap cleanup EXIT INT TERM

# 获取脚本文件所在的真实目录 (scripts/)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# 项目根目录就是 scripts 的上一级
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# 这样无论你在哪运行，路径都是绝对且正确的
EXEC_BIN="$PROJECT_ROOT/build/upsica_cli"
CSV_DIR="$PROJECT_ROOT/results"

# ==========================================
# 参数配置
# ==========================================
# 元素比特长度: 32bit, 128bit
BIT_LENGTHS=(32 128)

# Sender 集合大小 (nx): 2^18, 2^20, 2^22
NX_SIZES=($((1<<18)) $((1<<20)) $((1<<22)))

# Receiver 集合大小 (ny): 2^10
NY_SIZE=$((1<<10))

# ==========================================
# 函数: 清理网络限制规则
# ==========================================
cleanup() {
    echo "[!] 正在清理本地回环网卡(lo)的流量控制规则..."
    # 忽略错误输出，因为如果没有规则直接删除会报错
    sudo tc qdisc del dev lo root 2>/dev/null || true
    echo "[!] 清理完成。"
}

# ==========================================
# 函数: 设置网络环境
# ==========================================
set_network() {
    local env_name=$1
    
    # 每次设置前先清空旧规则
    sudo tc qdisc del dev lo root 2>/dev/null || true

    echo "=================================================="
    echo ">>>> 正在配置网络环境: $env_name <<<<"
    
    case $env_name in
        "LAN")
            # 10 Gbps, RTT = 0.2ms (单向 delay 0.1ms)
            sudo tc qdisc add dev lo root netem rate 10gbit delay 0.1ms
            ;;
        "WAN_100M")
            # 100 Mbps, RTT = 80ms (单向 delay 40ms)
            sudo tc qdisc add dev lo root netem rate 100mbit delay 40ms
            ;;
        "WAN_10M")
            # 10 Mbps, RTT = 80ms (单向 delay 40ms)
            sudo tc qdisc add dev lo root netem rate 10mbit delay 40ms
            ;;
        "WAN_1M")
            # 1 Mbps, RTT = 80ms (单向 delay 40ms)
            sudo tc qdisc add dev lo root netem rate 1mbit delay 40ms
            ;;
        *)
            echo "未知的网络环境: $env_name"
            exit 1
            ;;
    esac
}

# ==========================================
# 主执行循环
# ==========================================

# 确保可执行文件存在
if [ ! -f "$EXEC_BIN" ]; then
    echo "错误: 找不到可执行文件 $EXEC_BIN，请先编译。"
    exit 1
fi

echo "测试开始，结果将写入: $CSV_DIR"

# 定义要测试的网络环境数组
NETWORKS=("LAN" "WAN_100M" "WAN_10M" "WAN_1M")

for NET in "${NETWORKS[@]}"; do
    # 1. 切换并应用对应的网卡规则
    set_network $NET
    
    for BIT in "${BIT_LENGTHS[@]}"; do
        for NX in "${NX_SIZES[@]}"; do
            
            echo "[Run] Network: $NET | Bits: $BIT | nx: $NX | ny: $NY_SIZE"
            
            # 1. 动态拼接文件名
            CSV_NAME="element_${BIT}_server_${NX}_${NET}.csv"
            
            # 2. 使用绝对路径变量 CSV_DIR
            CSV_FULL_PATH="${CSV_DIR}/${CSV_NAME}"

            # 确保目录存在
            mkdir -p "$CSV_DIR"
            
            # 3. 将路径作为第 5 个参数传递给 C++ 核心程序
            # 传参顺序：<nx> <ny> <bit_length> <net_env> <csv_path>
            $EXEC_BIN $NX $NY_SIZE $BIT $NET "$CSV_FULL_PATH"
            
            # 每次运行完休息 1 秒，确保 TCP 端口 TIME_WAIT 状态释放
            sleep 1
            
        done
    done
done

echo "=================================================="
echo "所有测试运行完毕！结果已保存至 $CSV_FILE"