#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
    echo "Usage: $0 SERVER.csv CLIENT.csv OUTPUT.csv" >&2
    exit 2
fi

server_file=$1
client_file=$2
output_file=$3

metric() {
    local file=$1 key=$2
    awk -F, -v wanted="$key" '$1 == wanted { print $2; exit }' "$file"
}

server_offline=$(metric "$server_file" time_offline_comp)
server_setup=$(metric "$server_file" time_setup_server_oprf_keygen)
server_oprf=$(metric "$server_file" time_online_server_oprf_comp)
server_fhe=$(metric "$server_file" time_online_server_fhe_comp)
client_setup=$(metric "$client_file" time_setup)
setup_total=$(awk -v a="$server_setup" -v b="$client_setup" 'BEGIN { printf "%.6f", a+b }')
client_comp=$(metric "$client_file" time_online_client_comp)
online_wall=$(metric "$client_file" time_online_wall)
online_comp=$(awk -v a="$server_oprf" -v b="$server_fhe" -v c="$client_comp" \
    'BEGIN { printf "%.6f", a+b+c }')
online_comm=$(awk -v wall="$online_wall" -v setup="$client_setup" \
    -v a="$server_oprf" -v b="$server_fhe" -v c="$client_comp" \
    'BEGIN { value=wall-setup-a-b-c; if (value<0) value=0; printf "%.6f", value }')
total_comp=$(awk -v setup="$setup_total" -v offline="$server_offline" -v online="$online_comp" \
    'BEGIN { printf "%.6f", setup+offline+online }')

mkdir -p "$(dirname "$output_file")"
{
    echo "metrics_schema_version,2"
    echo "task,1"
    echo "task_name,PSUca_C"
    echo "protocol,UPSICA_VBF_slicing"
    echo "element_bits,$(metric "$client_file" element_bits)"
    echo "server_set,$(metric "$server_file" sender_set)"
    echo "client_set,$(metric "$client_file" receiver_set)"
    echo "intersection_cardinality,$(metric "$client_file" intersection_cardinality)"
    echo "union_cardinality,$(metric "$client_file" union_cardinality)"
    echo "time_setup,$setup_total"
    echo "time_setup_server_oprf_keygen,$server_setup"
    echo "time_setup_client_fhe_keygen,$client_setup"
    echo "comm_setup,$(metric "$client_file" comm_setup)"
    echo "time_offline_comp,$server_offline"
    echo "time_offline_comm,0"
    echo "comm_offline,0"
    echo "time_online_comp,$online_comp"
    echo "time_online_comm,$online_comm"
    echo "comm_online,$(metric "$client_file" comm_online)"
    echo "time_total_comp,$total_comp"
    echo "comm_total,$(metric "$client_file" comm_total)"
    echo "comm_online_upload,$(metric "$client_file" comm_online_upload)"
    echo "comm_online_download,$(metric "$client_file" comm_online_download)"
    echo "time_online_server_oprf_comp,$server_oprf"
    echo "time_online_server_fhe_comp,$server_fhe"
    echo "time_online_client_comp,$client_comp"
    echo "time_online_wall,$online_wall"
    echo "maximum_sub_bin_degree,$(metric "$server_file" maximum_sub_bin_degree)"
    echo "oprf_requests,1"
    echo "fhe_queries,1"
} > "$output_file"
