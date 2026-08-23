#!/bin/bash

# ==========================================
# ==========================================

SERVER_IP="1.2.3.4" 
IFACE="eth0"        

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

SERVER_SET=$((1 << 30))
EFFECTIVE_BITLENGTH=32

PROFILES=("lan" "wan-100Mbps" "wan-10Mbps" "wan-1Mbps")
HW_LIST=(7 8)
CLIENT_FACTORS=(1 2)

tc qdisc del dev "$IFACE" root 2>/dev/null

set_network_profile() {
    local profile=$1
    echo "Applying network profile: $profile on $IFACE..."
    tc qdisc del dev "$IFACE" root 2>/dev/null
    
    case $profile in
        "lan")
            ;;
        "wan-100Mbps")
            tc qdisc add dev "$IFACE" root netem delay 20ms rate 100mbit
            ;;
        "wan-10Mbps")
            tc qdisc add dev "$IFACE" root netem delay 50ms rate 10mbit
            ;;
        "wan-1Mbps")
            tc qdisc add dev "$IFACE" root netem delay 100ms rate 1mbit
            ;;
    esac
}

get_log_poly_degree() {
    local hw=$1
    if [ "$hw" -eq 7 ]; then
        echo 13
    elif [ "$hw" -eq 8 ]; then
        echo 14
    else
        echo 13
    fi
}

for profile in "${PROFILES[@]}"; do
    
    set_network_profile "$profile"
    
    for hw in "${HW_LIST[@]}"; do
        
        LOG_POLY_DEGREE=$(get_log_poly_degree "$hw")
        
        for factor in "${CLIENT_FACTORS[@]}"; do
            
            if [ "$factor" -eq 1 ]; then
                # client_size = 1 << log_poly_degree
                CLIENT_SIZE=$((1 << LOG_POLY_DEGREE))
            else
                # client_size = 1 << (log_poly_degree + 1)
                CLIENT_SIZE=$((1 << (LOG_POLY_DEGREE + 1)))
            fi
            
            OUT_FILE="${RESULTS_DIR}/eff_${EFFECTIVE_BITLENGTH}_hw_${hw}_${profile}_client_${CLIENT_SIZE}"
            
            echo "--------------------------------------------------"
            echo "Running Task: HW=$hw, Profile=$profile, Client Size=$CLIENT_SIZE"
            
            ./build/bin/client \
                --server_ip "$SERVER_IP" \
                --server_set "$SERVER_SET" \
                --client_set "$CLIENT_SIZE" \
                --effective_bitlength "$EFFECTIVE_BITLENGTH" \
                --hamming_weight "$hw" > "${OUT_FILE}"
            
            echo "Saved results to ${OUT_FILE}"
            
            sleep 5 
        done
    done
done

tc qdisc del dev "$IFACE" root 2>/dev/null
echo "All tasks completed successfully. Network limits removed."