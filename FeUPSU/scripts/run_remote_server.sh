#!/bin/bash

# ==========================================
# ==========================================

SERVER_SET=$((1 << 30))
EFFECTIVE_BITLENGTH=32

echo "=============================================="
echo "Starting FeUPSU Server..."
echo "Fixed Server Set Size: $SERVER_SET"
echo "Effective Bitlength: $EFFECTIVE_BITLENGTH"
echo "Press [Ctrl+C] to stop."
echo "=============================================="

while true; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Server is listening for incoming connections..."
    
    ./build/bin/server \
        --server_set "$SERVER_SET" \
        --effective_bitlength "$EFFECTIVE_BITLENGTH"
    
    sleep 2
done