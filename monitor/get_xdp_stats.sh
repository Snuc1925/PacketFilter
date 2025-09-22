#!/bin/bash

# Script to monitor CPU usage of an XDP program in real-time
# Logs every second into ebpf_cpu_usage.log
# Usage: ./get_xdp_stats_cpu.sh xdp_filter

if [ -z "$1" ]; then
    echo "Usage: $0 <program_name>"
    exit 1
fi

PROG_NAME="$1"
LOG_FILE="ebpf_cpu_usage.log"

# Initialize variables for previous values
PREV_RUN_TIME_NS=0
PREV_RUN_CNT=0
FIRST_RUN=true

# --- Function to fetch BPF program stats ---
get_bpf_stats() {
    local prog_id
    # Get program ID
    prog_id=$(sudo bpftool prog show | grep -A1 "name $PROG_NAME" | head -n1 | awk '{print $1}' | tr -d ':')

    if [ -z "$prog_id" ]; then
        echo "❌ Program named $PROG_NAME not found. Waiting..." >&2
        CURRENT_RUN_TIME_NS=0
        CURRENT_RUN_CNT=0
        return 1
    fi

    # Fetch run_time_ns and run_cnt
    local stats_output
    stats_output=$(sudo bpftool prog show id "$prog_id" | grep -E "run_time_ns|run_cnt")

    # Check if stats are available
    if echo "$stats_output" | grep -q "run_time_ns"; then
        CURRENT_RUN_TIME_NS=$(echo "$stats_output" | grep "run_time_ns" | awk '{for(i=1;i<=NF;i++){if($i=="run_time_ns"){print $(i+1)}}}')
    else
        CURRENT_RUN_TIME_NS=0
    fi

    if echo "$stats_output" | grep -q "run_cnt"; then
        CURRENT_RUN_CNT=$(echo "$stats_output" | grep "run_cnt" | awk '{print $NF}')
    else
        CURRENT_RUN_CNT=0
    fi
    return 0
}

# --- Cleanup function when script is interrupted (Ctrl+C) ---
cleanup() {
    echo -e "\n🛑 Stopping XDP CPU monitoring. Data has been saved to $LOG_FILE"
    exit 0
}

# Trap SIGINT (Ctrl+C)
trap cleanup SIGINT

echo "Starting CPU monitoring for XDP program '$PROG_NAME'..."
echo "Data will be written to file: $LOG_FILE"
echo "Timestamp %CPU" > "$LOG_FILE" # Write header to log file

# --- Main monitoring loop ---
while true; do
    get_bpf_stats
    
    # If program not found, retry
    if [ $? -ne 0 ]; then
        sleep 1
        continue
    fi

    TIMESTAMP=$(date +"%H:%M:%S")

    if [ "$FIRST_RUN" = true ]; then
        # First run: only store initial values, skip CPU calc
        echo "✅ Monitoring initialized for $PROG_NAME (ID: $PROG_ID). Skipping first %CPU calculation."
        PREV_RUN_TIME_NS="$CURRENT_RUN_TIME_NS"
        PREV_RUN_CNT="$CURRENT_RUN_CNT"
        FIRST_RUN=false
        # Log init line
        echo "$TIMESTAMP  Init" >> "$LOG_FILE"
    else
        # Calculate differences
        DIFF_RUN_TIME_NS=$((CURRENT_RUN_TIME_NS - PREV_RUN_TIME_NS))

        # Handle reset or abnormal decrease
        if (( DIFF_RUN_TIME_NS < 0 )); then
            echo "⚠️ run_time_ns decreased unexpectedly or counter reset. Resetting values." >&2
            DIFF_RUN_TIME_NS=0
        fi
        
        # Calculate %CPU
        # 1 second = 1,000,000,000 nanoseconds
        CPU_PERCENT=$(awk -v v="$DIFF_RUN_TIME_NS" 'BEGIN{printf "%.2f", (v/1000000000)*100}')

        echo "$TIMESTAMP  $CPU_PERCENT"
        echo "$TIMESTAMP  $CPU_PERCENT" >> "$LOG_FILE"

        # Update values for next loop
        PREV_RUN_TIME_NS="$CURRENT_RUN_TIME_NS"
        PREV_RUN_CNT="$CURRENT_RUN_CNT"
    fi

    sleep 1
done
