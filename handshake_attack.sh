#!/usr/bin/env bash
# handshake_attack.sh
# Simulate handshake-heavy short-lived TCP connections using iperf3 inside a network namespace.
# Place in ~/Manh/PacketFilter, chmod +x handshake_attack.sh
#
# Usage example:
# ./handshake_attack.sh -t 192.168.100.1 -p 5201 --workers 50 --conn-time 1 --pause 0.02 --duration 80
#
set -euo pipefail

# Defaults
TARGET="192.168.100.1"
PORT=80
WORKERS=5          # number of parallel worker processes
CONN_TIME=1         # iperf3 -t (seconds) per connection (short-lived)
PAUSE=0.02          # pause between connections inside each worker (seconds)
DURATION=60         # total run time of the whole test (seconds)
NAMESPACE="attacker-ns"
CPU_CORE=""         # e.g. "0" or empty for no pinning
LOGDIR="./handshake_logs"
VERBOSE=0

print_help() {
  cat <<EOF
handshake_attack.sh - simulate many short-lived TCP connections (handshake-heavy)

Options:
  -t, --target       target IP (default ${TARGET})
  -p, --port         target port (default ${PORT})
  --workers          number of parallel workers (default ${WORKERS})
  --conn-time        duration in seconds for each iperf3 run (default ${CONN_TIME})
  --pause            pause (s) between successive connections inside each worker (default ${PAUSE})
  --duration         total test duration in seconds (default ${DURATION})
  --ns               network namespace to run in (default ${NAMESPACE})
  --cpu              CPU core to taskset pin workers to (optional)
  -v                 verbose
  -h                 show this help
EOF
}

# parse args (simple)
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    -p|--port) PORT="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --conn-time) CONN_TIME="$2"; shift 2 ;;
    --pause) PAUSE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --ns) NAMESPACE="$2"; shift 2 ;;
    --cpu) CPU_CORE="$2"; shift 2 ;;
    -v) VERBOSE=1; shift ;;
    -h) print_help; exit 0 ;;
    *) echo "Unknown arg $1"; print_help; exit 1 ;;
  esac
done

mkdir -p "${LOGDIR}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
MAIN_LOG="${LOGDIR}/handshake_attack_${TIMESTAMP}.log"

echo "Starting handshake-heavy attack simulation" | tee -a "${MAIN_LOG}"
echo "target=${TARGET}:${PORT} workers=${WORKERS} conn_time=${CONN_TIME}s pause=${PAUSE}s duration=${DURATION}s ns=${NAMESPACE} cpu=${CPU_CORE}" | tee -a "${MAIN_LOG}"

# check required tools
if ! command -v iperf3 >/dev/null 2>&1; then
  echo "Error: iperf3 not found in PATH" | tee -a "${MAIN_LOG}"
  exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
  echo "Error: ip (iproute2) not found" | tee -a "${MAIN_LOG}"
  exit 1
fi

if ! ip netns list | grep -q "^${NAMESPACE}\b"; then
  echo "Warning: namespace '${NAMESPACE}' not found. Continue? (Ctrl-C to abort)" | tee -a "${MAIN_LOG}"
  sleep 2
fi

PIDS=()
WORKER_LOGS=()

cleanup() {
  echo "Cleaning up..." | tee -a "${MAIN_LOG}"
  for p in "${PIDS[@]:-}"; do
    if kill -0 "$p" >/dev/null 2>&1; then
      echo " Killing PID $p" | tee -a "${MAIN_LOG}"
      kill "$p" 2>/dev/null || kill -9 "$p" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
  echo "Finished cleanup" | tee -a "${MAIN_LOG}"
}
trap cleanup EXIT INT TERM

# Start workers
for i in $(seq 1 "${WORKERS}"); do
  worker_log="${LOGDIR}/worker_${i}_${TIMESTAMP}.log"
  WORKER_LOGS+=("${worker_log}")

  (
    # Each worker: loop until killed
    while true; do
      if [[ -n "${CPU_CORE}" ]]; then
        CMD="sudo ip netns exec ${NAMESPACE} taskset -c ${CPU_CORE} iperf3 -c ${TARGET} -p ${PORT} -t ${CONN_TIME} --interval 0.5"
      else
        CMD="sudo ip netns exec ${NAMESPACE} iperf3 -c ${TARGET} -p ${PORT} -t ${CONN_TIME} --interval 0.5"
      fi

      # run and ignore non-zero exit
      if [[ "${VERBOSE}" -eq 1 ]]; then
        echo "[$(date +%T)] worker ${i} run: ${CMD}" >> "${worker_log}"
        bash -c "${CMD}" >> "${worker_log}" 2>&1 || true
      else
        bash -c "${CMD}" >/dev/null 2>> "${worker_log}" || true
      fi

      # short pause to control connection creation rate
      # allow fractional sleep
      sleep "${PAUSE}"
    done
  ) &
  PIDS+=($!)
done

echo "Spawned ${#PIDS[@]} workers (PIDs: ${PIDS[*]})" | tee -a "${MAIN_LOG}"
echo "Running for ${DURATION}s..." | tee -a "${MAIN_LOG}"

sleep "${DURATION}"

echo "Time elapsed. Killing workers..." | tee -a "${MAIN_LOG}"
for p in "${PIDS[@]}"; do
  if kill -0 "$p" >/dev/null 2>&1; then
    kill "$p" 2>/dev/null || kill -9 "$p" 2>/dev/null || true
  fi
done

# wait briefly for graceful exit
sleep 1
echo "Done. Logs in ${LOGDIR}" | tee -a "${MAIN_LOG}"
