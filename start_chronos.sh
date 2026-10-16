#!/bin/bash
# Start Chronos end to end over AWS SSM (no SSH, no open admin ports):
#   1. start both EC2 instances if they are stopped, wait for their SSM agents
#   2. docker compose up on the sensor and on the SOC core
#   3. port-forward Dashboards (5601), TheHive (9000), OpenSearch API (9200) to localhost
#      and keep the tunnels open until Ctrl+C
# Usage: ./start_chronos.sh [--no-tunnels]
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/lib/ssm.sh
source scripts/lib/ssm.sh

TUNNELS=1
[[ "${1:-}" == "--no-tunnels" ]] && TUNNELS=0

cat <<'BANNER'

   ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ███████╗
  ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗██╔════╝
  ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║   ██║███████╗
  ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║╚════██║
  ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝███████║
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
        honeypot sensor  ──▶  SIEM  ──▶  case management

BANNER
echo "  sensor $CHRONOS_SENSOR_ID · core $CHRONOS_SOC_ID"
echo

ensure_running "$CHRONOS_SENSOR_ID" "$CHRONOS_SOC_ID"

printf "[*] Sensor containers"
ssm_run "$CHRONOS_SENSOR_ID" "cd $CHRONOS_REMOTE_DIR && docker compose -f docker-compose.edge.yml up -d >/dev/null 2>&1 && docker compose -f docker-compose.edge.yml ps --format 'table {{.Name}}\t{{.Status}}'"
printf "[*] Core containers"
ssm_run "$CHRONOS_SOC_ID" "cd $CHRONOS_REMOTE_DIR && docker compose -f docker-compose.core.yml up -d >/dev/null 2>&1 && docker compose -f docker-compose.core.yml ps --format 'table {{.Name}}\t{{.Status}}'"

(( TUNNELS )) || exit 0

# Replace any stale tunnels from a previous run.
pkill -f "AWS-StartPortForwardingSession.*(9000|5601|9200|8000)" 2>/dev/null || true
sleep 1
tunnel() {  # tunnel <remote-and-local-port>; runs in this shell so $! is a child we can wait on
  aws ssm start-session --target "$CHRONOS_SOC_ID" --document-name AWS-StartPortForwardingSession \
    --parameters "{\"portNumber\":[\"$1\"],\"localPortNumber\":[\"$1\"]}" >/dev/null 2>&1 &
}

echo "[*] Opening SSM tunnels"
tunnel 9000; PID_THEHIVE=$!
tunnel 5601; PID_DASHBOARDS=$!
tunnel 9200; PID_OPENSEARCH=$!
tunnel 8000; PID_SPLUNK=$!

cleanup() {
  echo -e "\n[*] Closing SSM tunnels"
  kill "$PID_THEHIVE" "$PID_DASHBOARDS" "$PID_OPENSEARCH" "$PID_SPLUNK" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM

check_service() {  # check_service <name> <url> <tunnel-pid> [max-wait-seconds]
  local name="$1" url="$2" pid="$3" max_wait="${4:-60}" waited=0 code=000
  printf "  * %-22s %-40s " "$name" "$url"
  while (( waited < max_wait )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[ERROR] tunnel exited"
      return 1
    fi
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || true)
    if [[ -n "$code" && "$code" != 000 ]]; then
      echo "[OK] HTTP $code"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
    printf .
  done
  echo "[WARN] no response after ${max_wait}s (services may still be starting)"
  return 1
}

# OpenSearch/TheHive take ~1-2 min after a cold boot, hence the generous wait.
THEHIVE_READY=0
DASHBOARDS_READY=0
check_service "TheHive" "http://localhost:9000" "$PID_THEHIVE" 180 && THEHIVE_READY=1
check_service "OpenSearch Dashboards" "http://localhost:5601" "$PID_DASHBOARDS" 180 && DASHBOARDS_READY=1
check_service "OpenSearch API" "http://localhost:9200/_cluster/health" "$PID_OPENSEARCH" 60 || true
check_service "Splunk" "http://localhost:8000/en-US/account/login" "$PID_SPLUNK" 180 || true

(( THEHIVE_READY )) && open "http://localhost:9000"
(( DASHBOARDS_READY )) && open "http://localhost:5601/app/dashboards#/view/chronos-overview"

echo -e "\n[Tunnels active on 9000, 5601, 9200, 8000. Keep this terminal open; Ctrl+C closes them.]"
echo "[Cost: the core is ~\$0.10/h while running. ./stop_chronos.sh stops it; the sensor keeps collecting.]"

# SSM closes idle sessions (20 min by default); reopen any tunnel that drops until Ctrl+C.
while :; do
  sleep 10
  kill -0 "$PID_THEHIVE" 2>/dev/null || { tunnel 9000; PID_THEHIVE=$!; echo "[*] $(date +%T) reopened tunnel 9000"; }
  kill -0 "$PID_DASHBOARDS" 2>/dev/null || { tunnel 5601; PID_DASHBOARDS=$!; echo "[*] $(date +%T) reopened tunnel 5601"; }
  kill -0 "$PID_OPENSEARCH" 2>/dev/null || { tunnel 9200; PID_OPENSEARCH=$!; echo "[*] $(date +%T) reopened tunnel 9200"; }
  kill -0 "$PID_SPLUNK" 2>/dev/null || { tunnel 8000; PID_SPLUNK=$!; echo "[*] $(date +%T) reopened tunnel 8000"; }
done
