#!/bin/bash
# Stop Chronos to save cost.
#   ./stop_chronos.sh         stop the SOC core only. The sensor keeps collecting; its Vector
#                             buffers to disk and delivers everything when the core starts again.
#   ./stop_chronos.sh --all   stop the sensor too (collection pauses).
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/lib/ssm.sh
source scripts/lib/ssm.sh

pkill -f "AWS-StartPortForwardingSession.*(9000|5601|9200)" 2>/dev/null || true

ids=("$CHRONOS_SOC_ID")
[[ "${1:-}" == "--all" ]] && ids+=("$CHRONOS_SENSOR_ID")

echo "[*] Stopping ${ids[*]}"
aws ec2 stop-instances --instance-ids "${ids[@]}" --query 'StoppingInstances[].[InstanceId,CurrentState.Name]' --output text
aws ec2 wait instance-stopped --instance-ids "${ids[@]}"
echo "[+] Stopped."
