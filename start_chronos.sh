#!/bin/bash
SOC_ID="i-073658c52d98d9975"

echo "=================================================="
echo "Chronos SOC Orchestrator ($SOC_ID)"
echo "=================================================="

# 1. Pre-flight check: Verify EC2 SSM connectivity
printf "Checking EC2 SSM status... "
PING_STATUS=$(aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=$SOC_ID" \
  --query "InstanceInformationList[0].PingStatus" \
  --output text 2>/dev/null)

if [ "$PING_STATUS" != "Online" ]; then
    echo "[FAIL] Offline"
    echo "Instance $SOC_ID is currently: ${PING_STATUS:-Not Found/Stopped}."
    echo "Please start the instance: aws ec2 start-instances --instance-ids $SOC_ID"
    exit 1
fi
echo "[OK] Online"

# 2. Remote Docker Startup & docker ps via SSM
printf "Starting Docker containers on EC2 & retrieving status... "
CMD_ID=$(aws ssm send-command \
  --instance-ids "$SOC_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["cd /home/ssm-user/Chronos && docker compose -f docker-compose.core.yml up -d && docker ps"]' \
  --query "Command.CommandId" \
  --output text 2>/dev/null)

if [ -z "$CMD_ID" ]; then
    echo -e "\n[ERROR] Failed to trigger SSM command on instance."
    exit 1
fi

while true; do
    STATUS=$(aws ssm get-command-invocation \
      --command-id "$CMD_ID" \
      --instance-id "$SOC_ID" \
      --query "Status" \
      --output text 2>/dev/null)
    if [ "$STATUS" = "Success" ] || [ "$STATUS" = "Failed" ] || [ "$STATUS" = "TimedOut" ]; then
        break
    fi
    sleep 2
    printf "."
done
echo " [OK] Done ($STATUS)"

echo -e "\n--- Live Remote Docker Containers (docker ps) ---"
aws ssm get-command-invocation \
  --command-id "$CMD_ID" \
  --instance-id "$SOC_ID" \
  --query "StandardOutputContent" \
  --output text
echo "---------------------------------------------------"

# 3. Clean up any stale/dangling local SSM tunnel processes
pkill -f "AWS-StartPortForwardingSession.*(9000|5601|9200)" 2>/dev/null || true
sleep 1

# 4. Launch Tunnels directly in the main shell
echo -e "\nStarting background SSM tunnels..."

aws ssm start-session \
  --target "$SOC_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["9000"],"localPortNumber":["9000"]}' >/dev/null 2>&1 &
PID_THEHIVE=$!

aws ssm start-session \
  --target "$SOC_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["5601"],"localPortNumber":["5601"]}' >/dev/null 2>&1 &
PID_DASHBOARDS=$!

aws ssm start-session \
  --target "$SOC_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["9200"],"localPortNumber":["9200"]}' >/dev/null 2>&1 &
PID_OPENSEARCH=$!

# Cleanup handler: ONLY triggers when you press Ctrl+C or kill the script
cleanup() {
    echo -e "\n\nStopping all background SSM tunnels..."
    kill $PID_THEHIVE $PID_DASHBOARDS $PID_OPENSEARCH 2>/dev/null
    echo "Tunnels closed cleanly. Exiting."
    exit 0
}
trap cleanup SIGINT SIGTERM

# 5. Health Check Function
check_service() {
    local name="$1"
    local url="$2"
    local pid="$3"
    local max_wait="${4:-20}"
    local count=0

    printf "  * Checking %-22s (%s) " "$name" "$url"
    while [ $count -lt $max_wait ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo -e "\n    [ERROR] Tunnel process ($pid) terminated unexpectedly."
            return 1
        fi

        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null)
        if [ "$code" != "000" ] && [ -n "$code" ]; then
            echo "-> [OK] Connected (HTTP $code)"
            return 0
        fi

        sleep 2
        count=$((count + 2))
        printf "."
    done

    echo -e "\n    [WARN] Unreachable (HTTP $code after ${max_wait}s)."
    return 1
}

# 6. Verify connectivity end-to-end
echo -e "\nVerifying service responses..."
THEHIVE_READY=0
DASHBOARDS_READY=0
OPENSEARCH_READY=0

check_service "TheHive 5" "http://localhost:9000" "$PID_THEHIVE" 16 && THEHIVE_READY=1
check_service "OpenSearch Dashboards" "http://localhost:5601" "$PID_DASHBOARDS" 16 && DASHBOARDS_READY=1
check_service "OpenSearch API" "http://localhost:9200/_cluster/health" "$PID_OPENSEARCH" 16 && OPENSEARCH_READY=1

# 7. Launch browser tabs
echo ""
if [ $THEHIVE_READY -eq 1 ] && [ $DASHBOARDS_READY -eq 1 ]; then
    echo "[INFO] All services verified. Opening dashboards in default browser..."
    open "http://localhost:9000"
    open "http://localhost:5601"
elif [ $THEHIVE_READY -eq 1 ]; then
    open "http://localhost:9000"
fi

echo -e "\n[All tunnels active (9000, 5601, 9200). Keep this terminal open. Press Ctrl+C to disconnect all.]"

# 8. Block and keep tunnels running indefinitely
wait $PID_THEHIVE $PID_DASHBOARDS $PID_OPENSEARCH
