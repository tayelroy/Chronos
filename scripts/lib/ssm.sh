# Shared AWS SSM helpers for Chronos scripts (source, don't execute).
# Uses whatever credentials the AWS CLI resolves (e.g. `export AWS_PROFILE=chronos`).

CHRONOS_SOC_ID="i-073658c52d98d9975"
CHRONOS_SENSOR_ID="i-024b46954f573b978"
CHRONOS_REMOTE_DIR="/home/ssm-user/Chronos"

# ssm_run <instance-id> <script>: run a bash script on the instance, print its output,
# return non-zero if it failed.
ssm_run() {
  local id="$1" script="$2" cmd status params
  # AWS-RunShellScript uses /bin/sh (dash on Ubuntu); run the payload under bash via a quoted heredoc.
  params=$(python3 - "$script" <<'PY'
import json, sys
wrapped = "bash <<'CHRONOS_EOF'\n" + sys.argv[1] + "\nCHRONOS_EOF"
print(json.dumps({"commands": [wrapped], "executionTimeout": ["1800"]}))
PY
)
  cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
    --parameters "$params" --query Command.CommandId --output text)
  while :; do
    sleep 3
    status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status --output text 2>/dev/null || echo Pending)
    case "$status" in Pending|InProgress|Delayed) printf . ;; *) break ;; esac
  done
  echo " [$status]"
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardOutputContent --output text
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardErrorContent --output text >&2
  [[ "$status" == Success ]]
}

# wait_ssm <instance-id>...: block until each instance's SSM agent reports Online (5 min cap each).
wait_ssm() {
  local id state
  for id in "$@"; do
    printf "[*] Waiting for SSM on %s " "$id"
    for _ in $(seq 1 60); do
      state=$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$id" \
        --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
      if [[ "$state" == Online ]]; then echo "[Online]"; continue 2; fi
      printf .
      sleep 5
    done
    echo "[timeout]"
    return 1
  done
}

# ensure_running <instance-id>...: start any stopped instance, wait for running + SSM.
ensure_running() {
  local stopped
  stopped=$(aws ec2 describe-instances --instance-ids "$@" \
    --query 'Reservations[].Instances[?State.Name==`stopped`].InstanceId' --output text)
  if [[ -n "$stopped" ]]; then
    echo "[*] Starting $stopped"
    # shellcheck disable=SC2086  # word-split the id list on purpose
    aws ec2 start-instances --instance-ids $stopped >/dev/null
  fi
  aws ec2 wait instance-running --instance-ids "$@"
  wait_ssm "$@"
}
