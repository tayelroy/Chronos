#!/bin/bash
# Chronos deploy over AWS SSM (no SSH). Run from the Mac:
#   scripts/deploy.sh core   [git-ref]   # SIEM + TheHive + triage on chronos-soc-core
#   scripts/deploy.sh sensor [git-ref]   # Cowrie + canary + Vector shipper on chronos-sensor
# The instance pulls <git-ref> (default: current local branch) from origin, so push first.
set -euo pipefail

SOC_ID="i-073658c52d98d9975"
SENSOR_ID="i-024b46954f573b978"
REMOTE_DIR="/home/ssm-user/Chronos"
TARGET="${1:?usage: deploy.sh core|sensor [git-ref]}"
REF="${2:-$(git rev-parse --abbrev-ref HEAD)}"

ssm_run() {  # ssm_run <instance-id> <script>; prints remote output, exits non-zero on failure
  local id="$1" script="$2" cmd status
  # AWS-RunShellScript uses /bin/sh (dash on Ubuntu); run the payload under bash via a quoted heredoc.
  local params
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

checkout="set -euo pipefail
cd $REMOTE_DIR
sudo -u ssm-user git fetch --quiet origin
sudo -u ssm-user git checkout --quiet '$REF'
sudo -u ssm-user git reset --quiet --hard 'origin/$REF'
echo \"[+] $REMOTE_DIR at \$(sudo -u ssm-user git log --oneline -1)\""

case "$TARGET" in
  core)
    ssm_run "$SOC_ID" "$checkout
mkdir -p replay
if ! grep -q '^THEHIVE_SECRET_KEY=' .env 2>/dev/null; then
  echo \"THEHIVE_SECRET_KEY=\$(openssl rand -hex 32)\" >> .env
fi
chmod 600 .env
sysctl -qw vm.max_map_count=262144
grep -q '^vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
docker compose -f docker-compose.core.yml up -d --build opensearch opensearch-dashboards thehive vector-core
python3 scripts/core-bootstrap.py
docker compose -f docker-compose.core.yml up -d --build --remove-orphans
docker compose -f docker-compose.core.yml ps --format 'table {{.Name}}\t{{.Status}}'"
    ;;
  sensor)
    CORE_IP=$(aws ec2 describe-instances --instance-ids "$SOC_ID" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
    ssm_run "$SENSOR_ID" "$checkout
# Real sshd off :22 so Cowrie can own it (admin access is SSM-only anyway).
if ! grep -q '^Port 22222' /etc/ssh/sshd_config; then
  sed -i 's/^#\\?Port .*/Port 22222/' /etc/ssh/sshd_config
  grep -q '^Port 22222' /etc/ssh/sshd_config || echo 'Port 22222' >> /etc/ssh/sshd_config
  systemctl restart sshd
fi
# Compose builds need buildx >= 0.17; the AL2023 docker package ships 0.12.
if ! docker buildx version 2>/dev/null | grep -qE ' v0\\.(1[7-9]|[2-9][0-9])\\.'; then
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-buildx \
    https://github.com/docker/buildx/releases/download/v0.37.1/buildx-v0.37.1.linux-arm64
  chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
fi
# 1 GB swap: t4g.micro has 1 GB RAM.
if ! swapon --show | grep -q /swapfile; then
  [ -f /swapfile ] || { dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none; chmod 600 /swapfile; mkswap /swapfile >/dev/null; }
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
mkdir -p logs/cowrie logs/cowrie-tty logs/cowrie-downloads logs/canary
chown -R 999:999 logs/cowrie logs/cowrie-tty logs/cowrie-downloads
echo 'CHRONOS_CORE_ADDR=$CORE_IP:9002' > .env
docker compose -f docker-compose.edge.yml up -d --build --remove-orphans
docker compose -f docker-compose.edge.yml ps --format 'table {{.Name}}\t{{.Status}}'
ss -tlnp | grep -E ':(22|23|80|22222) '"
    ;;
  *)
    echo "usage: deploy.sh core|sensor [git-ref]" >&2
    exit 2
    ;;
esac
