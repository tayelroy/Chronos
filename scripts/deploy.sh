#!/bin/bash
# Chronos deploy over AWS SSM (no SSH). Run from the Mac:
#   scripts/deploy.sh core   [git-ref]   # SIEM + TheHive + triage on chronos-soc-core
#   scripts/deploy.sh sensor [git-ref]   # Cowrie + canary + Vector shipper on chronos-sensor
# The instance pulls <git-ref> (default: current local branch) from origin, so push first.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=lib/ssm.sh
source scripts/lib/ssm.sh

SOC_ID="$CHRONOS_SOC_ID"
SENSOR_ID="$CHRONOS_SENSOR_ID"
REMOTE_DIR="$CHRONOS_REMOTE_DIR"
TARGET="${1:?usage: deploy.sh core|sensor [git-ref]}"
REF="${2:-$(git rev-parse --abbrev-ref HEAD)}"

checkout="set -euo pipefail
cd $REMOTE_DIR
sudo -u ssm-user git fetch --quiet origin
sudo -u ssm-user git checkout --quiet '$REF'
sudo -u ssm-user git reset --quiet --hard 'origin/$REF'
echo \"[+] $REMOTE_DIR at \$(sudo -u ssm-user git log --oneline -1)\""

# Honeytoken settings live only in the gitignored local honeytokens.env (scripts/honeytokens-provision.sh;
# the repo is public). The sensor gets the bait key pairs; the core gets key ids, the reader role and the
# alert topic, never a secret.
honeytoken_lines() {
  [[ -f honeytokens.env ]] || { echo "[!] honeytokens.env not found: honeytokens stay off" >&2; return 0; }
  grep -E "$1" honeytokens.env || true
}

case "$TARGET" in
  core)
    CORE_HONEYTOKENS=$(honeytoken_lines '^HONEYTOKEN_([A-Z]+_AWS_KEY_ID|READER_ROLE_ARN|ALERT_TOPIC_ARN)=')
    if grep -q '^HONEYTOKEN_READER_ROLE_ARN=.' <<<"$CORE_HONEYTOKENS"; then
      CORE_HONEYTOKENS+=$'\nCOMPOSE_PROFILES=honeytokens'
      echo "[*] Honeytoken poller enabled"
    fi
    ssm_run "$SOC_ID" "$checkout
mkdir -p replay honeytoken
chown 65534:65534 honeytoken  # honeytoken poller runs as nobody
touch .env
sed -i '/^HONEYTOKEN_/d;/^COMPOSE_PROFILES=/d' .env
cat >> .env <<'ENV_EOF'
$CORE_HONEYTOKENS
ENV_EOF
if ! grep -q '^THEHIVE_SECRET_KEY=' .env 2>/dev/null; then
  echo \"THEHIVE_SECRET_KEY=\$(openssl rand -hex 32)\" >> .env
fi
chmod 600 .env
sysctl -qw vm.max_map_count=262144
grep -q '^vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
docker compose -f docker-compose.core.yml up -d --build opensearch opensearch-dashboards thehive vector-core
python3 scripts/core-bootstrap.py
docker compose -f docker-compose.core.yml up -d --build --remove-orphans
docker compose -f docker-compose.core.yml restart vector-core  # reload pipeline/catalog changes
docker compose -f docker-compose.core.yml ps --format 'table {{.Name}}\t{{.Status}}'"
    ;;
  sensor)
    CORE_IP=$(aws ec2 describe-instances --instance-ids "$SOC_ID" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
    HONEYTOKENS=$(honeytoken_lines '^HONEYTOKEN_(DOTENV|WPCONFIG|GIT|COWRIE)_AWS_(KEY_ID|SECRET)=')
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
# Containers run as non-root: cowrie uid 999, canary uid 10001 (honeypots/canary_http/Dockerfile).
chown -R 999:999 logs/cowrie logs/cowrie-tty logs/cowrie-downloads
chown -R 10001:10001 logs/canary
cat > .env <<'ENV_EOF'
CHRONOS_CORE_ADDR=$CORE_IP:9002
$HONEYTOKENS
ENV_EOF
chmod 600 .env
docker compose -f docker-compose.edge.yml up -d --build --remove-orphans
docker compose -f docker-compose.edge.yml restart vector-edge  # reload shipper config; checkpoints persist
docker compose -f docker-compose.edge.yml ps --format 'table {{.Name}}\t{{.Status}}'
ss -tlnp | grep -E ':(22|23|80|22222) '"
    ;;
  *)
    echo "usage: deploy.sh core|sensor [git-ref]" >&2
    exit 2
    ;;
esac
