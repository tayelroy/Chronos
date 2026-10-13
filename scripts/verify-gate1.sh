#!/bin/bash
# Chronos - Verification Gate 1 (run on chronos-soc-core from the repo root):
# OpenSearch healthy, template/pipeline/ISM installed, replay event indexed into
# chronos-replay-* with severity + MITRE tagging, live index untouched.
set -euo pipefail

OS="${OPENSEARCH_URL:-http://localhost:9200}"
fail() { echo "[FAIL] $*"; exit 1; }
pass() { echo "[PASS] $*"; }

health=$(curl -sf "$OS/_cluster/health" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])') || fail "OpenSearch unreachable at $OS"
[[ "$health" == green || "$health" == yellow ]] && pass "cluster health $health" || fail "cluster health $health"

curl -sf "$OS/_index_template/chronos" >/dev/null && pass "index template chronos" || fail "index template missing (run scripts/core-bootstrap.py)"
curl -sf "$OS/_ingest/pipeline/chronos-geoip" >/dev/null && pass "ingest pipeline chronos-geoip" || fail "ingest pipeline missing"
curl -sf "$OS/_plugins/_ism/policies/chronos-retention" >/dev/null && pass "ISM policy chronos-retention" || fail "ISM policy missing"

marker="gate1-$(date +%s)"
mkdir -p replay
printf '{"eventid":"cowrie.command.input","session":"%s","src_ip":"198.51.100.23","input":"cat /etc/shadow","timestamp":"%s"}\n' \
  "$marker" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> replay/cowrie.json

for _ in $(seq 1 15); do
  sleep 2
  hit=$(curl -s "$OS/chronos-replay-*/_search?q=session:$marker" | python3 -c '
import json,sys
h=json.load(sys.stdin).get("hits",{}).get("hits",[])
print("" if not h else "{severity} {mitre_technique}".format(**h[0]["_source"]))')
  [[ -n "$hit" ]] && break
done
[[ -n "$hit" ]] || fail "replay event $marker not indexed within 30s"
[[ "$hit" == "4 T1003.008" ]] && pass "replay event indexed with severity/technique: $hit" || fail "unexpected tagging: $hit (want '4 T1003.008')"

live=$(curl -s "$OS/chronos-logs-*/_count?q=session:$marker" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("count",0))')
[[ "$live" == 0 ]] && pass "replay data kept out of chronos-logs-*" || fail "replay event leaked into chronos-logs-* ($live docs)"

echo "[SUCCESS] Gate 1"
