#!/bin/bash
# Chronos - Verification Gate 2 (run on chronos-soc-core from the repo root):
# TheHive reachable with the triage API key, a replayed session produces exactly one
# alert, and a second triage run over the same data creates no additional alerts.
set -euo pipefail

TH="${THEHIVE_HOST:-http://localhost:9000}"
COMPOSE="docker compose -f docker-compose.core.yml"
fail() { echo "[FAIL] $*"; exit 1; }
pass() { echo "[PASS] $*"; }

[[ -f .env ]] || fail ".env missing (run scripts/core-bootstrap.py)"
THEHIVE_API_KEY=$(grep '^THEHIVE_API_KEY=' .env | cut -d= -f2-)
[[ -n "$THEHIVE_API_KEY" ]] || fail "THEHIVE_API_KEY missing from .env"

alert_count() {
  curl -sf -H "Authorization: Bearer $THEHIVE_API_KEY" -H 'Content-Type: application/json' \
    "$TH/api/v1/query" -d '{"query":[{"_name":"listAlert"},{"_name":"count"}]}'
}
session_alerts() {
  curl -sf -H "Authorization: Bearer $THEHIVE_API_KEY" -H 'Content-Type: application/json' "$TH/api/v1/query" \
    -d "{\"query\":[{\"_name\":\"listAlert\"},{\"_name\":\"filter\",\"_eq\":{\"_field\":\"sourceRef\",\"_value\":\"$1\"}},{\"_name\":\"count\"}]}"
}

alert_count >/dev/null && pass "TheHive API reachable with triage key" || fail "TheHive API rejected the triage key"

session=$(python3 scripts/replay-harness.py --cowrie-only --speed 0 | sed -n 's/.*session \([0-9a-f]*\)).*/\1/p')
[[ -n "$session" ]] || fail "replay harness did not report a session id"
pass "replayed Cowrie session $session"

for _ in $(seq 1 15); do
  sleep 2
  n=$(curl -s "http://localhost:9200/chronos-replay-*/_count?q=session:$session" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("count",0))')
  [[ "$n" -ge 9 ]] && break
done
[[ "$n" -ge 9 ]] || fail "replayed session not fully indexed ($n/9 events)"

triage() { $COMPOSE run --rm --no-deps triage --index 'chronos-replay-*' --lookback 1h --settle 0; }
triage
before=$(alert_count)
[[ "$(session_alerts "$session")" == 1 ]] && pass "exactly one alert for session $session" || fail "expected 1 alert for $session, got $(session_alerts "$session")"
triage
after=$(alert_count)
[[ "$before" == "$after" ]] && pass "second triage run created no alerts (count $before -> $after)" || fail "duplicate alerts: $before -> $after"

echo "[SUCCESS] Gate 2"
