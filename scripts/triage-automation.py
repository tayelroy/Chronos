#!/usr/bin/env python3
"""
triage-automation.py - Chronos session-level triage: OpenSearch -> TheHive alerts.

One TheHive alert per Cowrie session that reached severity >= --min-severity
(login success and beyond). Alerts are keyed by `sourceRef = <cowrie session id>`,
so re-running never creates duplicates: existing sourceRefs are skipped up front
and TheHive itself rejects a second alert with the same (type, source, sourceRef).

A session is only alerted once it is complete (cowrie.session.closed seen, or no
events for --settle seconds) so the alert carries the whole command chain.

Latency reported per alert = alert creation time - timestamp of the session's first
severity >= threshold event (event-to-alert, includes the settle window by design).
"""
import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://localhost:9200")
THEHIVE_HOST = os.getenv("THEHIVE_HOST", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

ALERT_TYPE = "honeypot-session"
ALERT_SOURCE = "chronos-cowrie"
# Chronos severity (1-5) -> TheHive severity (1 low .. 4 critical)
THEHIVE_SEVERITY = {1: 1, 2: 1, 3: 2, 4: 3, 5: 4}
MAX_SESSIONS_PER_RUN = 500


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def os_search(index: str, body: Dict[str, Any]) -> Dict[str, Any]:
    res = requests.post(f"{OPENSEARCH_HOST}/{index}/_search", json=body, timeout=30)
    res.raise_for_status()
    return res.json()


def candidate_sessions(index: str, min_severity: int, lookback: str) -> List[str]:
    """Cowrie sessions with at least one event at or above min_severity inside the lookback window."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"honeypot": "cowrie"}},
            {"range": {"severity": {"gte": min_severity}}},
            {"range": {"timestamp": {"gte": f"now-{lookback}"}}},
        ]}},
        "aggs": {"sessions": {"terms": {"field": "session", "size": 10000, "order": {"first": "asc"}},
                              "aggs": {"first": {"min": {"field": "timestamp"}}}}},
    }
    # No aggregations key when the index pattern matches nothing yet (fresh deployment).
    buckets = os_search(index, body).get("aggregations", {}).get("sessions", {}).get("buckets", [])
    return [b["key"] for b in buckets]


def session_events(index: str, sessions: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    body = {
        "size": 10000,
        "query": {"terms": {"session": sessions}},
        "sort": [{"timestamp": "asc"}],
    }
    grouped: Dict[str, List[Dict[str, Any]]] = {s: [] for s in sessions}
    for hit in os_search(index, body)["hits"]["hits"]:
        src = hit["_source"]
        grouped.setdefault(src.get("session"), []).append(src)
    return grouped


def thehive(method: str, path: str, **kwargs) -> requests.Response:
    headers = {"Authorization": f"Bearer {THEHIVE_API_KEY}"}
    return requests.request(method, f"{THEHIVE_HOST}{path}", headers=headers, timeout=30, **kwargs)


def existing_source_refs(refs: List[str]) -> set:
    found = set()
    for i in range(0, len(refs), 200):
        chunk = refs[i:i + 200]
        query = {"query": [
            {"_name": "listAlert"},
            {"_name": "filter", "_and": [
                {"_eq": {"_field": "source", "_value": ALERT_SOURCE}},
                {"_in": {"_field": "sourceRef", "_values": chunk}},
            ]},
            {"_name": "page", "from": 0, "to": len(chunk), "extraData": []},
        ]}
        res = thehive("POST", "/api/v1/query", json=query)
        res.raise_for_status()
        found.update(a["sourceRef"] for a in res.json())
    return found


def code_block(text: str) -> str:
    """Fenced block whose fence is longer than any backtick run in attacker-controlled text."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def build_alert(session: str, events: List[Dict[str, Any]], min_severity: int) -> Dict[str, Any]:
    first = events[0]
    src_ip = first.get("src_ip", "0.0.0.0")
    trigger = next(e for e in events if e.get("severity", 0) >= min_severity)
    max_sev = max(e.get("severity", 1) for e in events)
    techniques = sorted({t for e in events for t in ([e.get("mitre_technique")] + e.get("command_techniques", []))
                         if t and t != "None"})
    commands = [e["input"] for e in events if e.get("eventid") == "cowrie.command.input" and e.get("input")]
    logins = [f"{e.get('username', '')}:{e.get('password', '')}" for e in events
              if e.get("eventid") in ("cowrie.login.success", "cowrie.login.failed")]
    urls = sorted({e["url"] for e in events if e.get("url")})
    hashes = sorted({e["shasum"] for e in events if e.get("shasum")})
    geo = first.get("geo", {}) or {}
    asn = first.get("as", {}) or {}
    client = next((e.get("version") for e in events if e.get("eventid") == "cowrie.client.version"), None)
    hassh = next((e.get("hassh") for e in events if e.get("eventid") == "cowrie.client.kex"), None)
    worst = max(events, key=lambda e: e.get("severity", 0))

    rows = [
        ("Session", session),
        ("Source IP", src_ip),
        ("Country", geo.get("country_name", "unknown")),
        ("ASN", f"AS{asn.get('asn', '?')} {asn.get('organization_name', '')}".strip()),
        ("Protocol", first.get("protocol", "unknown")),
        ("First event", first.get("timestamp")),
        ("Last event", events[-1].get("timestamp")),
        ("Max severity", f"{max_sev} / 5"),
        ("Techniques", ", ".join(techniques) or "none"),
        ("Commands", str(len(commands))),
    ]
    table = "| Field | Value |\n|---|---|\n" + "\n".join(
        f"| {k} | {code_block_inline(str(v))} |" for k, v in rows)
    desc = [
        "### Chronos honeypot session (NIST SP 800-61: Detection & Analysis)",
        table,
        "#### Credentials tried",
        code_block("\n".join(logins) or "(none)"),
        "#### Command chain",
        code_block("\n".join(commands) or "(no commands)"),
    ]
    if client or hassh:
        desc += ["#### Client fingerprint", code_block(f"version: {client}\nhassh: {hassh}")]
    if urls or hashes:
        desc += ["#### Staged payloads", code_block("\n".join(urls + hashes))]
    desc += [
        "#### Recommended actions",
        "1. Replay the session on chronos-sensor: `scripts/dfir-tools.py --parse-ttylog logs/cowrie-tty/<ttylog>` "
        "(ttylog name is in this session's `cowrie.log.closed` event).",
        "2. Check staged payloads: `scripts/dfir-tools.py --vt-check <sha256>` "
        "(files are kept on chronos-sensor under `logs/cowrie-downloads/`).",
        "3. Correlate with other sessions from the same ASN / client fingerprint in OpenSearch Dashboards.",
    ]

    observables = [{"dataType": "ip", "data": src_ip, "tags": ["attacker"]}]
    observables += [{"dataType": "url", "data": u, "tags": ["staging"]} for u in urls]
    observables += [{"dataType": "hash", "data": h, "tags": ["payload"]} for h in hashes]

    tags = ["chronos", "honeypot:cowrie", f"chronos-severity:{max_sev}"] + techniques
    if geo.get("country_iso_code"):
        tags.append(f"country:{geo['country_iso_code']}")

    return {
        "type": ALERT_TYPE,
        "source": ALERT_SOURCE,
        "sourceRef": session,
        "title": f"[Chronos] {worst.get('event_description', 'Honeypot session')} from {src_ip}",
        "description": "\n\n".join(desc),
        "severity": THEHIVE_SEVERITY.get(max_sev, 2),
        "date": int(parse_ts(trigger["timestamp"]).timestamp() * 1000),
        "tags": tags,
        "tlp": 2,
        "pap": 2,
        "observables": observables,
        "_trigger_ts": trigger["timestamp"],
    }


def code_block_inline(text: str) -> str:
    """Inline code span safe for attacker-controlled text inside a markdown table cell."""
    text = text.replace("|", "\\|").replace("\n", " ")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def run_once(args) -> int:
    sessions = candidate_sessions(args.index, args.min_severity, args.lookback)
    if not sessions:
        print("[*] No sessions at or above severity threshold.")
        return 0
    already = existing_source_refs(sessions) if not args.dry_run else set()
    pending = [s for s in sessions if s not in already][:MAX_SESSIONS_PER_RUN]
    print(f"[*] {len(sessions)} candidate sessions, {len(already)} already alerted, {len(pending)} to evaluate")
    if not pending:
        return 0

    now = time.time()
    created = 0
    latencies = []
    events_by_session = {}
    for i in range(0, len(pending), 50):
        events_by_session.update(session_events(args.index, pending[i:i + 50]))
    for session in pending:
        events = events_by_session.get(session) or []
        if not events:
            continue
        closed = any(e.get("eventid") == "cowrie.session.closed" for e in events)
        idle = now - parse_ts(events[-1]["timestamp"]).timestamp()
        if not closed and idle < args.settle:
            continue
        alert = build_alert(session, events, args.min_severity)
        trigger_ts = alert.pop("_trigger_ts")
        if args.dry_run:
            print(f"[DRY-RUN] {alert['title']} (sourceRef={session}, severity={alert['severity']})")
            created += 1
            continue
        res = thehive("POST", "/api/v1/alert", json=alert)
        if res.status_code in (200, 201):
            latency = time.time() - parse_ts(trigger_ts).timestamp()
            latencies.append(latency)
            created += 1
            print(f"[+] Alert {res.json().get('_id')} for session {session} ({alert['title']}); "
                  f"event-to-alert {latency:.1f}s")
        elif res.status_code == 400 and "already exist" in res.text.lower():
            print(f"[*] Session {session} already alerted (TheHive rejected duplicate sourceRef)")
        else:
            print(f"[-] TheHive rejected alert for session {session}: HTTP {res.status_code} {res.text[:300]}")
    if latencies:
        latencies.sort()
        print(f"[*] Created {created} alerts; event-to-alert latency median {latencies[len(latencies) // 2]:.1f}s, "
              f"max {latencies[-1]:.1f}s")
    else:
        print(f"[*] Created {created} alerts")
    return created


def main():
    parser = argparse.ArgumentParser(description="Chronos session-level triage (OpenSearch -> TheHive alerts)")
    parser.add_argument("--index", default=os.getenv("TRIAGE_INDEX", "chronos-logs-*"),
                        help="OpenSearch index pattern (use chronos-replay-* for synthetic data)")
    parser.add_argument("--min-severity", type=int, default=4, help="Chronos severity threshold (default 4)")
    parser.add_argument("--lookback", default="7d", help="OpenSearch date-math window (default 7d)")
    parser.add_argument("--settle", type=int, default=300,
                        help="Seconds without events before an unclosed session is considered complete")
    parser.add_argument("--loop", type=int, default=0, help="Run every N seconds (0 = run once)")
    parser.add_argument("--dry-run", action="store_true", help="Print alerts instead of sending them")
    args = parser.parse_args()

    if not args.dry_run and not THEHIVE_API_KEY:
        sys.exit("[-] THEHIVE_API_KEY is not set (run scripts/core-bootstrap.py) or use --dry-run")

    print(f"[*] Chronos triage: {OPENSEARCH_HOST}/{args.index} -> {THEHIVE_HOST} "
          f"(severity >= {args.min_severity}, lookback {args.lookback})")
    while True:
        try:
            run_once(args)
        except requests.RequestException as e:
            if not args.loop:
                sys.exit(f"[-] {e}")
            print(f"[-] {e}; retrying in {args.loop}s")
        if not args.loop:
            return
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
