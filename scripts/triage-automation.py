#!/usr/bin/env python3
"""
triage-automation.py - Chronos triage: OpenSearch -> TheHive alerts.

One TheHive alert per Cowrie session that reached severity >= --min-severity
(login success and beyond). Alerts are keyed by `sourceRef = <cowrie session id>`,
so re-running never creates duplicates: existing sourceRefs are skipped up front
and TheHive itself rejects a second alert with the same (type, source, sourceRef).

A session is only alerted once it is complete (cowrie.session.closed seen, or no
events for --settle seconds) so the alert carries the whole command chain.

Honeytoken key use (honeypot "honeytoken", from scripts/honeytoken-poller.py) gets one
alert per bait, source address and UTC day (`sourceRef = honeytoken:<bait>:<source>:<day>`),
raised once that group has been quiet for --settle seconds. Calls made after the alert
stay in OpenSearch but are not appended to it.

Latency reported per alert = alert creation time - timestamp of the first event at or
above the threshold (event-to-alert, includes the settle window by design).
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
LIVE_SOURCE = "chronos-cowrie"
REPLAY_SOURCE = "chronos-replay"  # synthetic sessions from chronos-replay-*; kept apart from live alerts
HONEYTOKEN_TYPE = "honeytoken-key-use"
HONEYTOKEN_SOURCE = "chronos-honeytoken"
BAIT_LOCATIONS = {
    "dotenv": "canary GET /.env",
    "wp-config": "canary GET /wp-config.php.bak",
    "git": "canary /.git/ repository (.env.production blob)",
    "cowrie": "Cowrie /root/.aws/credentials",
}
# The only call a deny-all IAM user can make successfully. Anything else succeeding means the deny is broken.
EXPECTED_SUCCESS = {"GetCallerIdentity"}
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


def existing_source_refs(refs: List[str], source: str) -> set:
    found = set()
    for i in range(0, len(refs), 200):
        chunk = refs[i:i + 200]
        query = {"query": [
            {"_name": "listAlert"},
            {"_name": "filter", "_and": [
                {"_eq": {"_field": "source", "_value": source}},
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


def build_alert(session: str, events: List[Dict[str, Any]], min_severity: int, source: str) -> Dict[str, Any]:
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
    # Only transferred files are payloads; cowrie.log.closed also carries a shasum (of the ttylog itself).
    hashes = sorted({e["shasum"] for e in events
                     if e.get("shasum") and e.get("eventid") in ("cowrie.session.file_download", "cowrie.session.file_upload")})
    ttylogs = [os.path.basename(e["ttylog"]) for e in events
               if e.get("eventid") == "cowrie.log.closed" and re.fullmatch(r"[\w./-]+", str(e.get("ttylog", "")))]
    geo = first.get("geo", {}) or {}
    asn = first.get("as", {}) or {}
    client = next((e.get("version") for e in events if e.get("eventid") == "cowrie.client.version"), None)
    hassh = next((e.get("hassh") for e in events if e.get("eventid") == "cowrie.client.kex"), None)
    # Prefer the concrete outcome (download, upload, login) over the command that caused it when severities tie.
    worst = max(events, key=lambda e: (e.get("severity", 0), e.get("eventid") != "cowrie.command.input"))

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
    actions = []
    for t in ttylogs:
        actions.append(f"Replay the session transcript (on chronos-sensor): "
                       f"`python3 scripts/dfir-tools.py --parse-ttylog logs/cowrie-tty/{t}`")
    for h in hashes:
        actions.append(f"Check payload reputation: `python3 scripts/dfir-tools.py --vt-check {h}` "
                       f"(file kept on chronos-sensor under `logs/cowrie-downloads/`)")
    actions.append("Correlate with other sessions from the same ASN / client fingerprint in OpenSearch Dashboards.")
    desc += ["#### Recommended actions", "\n".join(f"{i}. {a}" for i, a in enumerate(actions, 1))]

    observables = [{"dataType": "ip", "data": src_ip, "tags": ["attacker"]}]
    observables += [{"dataType": "url", "data": u, "tags": ["staging"]} for u in urls]
    observables += [{"dataType": "hash", "data": h, "tags": ["payload"]} for h in hashes]

    tags = ["chronos", "honeypot:cowrie", f"chronos-severity:{max_sev}"] + techniques
    if source == REPLAY_SOURCE:
        tags.append("synthetic")
    if geo.get("country_iso_code"):
        tags.append(f"country:{geo['country_iso_code']}")

    return {
        "type": ALERT_TYPE,
        "source": source,
        "sourceRef": session,
        "title": f"[Chronos] {worst.get('event_description', 'Honeypot session')} "
                 f"({worst.get('mitre_technique', 'n/a')}) from {src_ip}",
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


def post_alert(alert: Dict[str, Any], ref: str, dry_run: bool) -> Any:
    """Create the alert; return event-to-alert latency in seconds, 0.0 for a dry run, None if not created."""
    trigger_ts = alert.pop("_trigger_ts")
    if dry_run:
        print(f"[DRY-RUN] {alert['title']} (sourceRef={ref}, severity={alert['severity']})")
        return 0.0
    res = thehive("POST", "/api/v1/alert", json=alert)
    if res.status_code in (200, 201):
        latency = time.time() - parse_ts(trigger_ts).timestamp()
        print(f"[+] Alert {res.json().get('_id')} for {ref} ({alert['title']}); event-to-alert {latency:.1f}s")
        return latency
    if res.status_code == 400 and "already exist" in res.text.lower():
        print(f"[*] {ref} already alerted (TheHive rejected duplicate sourceRef)")
    else:
        print(f"[-] TheHive rejected alert for {ref}: HTTP {res.status_code} {res.text[:300]}")
    return None


def run_sessions(args) -> List[float]:
    sessions = candidate_sessions(args.index, args.min_severity, args.lookback)
    if not sessions:
        print("[*] No sessions at or above severity threshold.")
        return []
    source = REPLAY_SOURCE if args.index.startswith("chronos-replay") else LIVE_SOURCE
    already = existing_source_refs(sessions, source) if not args.dry_run else set()
    pending = [s for s in sessions if s not in already][:MAX_SESSIONS_PER_RUN]
    print(f"[*] {len(sessions)} candidate sessions, {len(already)} already alerted, {len(pending)} to evaluate")
    now = time.time()
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
        latency = post_alert(build_alert(session, events, args.min_severity, source), session, args.dry_run)
        if latency is not None:
            latencies.append(latency)
    return latencies


def honeytoken_groups(index: str, lookback: str) -> Dict[str, List[Dict[str, Any]]]:
    body = {
        "size": 10000,
        "query": {"bool": {"filter": [
            {"term": {"honeypot": "honeytoken"}},
            {"range": {"timestamp": {"gte": f"now-{lookback}"}}},
        ]}},
        "sort": [{"timestamp": "asc"}],
    }
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for hit in os_search(index, body)["hits"]["hits"]:
        e = hit["_source"]
        source_addr = e.get("src_ip") or e.get("source_address") or "unknown"
        groups.setdefault(f"honeytoken:{e.get('bait')}:{source_addr}:{e['timestamp'][:10]}", []).append(e)
    return groups


def first_handout(index: str, bait: str, src_ip: Any) -> Dict[str, Any]:
    """When the bait's key was first handed out to anyone, and to this source IP."""
    if bait == "cowrie":  # reading /root/.aws in Cowrie is the handout
        handout = [{"term": {"eventid": "cowrie.command.input"}}, {"term": {"command_techniques": "T1552.001"}}]
    else:
        handout = [{"term": {"honeypot": "canary"}}, {"term": {"bait": bait}}, {"term": {"honeytoken_served": True}}]
    aggs = {"first": {"min": {"field": "timestamp"}}}
    if src_ip:
        aggs["this_ip"] = {"filter": {"term": {"src_ip": src_ip}}, "aggs": {"first": {"min": {"field": "timestamp"}}}}
    a = os_search(index, {"size": 0, "query": {"bool": {"filter": handout}}, "aggs": aggs}).get("aggregations", {})
    return {
        "any": a.get("first", {}).get("value_as_string"),
        "this_ip": a.get("this_ip", {}).get("first", {}).get("value_as_string"),
    }


def build_honeytoken_alert(ref: str, events: List[Dict[str, Any]], handout: Dict[str, Any]) -> Dict[str, Any]:
    first, last = events[0], events[-1]
    bait = first.get("bait", "unknown")
    source_addr = first.get("src_ip") or first.get("source_address") or "unknown"
    geo = first.get("geo", {}) or {}
    asn = first.get("as", {}) or {}
    unexpected = [e for e in events if not e.get("aws_error_code") and e.get("aws_event_name") not in EXPECTED_SUCCESS]
    regions = sorted({e.get("aws_region", "?") for e in events})
    user_agents = sorted({e.get("user_agent", "") for e in events if e.get("user_agent")})
    calls = [f"{e['timestamp']}  {(e.get('aws_event_source') or '').split('.')[0]}:{e.get('aws_event_name')}  "
             f"{e.get('aws_region')}  {e.get('aws_error_code') or 'OK'}" for e in events]
    rows = [
        ("Bait", bait),
        ("Planted at", BAIT_LOCATIONS.get(bait, "unknown")),
        ("Access key", first.get("access_key_id", "?")),
        ("Source", source_addr),
        ("Country", geo.get("country_name", "unknown")),
        ("ASN", f"AS{asn.get('asn', '?')} {asn.get('organization_name', '')}".strip()),
        ("First call", first.get("timestamp")),
        ("Last call", last.get("timestamp")),
        ("API calls", str(len(events))),
        ("Regions", ", ".join(regions)),
        ("Key first handed out (anyone)", handout.get("any") or "never seen"),
        ("Key handed out to this IP", handout.get("this_ip") or "no: fetched elsewhere, or shared after the fetch"),
    ]
    table = "| Field | Value |\n|---|---|\n" + "\n".join(f"| {k} | {code_block_inline(str(v))} |" for k, v in rows)
    desc = ["### Chronos honeytoken key used (NIST SP 800-61: Detection & Analysis)", table]
    if unexpected:
        desc += ["#### UNEXPECTED SUCCESS: the deny-all policy did not hold",
                 code_block("\n".join(f"{e['timestamp']}  {e.get('aws_event_name')}  {e.get('aws_region')}"
                                      for e in unexpected))]
    desc += ["#### API calls (CloudTrail)", code_block("\n".join(calls)),
             "#### User agents", code_block("\n".join(user_agents) or "(none)")]
    actions = [
        "No containment needed while every call except GetCallerIdentity is denied: the key belongs to a deny-all "
        "IAM user in the isolated honeytoken account.",
        "Compare the source with the bait's fetchers: `python3 scripts/findings-report.py` → "
        "\"Key use seen in CloudTrail\".",
        "Look for other activity from this IP and ASN in OpenSearch Dashboards (scans, Cowrie sessions).",
    ]
    if unexpected:
        actions.insert(0, "Deactivate the key now (honeytoken account, IAM user) and re-run "
                          "scripts/honeytokens-provision.sh; check the SCP is still attached.")
    desc += ["#### Recommended actions", "\n".join(f"{i}. {a}" for i, a in enumerate(actions, 1))]

    observables = [{"dataType": "user-agent", "data": ua, "tags": ["honeytoken"]} for ua in user_agents]
    if first.get("src_ip"):
        observables.insert(0, {"dataType": "ip", "data": first["src_ip"], "tags": ["attacker", "honeytoken-user"]})
    tags = ["chronos", "honeytoken", f"bait:{bait}", "T1078.004", "chronos-severity:5"]
    tags += sorted({f"aws:{e.get('aws_event_name')}" for e in events})
    if geo.get("country_iso_code"):
        tags.append(f"country:{geo['country_iso_code']}")
    return {
        "type": HONEYTOKEN_TYPE,
        "source": HONEYTOKEN_SOURCE,
        "sourceRef": ref,
        "title": f"[Chronos] Honeytoken key used: {bait} bait from {source_addr}"
                 + (" (UNEXPECTED SUCCESS)" if unexpected else ""),
        "description": "\n\n".join(desc),
        "severity": 4,
        "date": int(parse_ts(first["timestamp"]).timestamp() * 1000),
        "tags": tags,
        "tlp": 2,
        "pap": 2,
        "observables": observables,
        "_trigger_ts": first["timestamp"],
    }


def run_honeytokens(args) -> List[float]:
    if args.index.startswith("chronos-replay"):
        return []  # honeytoken events only exist in the live index
    groups = honeytoken_groups(args.index, args.lookback)
    if not groups:
        return []
    already = existing_source_refs(list(groups), HONEYTOKEN_SOURCE) if not args.dry_run else set()
    now = time.time()
    latencies = []
    for ref, events in groups.items():
        if ref in already or now - parse_ts(events[-1]["timestamp"]).timestamp() < args.settle:
            continue
        handout = first_handout(args.index, events[0].get("bait", ""), events[0].get("src_ip"))
        latency = post_alert(build_honeytoken_alert(ref, events, handout), ref, args.dry_run)
        if latency is not None:
            latencies.append(latency)
    print(f"[*] {len(groups)} honeytoken key-use groups, {len(already)} already alerted")
    return latencies


def run_once(args) -> int:
    latencies = run_sessions(args) + run_honeytokens(args)
    if latencies:
        latencies.sort()
        print(f"[*] Created {len(latencies)} alerts; event-to-alert latency median "
              f"{latencies[len(latencies) // 2]:.1f}s, max {latencies[-1]:.1f}s")
    return len(latencies)


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
