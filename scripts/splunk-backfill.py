#!/usr/bin/env python3
"""
splunk-backfill.py - copy existing live events from OpenSearch into Splunk over HEC.

Vector only mirrors new events into Splunk, so run this once after enabling the splunk profile to
load history. It copies chronos-logs-* documents OLDER than the earliest event already in Splunk
(so it never overlaps Vector's live stream or an earlier backfill), oldest first, batched to HEC.

Splunk Free indexes up to 500 MB/day; --daily-cap-mb stops well under that and tells you to resume
tomorrow. Run on the core (reaches opensearch:9200 and splunk:8088 on the compose network), e.g.:

  docker compose -f docker-compose.core.yml run --rm --no-deps \
    --entrypoint python vector-core /dev/stdin < scripts/splunk-backfill.py
  # or simply, on the core host with the tunnels/compose network available:
  OPENSEARCH_HOST=http://localhost:9200 SPLUNK_HEC=http://localhost:8088 \
  SPLUNK_HEC_TOKEN=$(grep ^SPLUNK_HEC_TOKEN= .env | cut -d= -f2-) python3 scripts/splunk-backfill.py
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

OPENSEARCH = os.getenv("OPENSEARCH_HOST", "http://localhost:9200").rstrip("/")
SPLUNK_HEC = os.getenv("SPLUNK_HEC", "http://localhost:8088").rstrip("/")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
INDEX = "chronos"
SOURCETYPE = "chronos:event"


def os_post(path, body):
    req = urllib.request.Request(f"{OPENSEARCH}/{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.load(resp)


def hec_send(events):
    payload = "".join(json.dumps(e) for e in events).encode()
    req = urllib.request.Request(f"{SPLUNK_HEC}/services/collector/event", data=payload,
                                 headers={"Authorization": f"Splunk {HEC_TOKEN}"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.load(resp)
    if body.get("code") != 0:
        raise RuntimeError(f"HEC error: {body}")


def to_hec(doc):
    ts = doc.get("timestamp")
    try:
        epoch = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        epoch = time.time()
    return {"time": epoch, "host": doc.get("sensor_id", "chronos"), "index": INDEX,
            "sourcetype": SOURCETYPE, "event": doc}


def main():
    p = argparse.ArgumentParser(description="Backfill OpenSearch chronos-logs-* into Splunk HEC")
    p.add_argument("--index", default="chronos-logs-*", help="OpenSearch index pattern")
    p.add_argument("--until", help="Only copy events strictly before this ISO time "
                                   "(set to the earliest time shown in Splunk to avoid overlap)")
    p.add_argument("--since", help="Only copy events at or after this ISO time")
    p.add_argument("--batch", type=int, default=2000, help="Events per HEC request / OpenSearch page")
    p.add_argument("--daily-cap-mb", type=float, default=400.0, help="Stop after this many MB (Free cap is 500)")
    p.add_argument("--dry-run", action="store_true", help="Count and size only; send nothing")
    args = p.parse_args()

    if not args.dry_run and not HEC_TOKEN:
        sys.exit("[-] SPLUNK_HEC_TOKEN not set")

    rng = {}
    if args.since:
        rng["gte"] = args.since
    if args.until:
        rng["lt"] = args.until
    query = {"bool": {"filter": ([{"range": {"timestamp": rng}}] if rng else [{"match_all": {}}])}}
    total = os_post(f"{args.index}/_count", {"query": query})["count"]
    print(f"[*] {total:,} events to copy from {args.index}"
          + (f" in [{args.since or '-inf'}, {args.until or 'now'})" if rng else ""))
    if not total:
        return

    body = {"size": args.batch, "query": query, "sort": [{"timestamp": "asc"}, {"_doc": "asc"}],
            "_source": {"excludes": ["file", "host", "source_type"]}}
    cap_bytes = args.daily_cap_mb * 1024 * 1024
    sent = sent_bytes = 0
    while True:
        hits = os_post(f"{args.index}/_search", body)["hits"]["hits"]
        if not hits:
            break
        events = [to_hec(h["_source"]) for h in hits]
        size = sum(len(json.dumps(e)) for e in events)
        if sent_bytes + size > cap_bytes:
            print(f"[!] Stopping before the {args.daily_cap_mb} MB cap at {sent:,} events. "
                  f"Resume tomorrow with --since {hits[0]['_source'].get('timestamp')}")
            break
        if not args.dry_run:
            hec_send(events)
        sent += len(events)
        sent_bytes += size
        body["search_after"] = hits[-1]["sort"]
        if sent % (args.batch * 10) == 0:
            print(f"    {sent:,}/{total:,} sent ({sent_bytes / 1024 / 1024:.1f} MB)")
    verb = "would send" if args.dry_run else "sent"
    print(f"[+] {verb} {sent:,} events ({sent_bytes / 1024 / 1024:.1f} MB) to Splunk index {INDEX}")


if __name__ == "__main__":
    main()
