#!/usr/bin/env python3
import requests
import json
import time

OPENSEARCH_URL = "http://localhost:9200/chronos-logs-*/_search"

def query_threats():
    query = {
        "query": {
            "match_all": {}
        }
    }
    try:
        res = requests.post(OPENSEARCH_URL, json=query, timeout=5)
        data = res.json()
        hits = data.get("hits", {}).get("hits", [])
        print(f"[+] Active Defense Engine: Analyzed {len(hits)} attack events.")
        for hit in hits:
            source = hit.get("_source", {})
            src_ip = source.get("src_ip")
            source_type = source.get("source_type", "unknown")
            event_id = source.get("eventid") or source.get("event_type") or "activity"
            print(f"  [ALERT] [{source_type.upper()}] Event '{event_id}' detected from {src_ip}")
    except Exception as e:
        print(f"[-] Error querying OpenSearch: {e}")

if __name__ == "__main__":
    query_threats()
