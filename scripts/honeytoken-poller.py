#!/usr/bin/env python3
"""
honeytoken-poller.py - pull honeytoken key use from the honeytoken account's CloudTrail event history.

Runs on chronos-soc-core (docker-compose.core.yml, profile "honeytokens"). Each cycle it:
  1. assumes HONEYTOKEN_READER_ROLE_ARN (cloudtrail:LookupEvents + ec2:DescribeRegions only) with the
     core's instance role;
  2. looks up every event made with each bait's access key in every enabled region, from the last
     successful poll (minus an hour, for CloudTrail delivery delay) or the 90-day retention limit;
  3. appends unseen events as JSON lines to <out-dir>/events.json, which Vector core tails and indexes.
     scripts/triage-automation.py turns them into TheHive alerts.

Event history keeps 90 days, so the core can be stopped for days and still catch up on the next start.
State (seen event ids, last poll) lives in <out-dir>/poller-state.
"""
import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.config import Config

BAITS = {"DOTENV": "dotenv", "WPCONFIG": "wp-config", "GIT": "git", "COWRIE": "cowrie"}
RETENTION = timedelta(days=89)  # event history keeps 90 days; stay inside it
DELIVERY_SLACK = timedelta(hours=1)  # CloudTrail can deliver an event well after it happened
RETRY = Config(retries={"max_attempts": 10, "mode": "adaptive"})


def log(msg):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}] {msg}", flush=True)


def bait_keys():
    keys = {}
    for env_name, bait in BAITS.items():
        key_id = os.getenv(f"HONEYTOKEN_{env_name}_AWS_KEY_ID", "").strip()
        if key_id:
            keys[key_id] = bait
    if not keys:
        sys.exit("[-] no HONEYTOKEN_<BAIT>_AWS_KEY_ID configured")
    return keys


def reader_session(role_arn):
    creds = boto3.client("sts", region_name="us-east-1", config=RETRY).assume_role(
        RoleArn=role_arn, RoleSessionName="chronos-honeytoken-poller", DurationSeconds=3600)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"])


def to_record(ct, bait):
    """Flatten a CloudTrail event into the Chronos event shape (see README data model)."""
    identity = ct.get("userIdentity", {})
    source = ct.get("sourceIPAddress", "")
    try:
        src_ip = str(ipaddress.ip_address(source))
    except ValueError:
        src_ip = None  # e.g. "AWS Internal" or a service hostname when the call came through an AWS service
    record = {
        "event_type": "honeytoken_key_used",
        # The collector, not a sensor: keeps these events in the live index (chronos-logs-*).
        "sensor_id": "honeytoken-cloudtrail",
        "timestamp": ct["eventTime"],
        "bait": bait,
        "access_key_id": identity.get("accessKeyId"),
        "aws_user": identity.get("userName"),
        "aws_event_source": ct.get("eventSource"),
        "aws_event_name": ct.get("eventName"),
        "aws_region": ct.get("awsRegion"),
        "aws_error_code": ct.get("errorCode"),
        "aws_error_message": (ct.get("errorMessage") or "")[:512] or None,
        "user_agent": ct.get("userAgent"),
        "source_address": source,
        "cloudtrail_event_id": ct.get("eventID"),
    }
    if src_ip:
        record["src_ip"] = src_ip
    return {k: v for k, v in record.items() if v is not None}


def poll(role_arn, keys, out_dir, state):
    session = reader_session(role_arn)
    regions = sorted(r["RegionName"] for r in session.client("ec2", region_name="us-east-1", config=RETRY)
                     .describe_regions()["Regions"])
    now = datetime.now(timezone.utc)
    last = datetime.fromisoformat(state["last_poll"]) if state.get("last_poll") else None
    start = max(last - DELIVERY_SLACK, now - RETENTION) if last else now - RETENTION
    new = []
    for region in regions:
        pages = session.client("cloudtrail", region_name=region, config=RETRY).get_paginator("lookup_events")
        for key_id, bait in keys.items():
            for page in pages.paginate(LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": key_id}],
                                       StartTime=start, EndTime=now):
                for event in page["Events"]:
                    if event["EventId"] in state["seen"]:
                        continue
                    ct = json.loads(event["CloudTrailEvent"])
                    new.append(to_record(ct, bait))
                    state["seen"][event["EventId"]] = ct["eventTime"]
    new.sort(key=lambda r: r["timestamp"])
    if new:
        with open(out_dir / "events.json", "a") as f:
            for record in new:
                f.write(json.dumps(record) + "\n")
    cutoff = (now - RETENTION - DELIVERY_SLACK).strftime("%Y-%m-%dT%H:%M:%SZ")
    state["seen"] = {k: v for k, v in state["seen"].items() if v >= cutoff}
    state["last_poll"] = now.isoformat()
    log(f"[+] {len(regions)} regions, {len(keys)} keys, window from {start:%Y-%m-%d %H:%M}: {len(new)} new event(s)")


def load_state(path):
    if path.exists():
        return json.loads(path.read_text())
    return {"last_poll": None, "seen": {}}


def save_state(path, state):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(path)


def main():
    parser = argparse.ArgumentParser(description="Chronos honeytoken CloudTrail poller")
    parser.add_argument("--out-dir", default="/var/log/chronos-honeytoken")
    parser.add_argument("--loop", type=int, default=0, help="Seconds between polls (0 = poll once)")
    args = parser.parse_args()

    role_arn = os.getenv("HONEYTOKEN_READER_ROLE_ARN", "").strip()
    if not role_arn:
        sys.exit("[-] HONEYTOKEN_READER_ROLE_ARN not set")
    keys = bait_keys()
    out_dir = Path(args.out_dir)
    state_path = out_dir / "poller-state"

    while True:
        state = load_state(state_path)
        try:
            poll(role_arn, keys, out_dir, state)
            # Events are on disk before the state records them as seen, so a crash re-sends rather than drops.
            save_state(state_path, state)
        except Exception as e:  # keep looping through transient AWS/network errors
            log(f"[-] poll failed: {type(e).__name__}: {e}")
            if not args.loop:
                sys.exit(1)
        if not args.loop:
            return
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
