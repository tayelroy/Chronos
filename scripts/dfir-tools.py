#!/usr/bin/env python3
"""
dfir-tools.py - Chronos Digital Forensics & Artifact Extraction Engine

Parses Cowrie binary ttylog files into readable ASCII transcripts,
computes SHA256 hashes for staged malware payloads, and optionally queries
VirusTotal for reputation intelligence.
"""
import os
import re
import sys
import time
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Optional
import requests

VT_API_KEY = os.getenv("VT_API_KEY", "")


# Cowrie ttylog record header (src/cowrie/core/ttylog.py): op, tty, length, direction, sec, usec.
TTYLOG_HEADER = struct.Struct("<iLiiLL")
OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]")


def parse_ttylog(filepath: str) -> str:
    """
    Parses a Cowrie ttylog into a readable transcript: what the attacker saw (terminal
    output, which includes echoed typing) followed by the raw keystrokes they sent.
    """
    path = Path(filepath)
    if not path.exists():
        return f"[-] File not found: {filepath}"
    raw = path.read_bytes()
    if not raw:
        return "[*] Empty session log."

    output, keystrokes = [], []
    start = end = None
    idx = 0
    while idx + TTYLOG_HEADER.size <= len(raw):
        op, _tty, length, direction, sec, usec = TTYLOG_HEADER.unpack_from(raw, idx)
        idx += TTYLOG_HEADER.size
        if op not in (OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC) or length < 0 or idx + length > len(raw):
            return f"[-] {filepath} is not a Cowrie ttylog (bad record at byte {idx - TTYLOG_HEADER.size})"
        data = raw[idx:idx + length]
        idx += length
        ts = sec + usec / 1_000_000
        start = ts if start is None else start
        end = ts
        if op != OP_WRITE:
            continue
        text = data.decode("utf-8", errors="replace")
        if direction == TYPE_OUTPUT:
            output.append(text)
        elif direction == TYPE_INPUT:
            keystrokes.append((ts, text))

    transcript = ANSI_ESCAPE.sub("", "".join(output)).replace("\r\n", "\n").replace("\r", "")
    typed = "".join(t for _, t in keystrokes).replace("\r", "\n")
    duration = (end - start) if start is not None else 0.0
    return (
        "==================================================\n"
        "Chronos Forensic Session Transcript (Cowrie ttylog)\n"
        f"File    : {filepath} ({len(raw)} bytes)\n"
        f"Started : {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start or 0))} UTC, duration {duration:.1f}s\n"
        "==================================================\n"
        f"{transcript}\n"
        "---------------- attacker keystrokes ----------------\n"
        f"{typed}\n"
    )


def hash_payload(filepath: str) -> Optional[dict]:
    """Computes SHA256, MD5, and size of a downloaded malware payload."""
    path = Path(filepath)
    if not path.exists():
        return None

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)

    return {
        "file": str(path.name),
        "path": str(path.resolve()),
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


def check_virustotal(file_hash: str) -> dict:
    """Queries VirusTotal API v3 for hash reputation if VT_API_KEY is available."""
    if not VT_API_KEY:
        return {
            "status": "skipped",
            "message": "VT_API_KEY environment variable not set",
            "vt_url": f"https://www.virustotal.com/gui/file/{file_hash}",
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "vt_url": f"https://www.virustotal.com/gui/file/{file_hash}",
            }
        elif res.status_code == 404:
            return {"status": "not_found", "message": "Hash not observed on VirusTotal"}
        else:
            return {"status": "error", "message": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Chronos DFIR Tools & Forensic Extractor")
    parser.add_argument("--parse-ttylog", metavar="FILE", help="Parse binary ttylog file into text session transcript")
    parser.add_argument("--hash", metavar="FILE", help="Compute cryptographic hashes of a target file")
    parser.add_argument("--vt-check", metavar="HASH_OR_FILE", help="Check hash against VirusTotal")

    args = parser.parse_args()

    if args.parse_ttylog:
        transcript = parse_ttylog(args.parse_ttylog)
        print(transcript)
    elif args.hash:
        info = hash_payload(args.hash)
        if not info:
            print(f"[-] File not found: {args.hash}")
            sys.exit(1)
        print("==================================================")
        print(f"Chronos Forensic Artifact Analysis: {info['file']}")
        print("==================================================")
        print(f"Path   : {info['path']}")
        print(f"Size   : {info['size_bytes']} bytes")
        print(f"SHA256 : {info['sha256']}")
        print(f"MD5    : {info['md5']}")
        print(f"VT URL : https://www.virustotal.com/gui/file/{info['sha256']}")
    elif args.vt_check:
        target = args.vt_check
        if os.path.exists(target):
            h_info = hash_payload(target)
            target_hash = h_info["sha256"] if h_info else ""
        else:
            target_hash = target
        print(f"[*] Checking VirusTotal for: {target_hash}")
        res = check_virustotal(target_hash)
        print(res)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
