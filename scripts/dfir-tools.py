#!/usr/bin/env python3
"""
dfir-tools.py - Chronos Digital Forensics & Artifact Extraction Engine

Parses Cowrie binary ttylog files into readable ASCII transcripts,
computes SHA256 hashes for staged malware payloads, and optionally queries
VirusTotal for reputation intelligence.
"""
import os
import sys
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Optional
import requests

VT_API_KEY = os.getenv("VT_API_KEY", "")


def parse_ttylog(filepath: str) -> str:
    """
    Parses Cowrie binary ttylog files (User Mode Linux format).
    Supports 12-byte (<III) and 16-byte headers with fallback to raw decode.
    Returns a human-readable terminal session transcript.
    """
    path = Path(filepath)
    if not path.exists():
        return f"[-] File not found: {filepath}"

    with open(path, "rb") as f:
        raw = f.read()

    if not raw:
        return "[*] Empty session log."

    # Strategy 1: Standard 12-byte UML header (<III: sec, usec, length)
    transcript_12: list[str] = []
    idx = 0
    valid_12 = True
    while idx + 12 <= len(raw):
        sec, usec, length = struct.unpack("<III", raw[idx:idx + 12])
        idx += 12
        if length < 0 or length > (len(raw) - idx):
            valid_12 = False
            break
        data = raw[idx:idx + length]
        idx += length
        transcript_12.append(data.decode("utf-8", errors="replace"))

    if valid_12 and idx == len(raw) and transcript_12:
        reconstructed = "".join(transcript_12)
        return (
            f"==================================================\n"
            f"Chronos Forensic Session Transcript (12B UML)\n"
            f"File: {filepath} ({len(raw)} bytes)\n"
            f"==================================================\n"
            f"{reconstructed}"
        )

    # Strategy 2: 16-byte UML header (<IIII: sec, usec, length, type)
    transcript_16: list[str] = []
    idx = 0
    valid_16 = True
    while idx + 16 <= len(raw):
        sec, usec, length = struct.unpack("<III", raw[idx:idx + 12])
        idx += 16
        if length < 0 or length > (len(raw) - idx):
            valid_16 = False
            break
        data = raw[idx:idx + length]
        idx += length
        transcript_16.append(data.decode("utf-8", errors="replace"))

    if valid_16 and idx == len(raw) and transcript_16:
        reconstructed = "".join(transcript_16)
        return (
            f"==================================================\n"
            f"Chronos Forensic Session Transcript (16B UML)\n"
            f"File: {filepath} ({len(raw)} bytes)\n"
            f"==================================================\n"
            f"{reconstructed}"
        )

    # Strategy 3: Fallback raw stream decode
    reconstructed = raw.decode("utf-8", errors="replace")
    return (
        f"==================================================\n"
        f"Chronos Forensic Session Transcript (Raw Stream)\n"
        f"File: {filepath} ({len(raw)} bytes)\n"
        f"==================================================\n"
        f"{reconstructed}"
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
