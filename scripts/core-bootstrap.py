#!/usr/bin/env python3
"""
core-bootstrap.py - one-time (idempotent) setup of the chronos-soc-core stack.

Run on the core after `docker compose -f docker-compose.core.yml up -d`:
  1. OpenSearch: GeoIP ingest pipeline, index template, ISM retention policy.
  2. OpenSearch Dashboards: import saved objects from config/opensearch/dashboards.ndjson.
  3. TheHive: rotate the default admin password, create the `chronos` organisation,
     a human analyst account and the triage service account + API key.

Generated credentials are appended to .env (git-ignored); nothing secret is printed.
Stdlib only, so it runs on a bare Ubuntu host.
"""
import argparse
import base64
import json
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENV_FILE = REPO / ".env"
OS_URL = "http://localhost:9200"
OSD_URL = "http://localhost:5601"
TH_URL = "http://localhost:9000"
TH_DEFAULT_ADMIN = ("admin@thehive.local", "secret")
TH_ORG = "chronos"
TH_ANALYST = "analyst@chronos.local"
TH_TRIAGE = "triage@chronos.local"


def http(method, url, body=None, headers=None, auth=None, raw=False, timeout=30):
    """Returns (status, parsed-json-or-text). Never raises on HTTP errors."""
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        else:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
    if auth:
        hdrs["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, text = resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        return 0, str(e)
    if raw:
        return status, text
    try:
        return status, json.loads(text) if text else None
    except json.JSONDecodeError:
        return status, text


def wait_for(name, url, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, _ = http("GET", url, raw=True, timeout=5)
        if 200 <= status < 500:
            print(f"[+] {name} is up ({url})")
            return
        time.sleep(5)
    sys.exit(f"[-] {name} not reachable at {url} after {timeout}s")


def load_env():
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def set_env(key, value):
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    lines = [l for l in lines if not l.startswith(f"{key}=")]
    lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n")
    ENV_FILE.chmod(0o600)


def check(step, status, body=None, ok=(200, 201)):
    if status not in ok:
        sys.exit(f"[-] {step} failed (HTTP {status}): {body}")
    print(f"[+] {step}")


def setup_opensearch():
    cfg = REPO / "config" / "opensearch"
    status, body = http("PUT", f"{OS_URL}/_ingest/pipeline/chronos-geoip", json.loads((cfg / "ingest-geoip.json").read_text()))
    check("ingest pipeline chronos-geoip", status, body)
    status, body = http("PUT", f"{OS_URL}/_index_template/chronos", json.loads((cfg / "index-template.json").read_text()))
    check("index template chronos", status, body)

    policy = json.loads((cfg / "ism-retention.json").read_text())
    status, existing = http("GET", f"{OS_URL}/_plugins/_ism/policies/chronos-retention")
    if status == 200:
        seq, term = existing["_seq_no"], existing["_primary_term"]
        status, body = http("PUT", f"{OS_URL}/_plugins/_ism/policies/chronos-retention?if_seq_no={seq}&if_primary_term={term}", policy)
    else:
        status, body = http("PUT", f"{OS_URL}/_plugins/_ism/policies/chronos-retention", policy)
    check("ISM policy chronos-retention", status, body)


def setup_dashboards():
    ndjson = REPO / "config" / "opensearch" / "dashboards.ndjson"
    if not ndjson.exists():
        print("[*] No dashboards.ndjson in repo; skipping Dashboards import")
        return
    boundary = uuid.uuid4().hex
    payload = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"dashboards.ndjson\"\r\n"
        f"Content-Type: application/ndjson\r\n\r\n"
    ).encode() + ndjson.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    status, body = http(
        "POST", f"{OSD_URL}/api/saved_objects/_import?overwrite=true", payload,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "osd-xsrf": "true"},
    )
    if status != 200 or not body.get("success"):
        sys.exit(f"[-] Dashboards import failed (HTTP {status}): {body}")
    print(f"[+] Dashboards saved objects imported ({body.get('successCount')} objects)")


def setup_thehive():
    env = load_env()
    admin_pw = env.get("THEHIVE_ADMIN_PASSWORD")
    admin = (TH_DEFAULT_ADMIN[0], admin_pw) if admin_pw else None
    if not admin or http("GET", f"{TH_URL}/api/v1/user/current", auth=admin)[0] != 200:
        status, _ = http("GET", f"{TH_URL}/api/v1/user/current", auth=TH_DEFAULT_ADMIN)
        if status != 200:
            sys.exit("[-] TheHive admin login failed with both stored and default credentials")
        new_pw = secrets.token_urlsafe(24)
        status, _ = http("POST", f"{TH_URL}/api/v1/user/{TH_DEFAULT_ADMIN[0]}/password/change",
                         {"currentPassword": TH_DEFAULT_ADMIN[1], "password": new_pw}, auth=TH_DEFAULT_ADMIN)
        check("TheHive default admin password rotated (THEHIVE_ADMIN_PASSWORD in .env)", status, ok=(200, 204))
        set_env("THEHIVE_ADMIN_PASSWORD", new_pw)
        admin = (TH_DEFAULT_ADMIN[0], new_pw)

    if http("GET", f"{TH_URL}/api/v1/organisation/{TH_ORG}", auth=admin)[0] != 200:
        status, _ = http("POST", f"{TH_URL}/api/v1/organisation",
                         {"name": TH_ORG, "description": "Chronos honeypot SOC"}, auth=admin)
        check(f"TheHive organisation '{TH_ORG}' created", status)
    else:
        print(f"[+] TheHive organisation '{TH_ORG}' exists")

    for login, name, profile in ((TH_ANALYST, "Chronos Analyst", "org-admin"),
                                 (TH_TRIAGE, "Chronos Triage Automation", "analyst")):
        if http("GET", f"{TH_URL}/api/v1/user/{login}", auth=admin)[0] != 200:
            status, _ = http("POST", f"{TH_URL}/api/v1/user",
                             {"login": login, "name": name, "profile": profile, "organisation": TH_ORG}, auth=admin)
            check(f"TheHive user {login} created", status)
        else:
            print(f"[+] TheHive user {login} exists")

    if "THEHIVE_ANALYST_PASSWORD" not in env:
        pw = secrets.token_urlsafe(18)
        status, _ = http("POST", f"{TH_URL}/api/v1/user/{TH_ANALYST}/password/set", {"password": pw}, auth=admin)
        check(f"Password set for {TH_ANALYST} (THEHIVE_ANALYST_PASSWORD in .env)", status, ok=(200, 204))
        set_env("THEHIVE_ANALYST_PASSWORD", pw)

    if "THEHIVE_API_KEY" not in env:
        status, key = http("POST", f"{TH_URL}/api/v1/user/{TH_TRIAGE}/key/renew", auth=admin, raw=True)
        check(f"API key issued for {TH_TRIAGE} (THEHIVE_API_KEY in .env)", status)
        set_env("THEHIVE_API_KEY", key.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--skip-thehive", action="store_true")
    args = parser.parse_args()

    wait_for("OpenSearch", f"{OS_URL}/_cluster/health")
    setup_opensearch()
    wait_for("OpenSearch Dashboards", f"{OSD_URL}/api/status")
    setup_dashboards()
    if not args.skip_thehive:
        wait_for("TheHive", f"{TH_URL}/api/status")
        setup_thehive()
    print("[+] Core bootstrap complete")


if __name__ == "__main__":
    main()
