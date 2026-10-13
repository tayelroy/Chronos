# Project Chronos

A lightweight, workplace-style SOC on two AWS EC2 instances: an internet-facing honeypot sensor captures automated SSH, Telnet and HTTP bot traffic, and a separate SOC core turns it into searchable telemetry, triaged alerts and a findings report.

---

## Architecture

```
[Public Internet / bots]
         │  :22 SSH, :23 Telnet, :80 HTTP
         ▼
┌──────────────────────────────────────────┐
│  chronos-sensor  (t4g.micro, AL2023)     │  assumed-compromised, disposable
│  ├─ Cowrie SSH/Telnet  (:22, :23)        │  host sshd moved to :22222 (SSM-only admin)
│  ├─ Canary HTTP        (:80)             │
│  └─ Vector edge        tail → disk buffer│  ships raw JSON lines, no parsing
└──────────────┬───────────────────────────┘
               │ :9002 private IP, chronos-soc-sg admits chronos-sensor-sg only
               ▼
┌──────────────────────────────────────────┐
│  chronos-soc-core  (m7i-flex.large)      │  zero inbound from the internet
│  ├─ Vector core     normalize + classify │  catalog CSV + command rules → severity, MITRE
│  ├─ OpenSearch 2.11 template, GeoIP, ISM │  chronos-logs-* (live) / chronos-replay-* (synthetic)
│  ├─ OpenSearch Dashboards (:5601)        │
│  ├─ TheHive 5.2 (:9000)                  │  one alert per attacker session
│  └─ triage loop                          │  OpenSearch → TheHive, idempotent by session
└──────────────────────────────────────────┘
               │ SSM port forwarding (outbound TLS only)
               ▼
        Analyst Mac: localhost:9000 TheHive, localhost:5601 Dashboards
```

Design rules:

1. **The sensor only collects and holds.** Vector on the sensor tails Cowrie and canary logs and forwards raw lines. It saves read positions and unsent events on disk, so restarts and core downtime lose nothing. The core can be stopped to save money while the sensor keeps collecting.
2. **One place for single-event detection.** `config/vector/threat_enrichment.csv` maps each event type to a severity (1–5) and MITRE ATT&CK technique. Command rules in `config/vector/vector-core.yaml` refine shell commands, for example T1105 download, T1098.004 SSH key, T1496 miner and T1082 discovery. Unit tests live in `config/vector/tests/`.
3. **Events → alerts → cases.** On a honeypot every event is hostile, so per-event alerts are noise. `scripts/triage-automation.py` raises **one TheHive alert per Cowrie session** that reaches severity ≥ 4 (successful login onwards). `sourceRef` is the Cowrie session id, so re-runs never duplicate. Analysts promote alerts to cases in TheHive.
4. **Synthetic data never mixes with live data.** The replay harness writes to `replay/` on the core and is indexed into `chronos-replay-*`. Live sensor events go to `chronos-logs-*`.
5. **Attacker strings are untrusted.** Commands and credentials are placed in fenced code blocks or escaped code spans in TheHive alerts and in the findings report.

### Data model (OpenSearch)

| Field | Type | Notes |
| :--- | :--- | :--- |
| `timestamp` | date | event time from the honeypot; picks the daily index |
| `src_ip` | ip | GeoIP → `geo.country_name`, `geo.location`; ASN → `as.asn`, `as.organization_name` |
| `session`, `eventid`, `honeypot` | keyword | Cowrie session id / event type; `cowrie` or `canary` |
| `severity` | integer | 1–5 |
| `mitre_technique`, `mitre_tactic`, `command_techniques` | keyword | primary technique, and every technique a command matched |
| `username`, `password`, `input` | keyword | credentials and shell commands |
| `path`, `query`, `body`, `user_agent`, `headers` | keyword / flat_object | canary HTTP requests |

GeoIP uses the GeoLite2 City/ASN databases bundled with OpenSearch 2.11.1, built in Nov 2023. Indices are deleted after 60 days by the `chronos-retention` ISM policy.

---

## Deploy

Both instances pull this repository from GitHub over SSM, so push your branch first.

```bash
scripts/deploy.sh core   [git-ref]   # OpenSearch, Dashboards, TheHive, Vector, triage + bootstrap
scripts/deploy.sh sensor [git-ref]   # sshd→22222, swap, Cowrie, canary, Vector edge
```

`deploy.sh core` creates `THEHIVE_SECRET_KEY` in the core's `.env` and runs `scripts/core-bootstrap.py`, which:

- installs the ingest pipeline, index template and ISM policy
- imports the Dashboards saved objects from `config/opensearch/dashboards.ndjson`
- rotates TheHive's default admin password
- creates the `chronos` organisation, the `analyst@chronos.local` user and the triage service account

Generated credentials (`THEHIVE_ADMIN_PASSWORD`, `THEHIVE_ANALYST_PASSWORD`, `THEHIVE_API_KEY`) stay in the core's `.env` and are never committed. To read them: `aws ssm start-session --target <core>`, then `sudo cat /home/ssm-user/Chronos/.env`.

## Verify

```bash
# On the core (repo root):
scripts/verify-gate1.sh   # template/pipeline/ISM present; replay event tagged and kept out of chronos-logs-*
scripts/verify-gate2.sh   # replayed session → exactly one TheHive alert; a second triage run adds none
docker run --rm -v "$PWD/config/vector:/etc/vector:ro" timberio/vector:0.34.1-alpine \
  test /etc/vector/vector-core.yaml /etc/vector/tests/vector-core.test.yaml

# From the Mac:
nc -zv <sensor-public-ip> 22 && nc -zv <sensor-public-ip> 23 && nc -zv <sensor-public-ip> 80   # must succeed
nc -zv -G 5 <core-public-ip> 9002                                                               # must fail
```

## Findings report

```bash
# On the core, or on the Mac with an SSM tunnel to :9200
python3 scripts/findings-report.py --exclude-ip <your-public-ip>
```

This writes `reports/findings-<date>.md` with these sections:

- collection window and daily volume
- top countries and ASNs
- MITRE techniques
- top credentials
- top commands
- bot families (sessions grouped by normalized command sequence) with enumeration patterns
- canary paths and user agents

The script exits non-zero if any section has no data.

---

## Administration (SSM quick reference)

```bash
./start_chronos.sh                      # start core containers + tunnels for 9000 / 5601 / 9200

aws ssm start-session --target <chronos-sensor-instance-id>
aws ssm start-session --target <chronos-soc-core-instance-id>
aws ssm start-session --target <chronos-soc-core-instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["9000"],"localPortNumber":["9000"]}'
```

---

## Documentation

| Document | Description |
| :--- | :--- |
| [`docs/scope.md`](docs/scope.md) | Capabilities, constraints, in/out-of-scope boundaries |
| [`docs/architecture.md`](docs/architecture.md) | Component specs, data flow diagrams, and threat model |
| [`docs/plan.md`](docs/plan.md) | Phased implementation plan and verification gates |
| [`aws/instance.md`](aws/instance.md) | AWS instance IDs and SSM access commands |
