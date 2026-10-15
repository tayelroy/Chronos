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
│  ├─ Cowrie SSH/Telnet  (:22, :23)        │  host sshd moved to :22222 (SSM-only admin); breadcrumbs
│  ├─ Canary HTTP        (:80)             │  per-IP server personas; honeytoken bait
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
│  ├─ triage loop                          │  OpenSearch → TheHive, idempotent by session
│  └─ honeytoken poller                    │  honeytoken account CloudTrail → Vector, SNS email
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
6. **The sensor can't be used as compute.** Cowrie emulates commands (nothing an attacker types executes) and fakes SSH port-forwarding. Decoy containers run non-root with no capabilities, `no-new-privileges` and read-only root filesystems. Cowrie's real fetches (`wget`/`curl`/`nc`, used for payload capture) are capped at 10 MB. `chronos-sensor-sg` admits only TCP 22/23/80 and allows egress only to TCP 80/443 (payload capture, SSM, image pulls) and 9002 to the core's security group. `chronos-soc-sg` admits only 9002 from the sensor's group and allows egress only to TCP 80/443 (AWS APIs, SSM, GitHub, image and package pulls). IMDSv2 with hop limit 1 keeps containers away from instance credentials. The Cowrie image is pinned by digest and the canary's Flask/Werkzeug by version, so upstream releases only arrive through a reviewed change.

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
| `persona`, `status` | keyword / integer | canary persona that answered (`iis`, `apache-php`, `nginx`, `router-boa`) and the HTTP status it returned |
| `bait`, `honeytoken_served` | keyword / boolean | canary bait file served (`dotenv`, `wp-config`, `git`) and whether the response contained its AWS key |

GeoIP uses the GeoLite2 City/ASN databases bundled with OpenSearch 2.11.1, built in Nov 2023. Indices are deleted after 60 days by the `chronos-retention` ISM policy.

## Experiments

The sensor runs two experiments on bot behaviour. Results land in the last two sections of the findings report.

**HTTP server personas.** `honeypots/canary_http/app.py` pins each source IP (by sha256) to one of four personas: IIS 10, Apache 2.4 with PHP (answers the PHPUnit `eval-stdin.php` RCE probe as if vulnerable), nginx 1.18, or a Boa GPON router login (`/boaform/admin/formLogin`, `formPing`). Personas differ only in fingerprint (`Server` header, default page, 404 page) and product pages; unknown paths return the persona's 404. Because assignment is random per IP, scanners that ignore the fingerprint hit every product path family at the same rate across personas. A persona pulling ahead on its own family means the scanners adapt. Adding or removing a persona reassigns every IP, so start a new analysis window when `PERSONAS` changes.

**Honeytokens and breadcrumbs.** Every bait carries its own AWS key pair, so a key-use alert names the file that leaked:

| Bait | Where | Variables |
| :--- | :--- | :--- |
| `GET /.env` | canary, Laravel-style `.env` | `HONEYTOKEN_DOTENV_AWS_KEY_ID`, `HONEYTOKEN_DOTENV_AWS_SECRET` |
| `GET /wp-config.php.bak` | canary, WordPress config with WP Offload Media keys | `HONEYTOKEN_WPCONFIG_AWS_*` |
| `GET /.git/…` | canary, dumpable repository (loose objects + index); the key is only in the committed `.env.production` blob, so it shows how deep each dumper goes | `HONEYTOKEN_GIT_AWS_*` |
| `/root/.aws/credentials` | Cowrie fake filesystem, next to a `/root/.bash_history` that points at `deploy@192.168.50.12` and `aws s3` commands | `HONEYTOKEN_COWRIE_AWS_*` |

`honeypots/cowrie/start-cowrie.py` wraps Cowrie's entrypoint: it copies the image's own `fs.pickle`, plants the breadcrumbs, and execs `twistd`. Bait with no key pair configured stays off (404 on the canary, no `/root/.aws` in Cowrie); `/root/.bash_history` is always planted. The fake internal hosts (`192.168.50.0/24`) are outside the VPC and Docker ranges, so nothing real answers. Vector tags the follow-up: `canary.honeytoken` (T1552.001) when a response carried a key, and the Cowrie command rules T1552.001 (AWS credentials), T1552.003 (reading shell history) and T1021.004 (`ssh`/`scp` to `user@host`).

The keys are self-hosted, so key-checking tools can't recognise them the way TruffleHog recognises canarytokens.org keys by their AWS account ID. `scripts/honeytokens-provision.sh <new-account-email> <alert-email>` (run once from the Mac with an admin `default` profile plus `chronos`; safe to re-run) sets up:

| Where | What |
| :--- | :--- |
| AWS Organization (Chronos account = management account) | member account `chronos-honeytokens`, holding nothing but the honeytokens |
| SCP on that account | denies every action to every IAM user in it, on top of each user's own deny-all policy |
| Honeytoken account | one IAM user + access key per bait (`billing-api-prod`, `wp-offload-media`, `billing-deploy`, `s3-backup-sync`: the names a `GetCallerIdentity` reveals). Keys authenticate but every call is denied. |
| Honeytoken account | role `ChronosHoneytokenReader`: `cloudtrail:LookupEvents` + `ec2:DescribeRegions`, assumable only by `ChronosCoreRole` |
| Chronos account | role `ChronosCoreRole` on chronos-soc-core only: the core's SSM/CloudWatch policies + assume the reader role + publish to SNS topic `chronos-honeytoken-alerts` (email). The sensor keeps `ChronosEdgeSSMRole` and can reach neither. |

The script writes `honeytokens.env` at the repo root (gitignored, mode 600) and finishes by proving every key authenticates and is denied `s3:ListAllMyBuckets`. Those check calls come from your IP, so run the findings report with `--exclude-ip`. Never commit `honeytokens.env`: the repo is public, the account id inside the keys would tie them to it, and GitHub scrapers would trigger them, so alerts could no longer be traced to a bait. `scripts/deploy.sh sensor` copies only the bait key pairs to the sensor; `scripts/deploy.sh core` copies only the key ids, the reader role and the topic to the core and enables the `honeytokens` compose profile.

`scripts/honeytoken-poller.py` (core, every 5 minutes) assumes the reader role, looks up each key's CloudTrail event history in every enabled region, appends new events to `honeytoken/events.json` for Vector (`honeytoken.key_used`, severity 5, T1078.004) and emails a summary through SNS. Event history is free and keeps 90 days, and the poller resumes from its last successful poll, so stopping the core only delays alerts. CloudTrail delivers events about 5–15 minutes after the call. The findings report's "Key use seen in CloudTrail" table shows, for each call, whether the same IP fetched that bait and how long after the first handout it came. Harvesters often fetch and use keys from different IPs, so a use with no matching fetch is itself a finding.

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
- experiment: HTTP server personas (requests per persona, product path families per persona, top paths)
- experiment: honeytoken bait and breadcrumbs (bait fetches, key recipients, `.git` dump depth per IP, Cowrie breadcrumb commands)

The script exits non-zero if any non-experiment section has no data. Experiment sections show `_No data yet._` until the bait is live.

---

## Administration

Day-to-day commands live in [`COMMANDS.md`](COMMANDS.md) (`cat COMMANDS.md`). The essentials:

```bash
export AWS_PROFILE=chronos        # least-privilege IAM user chronos-operator (config/iam/chronos-operator-policy.json)
./start_chronos.sh                # start both instances if stopped, compose up both, SSM tunnels 9000 / 5601 / 9200
./stop_chronos.sh                 # stop the core only; the sensor keeps collecting and buffers events
./stop_chronos.sh --all           # stop both instances
```

`start_chronos.sh`, `stop_chronos.sh` and `scripts/deploy.sh` share `scripts/lib/ssm.sh` (SSM `send-command` runner, wait-for-SSM, start-if-stopped). The `chronos-operator` IAM user can only: describe EC2/SSM, start/stop/reboot the two Chronos instances, edit the two Chronos security groups, and open SSM sessions or send commands to those two instances.

---

## Documentation

| Document | Description |
| :--- | :--- |
| [`docs/scope.md`](docs/scope.md) | Capabilities, constraints, in/out-of-scope boundaries |
| [`docs/architecture.md`](docs/architecture.md) | Component specs, data flow diagrams, and threat model |
| [`docs/plan.md`](docs/plan.md) | Phased implementation plan and verification gates |
| [`aws/instance.md`](aws/instance.md) | AWS instance IDs and SSM access commands |
