# Project Chronos

**Enterprise-Grade Deception & Active Defense Mesh** — A decoupled, cloud-native two-node AWS deployment for real-world adversary capture, automated detection & triage, forensic reconstruction, and incident response.

---

## Architecture Overview

```
[Public Internet / Attackers]
         │
         ▼
┌──────────────────────────────────┐
│  chronos-sensor  (t4g.micro)     │  AWS Cloud Edge Honeypot
│  ├─ Cowrie SSH/Telnet (:22)      │  Amazon Linux 2023 ARM64
│  ├─ Canary HTTP (:80)            │
│  └─ Vector Edge Forwarder        │
└──────────────┬───────────────────┘
               │ Port 9002 (VPC Private IP)
               ▼
┌──────────────────────────────────┐
│  chronos-soc-core  (m7i-flex.lg) │  AWS Cloud SOC & DFIR Core
│  ├─ Vector Aggregator (:9002)    │  Ubuntu 24.04 x86_64
│  ├─ OpenSearch 2.11+ (:9200)     │  Zero inbound WAN ports
│  ├─ OpenSearch Dashboards (:5601)│
│  ├─ TheHive 5.2 (:9000)          │
│  └─ Cortex 3.1.1 (:9001)         │
└──────────────────────────────────┘
               │
               │ SSM Port Forwarding (TLS, outbound-only)
               ▼
┌──────────────────────────────────┐
│  Analyst Workstation (Mac)       │  Admin Client Only
│  └─ localhost:9000 → TheHive     │  No local containers
│     localhost:5601 → Dashboards  │
└──────────────────────────────────┘
```

- **Deception Layer**: Cowrie SSH/Telnet honeypot & custom HTTP canary traps on `chronos-sensor`.
- **Telemetry Pipeline**: Vector edge forwarder streams JSON events to `chronos-soc-core` over port 9002 (intra-VPC, Security Group restricted).
- **SIEM & Analytics**: OpenSearch 2.11+ indexed under `chronos-logs-*` with MITRE ATT&CK severity scoring (Tiers 1–5).
- **SOAR & Incident Response**: TheHive 5.2 + Cortex 3.1.1 enforcing NIST SP 800-61 Rev. 2 playbooks.
- **Zero-Trust Admin Access**: All management via AWS SSM Session Manager — no inbound SSH/RDP on either node.

---

## Key Design Principles

1. **Zero Blast Radius** — The honeypot sensor is an assumed-compromised asset. Hypervisor-level Security Group referencing ensures compromise cannot pivot to the SOC core.
2. **Off-Host Telemetry** — Events are streamed off `chronos-sensor` in real time; an attacker who gains root cannot tamper with already-shipped logs.
3. **Zero Inbound WAN Management** — No public SSH, RDP, or dashboard ports. Administration is exclusively via encrypted AWS SSM tunnels.
4. **Cost-Efficient Architecture** — Intra-AZ telemetry (free), Internet Gateway outbound (free) instead of NAT Gateway ($32+/mo). Target: <$25/month total.

---

## Required Secrets

Set `THEHIVE_SECRET_KEY` and `CORTEX_SECRET_KEY` in a local `.env` file before starting the stack (see `.env.example`):

```bash
cat <<EOF > .env
THEHIVE_SECRET_KEY=$(openssl rand -base64 32)
CORTEX_SECRET_KEY=$(openssl rand -base64 32)
EOF
```

---

## Administration (SSM Quick Reference)

See [`aws/instance.md`](aws/instance.md) for instance IDs.

```bash
# Shell into chronos-sensor
aws ssm start-session --target <chronos-sensor-instance-id>

# Shell into chronos-soc-core
aws ssm start-session --target <chronos-soc-core-instance-id>

# Forward TheHive dashboard to localhost
aws ssm start-session \
  --target <chronos-soc-core-instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["9000"],"localPortNumber":["9000"]}'

# Forward OpenSearch Dashboards to localhost
aws ssm start-session \
  --target <chronos-soc-core-instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["5601"],"localPortNumber":["5601"]}'
```

---

## Documentation

| Document | Description |
| :--- | :--- |
| [`docs/scope.md`](docs/scope.md) | **Source of truth** — capabilities, constraints, in/out-of-scope boundaries, and resume bullets |
| [`docs/architecture.md`](docs/architecture.md) | Deep component specs, data flow diagrams, and threat model |
| [`docs/plan.md`](docs/plan.md) | Phased implementation plan with shell commands and verification gates |
| [`aws/instance.md`](aws/instance.md) | AWS instance IDs and SSM access commands |
