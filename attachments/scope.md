# Project Chronos: Scope & Capability Alignment

> **Document Version**: 2.0.0  
> **Target Role**: SOC Analyst (Tier 1/Tier 2) & Digital Forensics / Incident Response (DFIR) Engineer / Security Intern  
> **Author**: Senior Software Engineer / Elroy Tay  
> **Workspace Path**: `docs/scope.md`  

---

## 1. Executive Summary & Mission

**Project Chronos** is an enterprise-grade, cloud-native **Deception & Active Defense Mesh** engineered to capture real-world adversary behavior, automate detection and triage, reconstruct forensic artifacts, and orchestrate incident response.

Unlike standard tutorial homelabs that run monolithic, resource-heavy SIEM instances locally on personal computers or on expensive on-premise rack servers, Project Chronos is architected as a decoupled, multi-node cloud deployment within Amazon Web Services (AWS) that overcomes core operational constraints:
1. **Separation of Concerns & Zero Blast Radius**: An internet-exposed honeypot is an assumed-compromised asset. By decoupling bait decoys from the analytics and case management core into distinct cloud virtual instances with hypervisor-enforced security group isolation, compromise of an edge sensor cannot pivot to or compromise the SIEM/SOAR data store.
2. **Elimination of Host Resource Overhead**: Offloading all heavy analytical workloads (OpenSearch, TheHive, Cortex) from the local analyst workstation (e.g. Apple Silicon M3 Mac) to a dedicated cloud SOC core instance eliminates thermal throttling, memory pressure, and local VM hypervisor overhead. The analyst workstation functions strictly as an administrative client.
3. **Zero Administrative Public Exposure**: Zero public WAN management ports (no open SSH/RDP, no public web dashboards). Both cloud nodes are managed and accessed exclusively through encrypted **AWS Systems Manager (SSM) Session Manager** and SSM Port Forwarding tunnels over outbound TLS.

The architecture is implemented across a two-node AWS EC2 topology:
- **`chronos-sensor`** (Cloud Edge Honeypot): Low/medium-interaction deception node running Cowrie (SSH/Telnet) and custom HTTP canary traps, streaming real-time JSON telemetry off-host over port 9002.
- **`chronos-soc-core`** (Cloud SIEM/SOAR Core): Centralized analytics and orchestration node running OpenSearch 2.11+, TheHive 5.2, Cortex 3.1.1, and Vector aggregator. The node has zero inbound ports from the public internet; its ingestion port (9002) is strictly restricted to traffic originating from `chronos-sensor-sg`.

---

## 2. Core Operational Requirements & Constraints

| Dimension | Constraint | Architecture Solution |
| :--- | :--- | :--- |
| **Cloud SOC Core (`chronos-soc-core`)** | Resource allocation for SIEM, SOAR, & Ingestion | Sized on AWS `m7i-flex.large` (8 GB RAM, Ubuntu 24.04 x86_64). Allocated ~4.8 GB across Docker containers: OpenSearch 2.11+ (1.5 GB limit, JVM heap capped at `-Xms1g -Xmx1g`), TheHive 5.2 (1.8 GB limit), Cortex 3.1.1 (1.2 GB limit), and Vector Aggregator (0.3 GB limit). |
| **Cloud Edge Sensor (`chronos-sensor`)** | Lightweight bait footprint (<$5/mo or Free Tier) | Sized on AWS `t4g.micro` (1 GB RAM, Amazon Linux 2023 ARM64). Runs lightweight edge decoys (Cowrie SSH container, Canary HTTP container, and Vector edge shipper) with host `sshd` moved to port 22222 so Cowrie binds port 22 cleanly. |
| **Analyst Workstation (M3 Mac)** | Zero local workload burden | No local containers or heavy JVM/SIEM runtimes. The workstation acts purely as an analyst client connecting to TheHive (:9000) and OpenSearch Dashboards (:5601) via secure AWS SSM port forwarding tunnels over localhost. |
| **Telemetry Ingestion & Transport** | Reliable, isolated inter-node log delivery | Telemetry streamed directly from `chronos-sensor` to `chronos-soc-core` private IP on port `9002`. Both instances reside in the same VPC subnet (`project-subnet-public1-us-east-1a`) for free intra-AZ data transfer. |
| **Containment / Micro-Segmentation** | Prevent honeypot pivot, abuse, or tampering | **AWS Hypervisor Security Group Referencing**: `chronos-soc-sg` permits port 9002 ingress exclusively from `chronos-sensor-sg`. The SOC instance has **0% inbound WAN visibility** from the public internet. |
| **Admin Attack Surface** | Zero internet-facing management interfaces | No open SSH (port 22) or web ports exposed to the WAN for admin. Administration is conducted 100% via **AWS Systems Manager (SSM) Session Manager**. |
| **Infrastructure Cost Optimization** | Budget-conscious engineering | Public IP auto-assignment on SOC core allows outbound package/container updates via Internet Gateway with 0 inbound WAN access, avoiding costly AWS NAT Gateways ($32.40/mo). Free intra-AZ communication. |

---

## 3. In-Scope vs. Out-of-Scope Boundaries

### In-Scope (Core Deliverables)

- **Node 1: AWS Cloud Edge Sensor (`chronos-sensor` - `t4g.micro`)**:
  - **Cowrie Honeypot**: Medium-interaction SSH/Telnet daemon listening on port 22 (host `sshd` shifted to port 22222), emulating a Debian `svr04` environment, recording credentials, command executions, and raw binary `ttylog` sessions.
  - **Canary HTTP Web Trap**: Lightweight Python/Flask decoy web server capturing HTTP reconnaissance probes (Nikto, SQLmap, web scanners, directory traversal).
  - **Edge Vector Forwarder**: Ingests local honeypot JSON streams and forwards them across the private VPC network to the SOC Core on port 9002.
  - **Hypervisor Egress Isolation**: Security group locking down outbound traffic to prevent compromised honeypot instances from participating in botnets or lateral movement.
  - **AWS SSM Agent**: Zero-port shell administration.

- **Node 2: AWS SOC & DFIR Core (`chronos-soc-core` - `m7i-flex.large`)**:
  - **Vector Ingestion Aggregator**: Listens on port 9002 for the sensor telemetry stream, normalizes events, applies MITRE ATT&CK tagging and 5-tier severity scoring, and bulk-indexes into OpenSearch.
  - **OpenSearch 2.11+ SIEM**: Single-node cluster with capped JVM heap (`-Xms1g -Xmx1g`), indexed under `chronos-logs-*`.
  - **OpenSearch Dashboards**: Centralized analytics, attack heatmaps, triage distribution, and operational metrics (MTTD / MTTA / MTTR).
  - **TheHive 5.2 + Cortex 3.1.1 SOAR**: Structured incident case management backed by OpenSearch and BerkeleyDB, pre-configured with NIST SP 800-61 Rev. 2 incident playbooks.
  - **Automated Triage & DFIR Tools**: Python automation scripts (`triage-automation.py`, `dfir-tools.py`) polling OpenSearch for High-Severity alerts (Severity >= 4), deduplicating events, extracting observables, and generating case dossiers with forensic transcripts.

- **Analyst Workstation (Mac Client)**:
  - Secure tunnel initiator using AWS CLI SSM port-forwarding sessions:
    - Port 9000 forward -> TheHive UI (`http://localhost:9000`)
    - Port 5601 forward -> OpenSearch Dashboards (`http://localhost:5601`)
  - No local Docker or SOC containers required.

### Out-of-Scope (Explicit Non-Goals)

- **Local Mac SOC Hosting**: No local execution of OpenSearch, TheHive, or SIEM pipelines on the analyst's laptop; all workloads are cloud-hosted.
- **High-Interaction / Live Windows Kernels**: No live uncontained Windows/Linux malware execution on bare metal.
- **Offensive Counter-Measures (Hacking Back)**: No automated port-scanning, credential brute-forcing, or retaliatory exploitation directed at attacker source IPs.
- **Commercial Enterprise Licenses**: No proprietary enterprise SIEM/SOAR platforms (Splunk Enterprise, Palo Alto XSOAR, Microsoft Sentinel).
- **Expensive Cloud Topologies**: No paid NAT Gateways, transit gateways, or multi-region setups that incur unnecessary cloud expenditures.

---

## 4. Alignment with Target SOC & DFIR Capabilities

```
+---------------------------------------------------------------------------------------+
|                              PROJECT CHRONOS CAPABILITY MAP                           |
+---------------------------------------------------------------------------------------+
|  SOC Tier 1 / Tier 2 Competency    <--->   Chronos Implementation & Evidence          |
+---------------------------------------------------------------------------------------+
|  Alert Triage & Queue Fatigue      <--->   triage-automation.py: automated            |
|  Management                                deduplication, observable extraction, and   |
|                                            severity scoring before case dispatch.     |
|                                                                                       |
|  SIEM Detection Engineering        <--->   OpenSearch query DSL rules mapping to      |
|                                            MITRE ATT&CK (T1110, T1059, T1190, T1595).  |
|                                                                                       |
|  Operational Metrics Tracking      <--->   OpenSearch Dashboards tracking MTTD,       |
|                                            MTTA, and MTTR with baseline comparisons.  |
|                                                                                       |
|  Incident Response Playbooks       <--->   TheHive 5 structured case templates        |
|                                            enforcing NIST SP 800-61 Rev. 2 phases.    |
+---------------------------------------------------------------------------------------+
|  DFIR Competency                   <--->   Chronos Implementation & Evidence          |
+---------------------------------------------------------------------------------------+
|  Terminal Session Reconstruction  <--->   dfir-tools.py: parsing raw Cowrie ttylog   |
|                                            binaries into chronological terminal text. |
|                                                                                       |
|  Malware Staging & Artifact Triage <--->   dfir-tools.py: SHA256 cryptographic        |
|                                            hashing, VirusTotal reputation enrichment. |
|                                                                                       |
|  Chain of Custody & Dossier        <--->   Automated forensic artifact attachment     |
|  Packaging                                 to TheHive case files via REST API.        |
+---------------------------------------------------------------------------------------+
|  Cloud & Infrastructure Security   <--->   Chronos Implementation & Evidence          |
+---------------------------------------------------------------------------------------+
|  Cloud Micro-Segmentation         <--->   Security Group referencing: chronos-soc-sg  |
|                                            permits port 9002 only from sensor SG.     |
|                                                                                       |
|  Zero-Trust Remote Administration  <--->   AWS SSM Session Manager (zero inbound WAN  |
|                                            management ports; encrypted port tunnels). |
|                                                                                       |
|  Decoupled Cloud Architecture      <--->   Independent bait (sensor) & core (SOC)     |
|                                            nodes isolating attacker blast radius.     |
+---------------------------------------------------------------------------------------+
```

### Detailed Competency Breakdown

#### A. Security Operations Center (SOC) Operations & Triage
- **The Competency**: Triage high-volume alerts, distinguish false positives from true positives, prioritize incidents based on severity, and prevent analyst burnout.
- **Chronos Evidence**: `triage-automation.py` monitors OpenSearch for events. Low-severity scanner noise is aggregated into metrics, while multi-stage attacks (e.g., successful Cowrie authentication followed by `curl`/`wget` execution) receive elevated Severity 4/5 tags and are auto-dispatched into TheHive with pre-populated observable tags (`src_ip`, `user_agent`, `command_chain`).

#### B. Detection Engineering & MITRE ATT&CK Mapping
- **The Competency**: Authoring actionable detection logic grounded in recognized adversary tactics, techniques, and procedures (TTPs).
- **Chronos Evidence**: Detections are formally mapped to MITRE ATT&CK technique IDs:
  - `T1110` (Brute Force): Credential spraying on Cowrie SSH.
  - `T1059.004` (Command and Scripting Interpreter: Unix Shell): Interactive commands executed post-authentication.
  - `T1105` (Ingress Tool Transfer): Attacker using `wget`/`curl` to download staging binaries.
  - `T1595.002` (Active Scanning: Vulnerability Scanning): Nikto, SQLmap, and web vulnerability probing on Canary HTTP.

#### C. Digital Forensics & Incident Response (DFIR)
- **The Competency**: Extracting digital evidence, analyzing attacker tradecraft, handling malicious artifacts, and reconstructing adversary actions step-by-step.
- **Chronos Evidence**: `dfir-tools.py` reads Cowrie's binary `ttylog` files and generates clean ASCII session transcripts showing exact keystrokes, typos, and backspaces. When attackers download tools or drop scripts, the file is automatically quarantined, its SHA256 hash calculated, checked against threat intelligence APIs, and attached to the investigation case file.

#### D. Operational Metrics & Continuous Process Improvement
- **The Competency**: Quantifying SOC performance and demonstrating measurable efficiency improvements through automation.
- **Chronos Evidence**: The triage automation workflow enables A/B benchmarking: comparing manual analyst triage against automated SOAR ingestion. OpenSearch Dashboards display the resulting reduction in **Mean Time to Acknowledge (MTTA)** from ~3–5 minutes down to <2 seconds.

---

## 5. Resume & Portfolio Bullet Points

- **Bullet 1 (Distributed Cloud Deception & SIEM)**:  
  *“Architected a decoupled two-node AWS cloud deception mesh (`chronos-sensor` and `chronos-soc-core`) streaming real-time SSH and HTTP threat telemetry over port 9002 into OpenSearch 2.x, authoring detection rules mapped to MITRE ATT&CK (T1110, T1059, T1190).”*
- **Bullet 2 (Security Automation & SOAR)**:  
  *“Engineered a Python triage automation engine (`triage-automation.py`) integrating OpenSearch and TheHive 5 REST APIs, automating observable qualification and dispatching NIST SP 800-61 response playbooks, reducing MTTA by >98%.”*
- **Bullet 3 (DFIR & Artifact Analysis)**:  
  *“Built a digital forensics pipeline (`dfir-tools.py`) that reconstructs raw binary `ttylog` sessions into terminal transcripts, computes SHA256 cryptographic hashes for dropped staging payloads, and auto-packages forensic dossiers for case files.”*
- **Bullet 4 (Cloud Infrastructure & Zero-Trust Access)**:  
  *“Enforced zero-blast-radius containment between cloud honeypot and SOC core using hypervisor-level security group referencing and zero inbound public management ports, accessing dashboards securely via encrypted AWS SSM port-forwarding tunnels.”*
- **Bullet 5 (Systems & Cost Optimization)**:  
  *“Designed a highly cost-efficient cloud architecture (<$25/mo) by co-locating instances in a single AZ to eliminate inter-AZ transfer costs and leveraging Internet Gateway routing to avoid paid AWS NAT Gateways while maintaining strict 0% WAN inbound visibility on the SOC core.”*
