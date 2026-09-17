**Cloud-Edge Hybrid Deception & Active Defense Mesh**

## Architecture Overview
- **Deception Layer**: Cowrie SSH/Telnet honeypots & custom HTTP canary traps.
- **Log Pipeline**: Vector log streaming and structured parsing.
- **SIEM & Incident Response**: OpenSearch 2.x & TheHive 5 (Community Edition).
- **Active Defense**: Automated tarpitting, canary token payload tracking, and threat intel synthesis.

## Target Hardware
- Apple Silicon (M3 Air 16GB RAM) optimized container stack.

## Required Secrets
- Set `THEHIVE_SECRET_KEY` and `CORTEX_SECRET_KEY` in a local `.env` file before starting the stack.
- Use the `${VARIABLE_NAME}` syntax in `docker-compose.yml` for secret environment values.
