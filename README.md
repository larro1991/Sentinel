# Sentinel

Security assessment toolkit with three-dimensional scope enforcement, honeypot defense, and professional reporting. Built in Rust.

## What It Does

Sentinel combines active scanning and passive defense in a single binary:

- **Reconnaissance** — DNS enumeration, subdomain discovery (CT logs + brute force), port scanning, service fingerprinting
- **Vulnerability checks** — 11 built-in checks: SSL/TLS, HTTP headers, SSH, SMB signing, default credentials, directory enumeration, SNMP, CORS, DNS zone transfer, SMTP relay, weak TLS ciphers
- **Honeypot defense** — 11 protocol honeypots capturing attacker activity in real time
- **Correlation engine** — Detects port scans, brute force, lateral movement, and event floods
- **SQLite persistence** — All events stored for querying via REST API
- **Professional reporting** — Markdown, JSON, HTML, CSV, and SARIF output with CVSS scoring

## Key Features

### Three-Dimensional Scope Enforcement
Every network operation passes through a scope validator:
1. **Spatial** — CIDR range whitelisting with explicit exclusions
2. **Temporal** — Time window restrictions (e.g., business hours only)
3. **Authorization** — Graduated levels from Passive to Post-Exploitation

If any dimension fails, the operation is blocked.

### Authorization Levels
| Level | Operations | Impact |
|-------|-----------|--------|
| Passive | DNS, WHOIS, cert transparency, subdomain enum | Zero |
| Scanning | Port scans, service fingerprinting, vuln checks | Network traffic |
| Verification | Safe PoC checks, version detection | Confirms exploitability |
| Exploitation | Actual exploit attempts | Requires explicit approval |
| Post-Exploitation | Persistence, lateral movement | Most invasive |

### Watch Mode (Honeypot Defense)
11 protocol honeypots with a full enrichment pipeline:
- **Protocols**: SSH, HTTP, SMB, FTP, Telnet, RDP, SMTP, DNS, MySQL, PostgreSQL, TLS
- **Enrichment**: Scope filtering, rate limiting, GeoIP, threat intelligence (AbuseIPDB)
- **Sinks**: Console, rotating NDJSON, webhooks, syslog/CEF, live dashboard, SQLite
- **Intelligence**: Event deduplication, correlation engine (port scan/brute force/lateral movement/flood detection)
- **REST API**: Query events, findings, correlations, and statistics

## Installation

```bash
# From source
git clone https://github.com/larro1991/Sentinel.git
cd Sentinel
cargo build --release

# Binary at target/release/sentinel
```

### Docker

```bash
docker-compose up -d
# Honeypots on various ports, dashboard on :9090, API on :9091
```

## Usage

```bash
# Full assessment (recon + vuln checks + reports)
sentinel run -c config/engagement.yaml

# Validate config without running
sentinel validate -c config/engagement.yaml

# Recon phase only
sentinel recon -c config/engagement.yaml

# Vulnerability checks only (uses previous recon results)
sentinel scan -c config/engagement.yaml

# Honeypot / passive defense mode
sentinel watch -c config/engagement.yaml

# Analyze captured watch events
sentinel watch-report -i results/watch-events.jsonl -o report.html

# Standalone API server for querying an existing database
sentinel serve --database results/sentinel.db
```

### REST API Endpoints

When running in watch mode with `api` configured, or via `sentinel serve`:

```
GET /health                          -> {"status":"ok"}
GET /api/events?severity=High&limit=10
GET /api/findings?module=cors-check
GET /api/correlations?rule_name=port-scan
GET /api/stats
```

## Engagement Configuration

Engagements are defined in YAML (see `config/engagement.yaml` for a full example):

```yaml
id: "engagement-001"
name: "Q1 2026 Security Assessment"

scope:
  targets:
    - "10.0.0.0/24"
    - "example.com"
    - "*.example.com"
  exclusions:
    - "10.0.0.1/32"
  time_windows:
    - start: "09:00"
      end: "17:00"
      days: ["Mon", "Tue", "Wed", "Thu", "Fri"]

authorization:
  max_level: "scanning"
  auto_approve_up_to: "scanning"

rate_limit_per_second: 100
emergency_contact: "security-team@example.com"
output_dir: "./results"

watch:
  bind_address: "0.0.0.0"
  database: "./results/sentinel.db"
  correlation_rules: "./config/correlation-rules.yaml"
  dedup_window_secs: 30
  api:
    port: 9091
  services:
    - protocol: ssh
      port: 2222
    - protocol: http
      port: 8888
    # ... see config/engagement.yaml for all 11
```

## Modules

### Reconnaissance (4 modules)
| Module | Auth Level | Description |
|--------|-----------|-------------|
| dns-enum | Passive | A, AAAA, MX, TXT, NS, SOA, CNAME records |
| subdomain-enum | Passive | CT logs (crt.sh) + DNS brute force (~200 words) |
| port-scan | Scanning | Async TCP connect scan (quick/standard/thorough profiles) |
| service-probe | Scanning | Banner grabbing, HTTP/TLS fingerprinting |

### Vulnerability Checks (11 checks)
| Check | Auth Level | Description |
|-------|-----------|-------------|
| ssl-tls-check | Scanning | Certificate validity, key strength, expiry |
| http-headers-check | Scanning | HSTS, CSP, X-Frame-Options, etc. |
| ssh-version-check | Scanning | Protocol version, known vulnerable versions |
| smb-signing-check | Scanning | SMB signing enforcement |
| default-creds-check | Scanning | Default credential detection |
| dir-enum-check | Scanning | Web directory enumeration |
| snmp-community-check | Scanning | SNMP community string testing |
| cors-check | Scanning | CORS misconfiguration (wildcard, reflection, credentials) |
| dns-zone-transfer-check | Scanning | DNS AXFR zone transfer detection |
| smtp-relay-check | Scanning | Open SMTP relay detection |
| tls-cipher-check | Scanning | Weak cipher suites (RC4, 3DES, CBC, old protocols) |

### Honeypot Listeners (11 protocols)
SSH, HTTP, SMB, FTP, Telnet, RDP, SMTP, DNS (UDP), MySQL, PostgreSQL, TLS

### Report Formats (5)
Markdown, JSON, HTML, CSV, SARIF

## Architecture

```
sentinel/
├── src/
│   ├── main.rs              # CLI (clap) — run, validate, recon, scan, watch, serve
│   ├── lib.rs               # Module declarations
│   ├── auth.rs              # Authorization levels
│   ├── config.rs            # YAML engagement config
│   ├── scope.rs             # 3-dimensional scope enforcement
│   ├── finding.rs           # Findings model + CVSS + dedup
│   ├── engine.rs            # Engagement execution engine
│   ├── store.rs             # SQLite event store
│   ├── api.rs               # axum REST API
│   ├── recon/               # 4 reconnaissance modules
│   ├── vuln/                # 11 vulnerability checks
│   ├── report/              # 5 report generators
│   └── watch/               # Honeypot system
│       ├── engine.rs        # Watch orchestrator + enrichment pipeline
│       ├── correlation.rs   # Pattern detection engine
│       ├── dedup.rs         # Event deduplication
│       ├── sqlite_sink.rs   # SQLite persistence sink
│       ├── alert.rs         # Console + JSON file sinks
│       ├── dashboard.rs     # Live HTML dashboard
│       ├── geo.rs           # GeoIP enrichment
│       ├── threat_intel.rs  # AbuseIPDB integration
│       ├── rate_limit.rs    # Per-IP rate limiting
│       ├── syslog.rs        # Syslog/CEF export
│       ├── webhook.rs       # Slack/generic webhook alerts
│       └── [11 honeypots]   # ssh.rs, http.rs, smb.rs, ...
├── config/
│   ├── engagement.yaml      # Example configuration
│   └── correlation-rules.yaml
├── tests/                   # 85 tests (unit + integration)
├── Dockerfile               # Multi-stage build
└── docker-compose.yml       # Full deployment
```

## Tests

```bash
cargo test
# 85 tests: 45 unit, 11 integration (honeypots), 29 Phase 3 (store, API, correlation, vuln checks)
```

## Ethical Use

Sentinel is designed for **authorized security testing only**. The scope enforcement system exists to prevent accidental or unauthorized testing. Always ensure you have written authorization before scanning any target.

## License

MIT

## Author

Larry Roberts
