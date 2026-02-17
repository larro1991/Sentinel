# Sentinel

Security assessment scanner with three-dimensional scope enforcement and professional reporting.

## What It Does

Sentinel is a standalone security scanner built in Rust that combines:
- **Passive reconnaissance** — DNS enumeration, certificate analysis
- **Active scanning** — Port scanning, service fingerprinting, banner grabbing
- **Vulnerability checks** — SSL/TLS configuration, HTTP security headers, SSH version analysis
- **Three-dimensional scope enforcement** — CIDR ranges, time windows, and authorization levels validated before every operation
- **Professional reporting** — Markdown and JSON reports with CVSS scoring, evidence, and remediation guidance

## Key Features

### Scope Enforcement (The Differentiator)
Every network operation passes through a three-dimensional scope validator:
1. **Spatial** — CIDR range whitelisting with explicit exclusions
2. **Temporal** — Time window restrictions (e.g., business hours only)
3. **Authorization** — Graduated levels from Passive to Post-Exploitation

If any dimension fails, the operation is blocked. No exceptions.

### Authorization Levels
| Level | Operations | Impact |
|-------|-----------|--------|
| Passive | DNS, WHOIS, cert transparency | Zero |
| Scanning | Port scans, service fingerprinting | Network traffic |
| Verification | Safe PoC checks, version detection | Confirms exploitability |
| Exploitation | Actual exploit attempts | Requires explicit approval |
| Post-Exploitation | Persistence, lateral movement | Most invasive |

### Findings Model
- CVSS 3.1 scoring
- CWE/CVE correlation
- Evidence-based (HTTP exchanges, banners, certificates)
- Automatic deduplication
- Severity-sorted reporting

## Installation

```bash
# From source
git clone https://github.com/larro1991/Sentinel.git
cd Sentinel
cargo build --release

# Binary will be at target/release/sentinel
```

## Quick Start

```bash
# 1. Create an engagement config (see engagement.yaml for example)

# 2. Validate your config
sentinel validate -c engagement.yaml

# 3. Run a full assessment
sentinel run -c engagement.yaml

# 4. Reports are saved to the output directory
```

## Usage

```bash
# Full assessment (recon + vuln checks + reports)
sentinel run -c engagement.yaml

# Validate config without running
sentinel validate -c engagement.yaml

# Recon phase only
sentinel recon -c engagement.yaml

# Vulnerability checks only
sentinel scan -c engagement.yaml
```

## Engagement Configuration

Engagements are defined in YAML:

```yaml
id: "engagement-001"
name: "Q1 2026 Security Assessment - Example Corp"
scope:
  targets:
    - "10.0.0.0/24"
    - "192.168.1.0/24"
    - "example.com"
    - "*.example.com"
  exclusions:
    - "10.0.0.1"          # Production database
    - "10.0.0.2"          # Domain controller
  time_windows:
    - start: "09:00"
      end: "17:00"
      days: ["Mon", "Tue", "Wed", "Thu", "Fri"]
authorization:
  max_level: "scanning"
  auto_approve_up_to: "scanning"
rate_limit_per_second: 100
emergency_contact: "security-team@example.com"
roe_document: "./rules-of-engagement.pdf"
output_dir: "./results"
```

## Modules

### Reconnaissance
| Module | Auth Level | Description |
|--------|-----------|-------------|
| dns-enum | Passive | A, AAAA, MX, TXT, NS, SOA, CNAME records |
| port-scan | Scanning | Async TCP connect scan, 32 common ports |
| service-probe | Scanning | Banner grabbing, HTTP fingerprinting |

### Vulnerability Checks
| Check | Auth Level | Safe | Description |
|-------|-----------|------|-------------|
| ssl-tls-check | Scanning | Yes | Certificate validity, key strength, expiry |
| http-headers-check | Scanning | Yes | HSTS, CSP, X-Frame-Options, etc. |
| ssh-version-check | Scanning | Yes | Protocol version, known vulnerable versions |

## Reports

Sentinel generates two report formats:

### Markdown Report (`report.md`)
Professional pentest report with executive summary, findings sorted by severity, evidence blocks, and remediation guidance.

### JSON Report (`report.json`)
Machine-readable output for integration with other tools, ticketing systems, or dashboards.

## Architecture

```
sentinel/
├── src/
│   ├── main.rs         # CLI (clap)
│   ├── lib.rs          # Module declarations
│   ├── auth.rs         # Authorization levels
│   ├── config.rs       # YAML engagement config
│   ├── scope.rs        # 3-dimensional scope enforcement
│   ├── finding.rs      # Findings model + CVSS + dedup
│   ├── engine.rs       # Engagement execution engine
│   ├── recon/          # Reconnaissance modules
│   │   ├── dns.rs      # DNS enumeration
│   │   ├── ports.rs    # Port scanning
│   │   └── service.rs  # Service fingerprinting
│   ├── vuln/           # Vulnerability checks
│   │   ├── ssl.rs      # SSL/TLS analysis
│   │   ├── headers.rs  # HTTP security headers
│   │   └── ssh.rs      # SSH version check
│   └── report/         # Report generators
│       ├── markdown.rs # Markdown report
│       └── json.rs     # JSON report
└── engagement.yaml     # Example config
```

## Adding Custom Modules

Sentinel uses Rust traits for extensibility:

```rust
#[async_trait]
pub trait ReconModule: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn authorization_level(&self) -> AuthorizationLevel;
    async fn execute(&self, target: &str) -> Result<ReconResult>;
}

#[async_trait]
pub trait VulnCheck: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn authorization_level(&self) -> AuthorizationLevel;
    fn is_safe(&self) -> bool;
    async fn check(&self, service: &Service) -> Result<Vec<Finding>>;
    fn applies_to(&self, service: &Service) -> bool;
}
```

## Ethical Use

Sentinel is designed for **authorized security testing only**. The scope enforcement system exists to prevent accidental or unauthorized testing. Always ensure you have written authorization before scanning any target.

## License

MIT

## Author

Larry Roberts
