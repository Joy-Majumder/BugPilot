# BugHunter - Personal Bug Bounty Automation Tool

> **⚠️ Legal Notice**: This tool is for testing targets you are explicitly authorized to test — programs on HackerOne/Bugcrowd where you're enrolled and in-scope, or your own infrastructure. Running any of this against unauthorized targets is illegal regardless of intent.

A self-contained, local-first bug bounty automation tool that runs as a web application. Everything (Python deps, binaries like nuclei/sqlmap, databases) lives inside the project directory — no system-wide installation.

## Features

- **Self-contained**: Single `bootstrap.sh` creates venv, downloads all binaries (nuclei, subfinder, httpx), installs Playwright browsers locally
- **Web UI**: Local-only FastAPI server (127.0.0.1:8080) with real-time WebSocket progress
- **Comprehensive Detection**: 18+ vulnerability classes with proof-based confirmation
- **Multi-format Reports**: HackerOne and Bugcrowd markdown templates with VRT category mapping
- **Authenticated Testing**: Multi-session support for IDOR/BOLA/privilege escalation detection
- **OOB Confirmation**: Built-in DNS/HTTP callback server for blind SSRF/XXE/SSTI/RCE
- **Evidence Storage**: SQLite database with full request/response capture, screenshots, dedup

## Quick Start

```bash
git clone <this-repo> bughunter
cd bughunter
./bootstrap.sh

# Start the web UI
bughunter serve
# Open http://127.0.0.1:8080

# Or run interactively (no args = menu)
bughunter

# Or use CLI commands directly
bughunter scan --target https://example.com
bughunter list-scans
bughunter findings --scan-id 1
bughunter report --finding-id 1 --format bugcrowd
```

## Directory Structure

```
bughunter/
├── venv/                      # Local Python virtualenv
├── tools/                     # Downloaded binaries (nuclei, subfinder, httpx, Playwright browsers)
├── data/
│   ├── findings.db            # SQLite database
│   ├── sessions/              # Auth sessions/cookies per target
│   └── payloads/              # Custom payload library
├── reports/
│   └── <target>/<date>/       # Generated markdown reports
├── app/
│   ├── server.py              # FastAPI web server
│   ├── recon/                 # Recon module (subfinder, nuclei, tech detection)
│   ├── crawler/               # JS-aware crawler (Playwright)
│   ├── detectors/             # Vulnerability detectors (plugin pattern)
│   ├── validation/            # Proof capture, diffing, dedup
│   ├── scoring/               # CVSS 3.1 scoring
│   ├── reporting/             # HackerOne/Bugcrowd templates
│   └── oob_server.py          # Out-of-band callback server
├── bootstrap.sh               # One-shot installer
├── requirements.txt
├── pyproject.toml
└── cli.py                     # Typer CLI entrypoint
```

## Vulnerability Classes Detected

| Category | Detectors |
|----------|-----------|
| **Injection** | SQLi (error/boolean/time), NoSQLi, Command Injection, LDAP, XPath, XXE |
| **XSS** | Reflected (Playwright execution), Stored, DOM-based (taint tracking), Blind (OOB) |
| **SSRF** | Basic, Blind (OOB), Cloud metadata (AWS/GCP/Azure), Filter bypasses |
| **Auth/Access** | IDOR, BOLA (API Top 10 #1), Privilege Escalation, JWT flaws |
| **SSTI** | Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, Thymeleaf, Express |
| **File Upload** | Extension bypass, Content-Type bypass, Polyglots, Webshell detection |
| **Business Logic** | Race conditions (TOCTOU), Price/quantity manipulation, Workflow bypass |
| **Client-side** | Open Redirect, CSRF, CORS, Clickjacking, postMessage, DOM Clobbering, Prototype Pollution |
| **API Security** | All OWASP API Top 10 2023 categories |
| **Infrastructure** | Subdomain takeover, Exposed admin panels, Weak TLS |
| **AI/LLM** | Prompt injection, Sensitive info disclosure, Insecure output handling |

## Detection Philosophy

**Proof over patterns**: Every finding requires executable proof:
- XSS → Headless browser confirms JS execution
- SQLi → Boolean differential + timing + optional sqlmap handoff
- SSTI → Math expression evaluation (`{{7*7}}` → `49`)
- Blind SSRF/XXE/RCE → OOB DNS/HTTP callback correlation
- Race conditions → Concurrent request state divergence

## Report Generation

Reports are generated as Markdown in your chosen format:

```markdown
# [Critical] SQL Injection in /api/users?id=1

## Summary
The `id` parameter is vulnerable to error-based SQL injection...

## Severity
Critical (CVSS 3.1: 9.8 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Steps To Reproduce
1. Navigate to: https://target.com/api/users?id=1'
2. Observe database error in response

## Proof of Concept
```
GET /api/users?id=1' HTTP/1.1
Host: target.com
```

## Impact
Full database read/write access via UNION injection...

## Suggested Remediation
Use parameterized queries. Never concatenate user input into SQL.
```

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
OOB_DOMAIN=your-oob-domain.com  # Required for real OOB callbacks
OOB_HTTP_PORT=8081
OOB_DNS_PORT=5353
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
```

## CLI Usage

```bash
# Interactive menu (run with no arguments)
bughunter

# Run a scan
bughunter scan --target https://example.com --name "My Scan" --detectors sqli,ssrf --rate-limit 10 --concurrency 5

# List all scans
bughunter list-scans

# View findings for a scan
bughunter findings --scan-id 1

# Generate a report for a finding
bughunter report --finding-id 1 --format hackerone  # or bugcrowd

# Start web UI
bughunter serve  # or: bughunter serve --port 9090
```

## Adding Custom Payloads

```bash
bughunter payload add --category sqli --context "mysql" --payload "' OR '1'='1" --desc "Basic boolean bypass"
```

Or via web UI → Settings → Payload Library.

## Architecture Highlights

1. **Plugin-based detectors** — Each vuln class is a独立 `Detector` class with `applies_to()` and `run()`
2. **Multi-role crawling** — Crawl as multiple users simultaneously for IDOR/BOLA detection
3. **Stateful workflow testing** — Multi-step flows (cart→checkout) with concurrent race testing
4. **Scope-aware** — Parses program scope rules, enforces rate limits, excludes paths
5. **Dedup by design** — `hash(vuln_class + endpoint + param)` prevents duplicate findings
6. **Confidence tagging** — `confirmed` (proof) vs `suspected` (heuristic only)

## Requirements

- Python 3.10+
- Linux/macOS (Windows WSL2 supported)
- ~500MB disk space for tools/browsers

## License

MIT — Use responsibly and only on authorized targets.