# Contributing to BugPilot

Thank you for your interest in contributing! This document covers everything you need to get started.

## Development Setup

```bash
git clone https://github.com/Joy-Majumder/BugPilot.git
cd BugPilot
./bootstrap.sh
```

This creates a self-contained environment with all dependencies, binaries, and Playwright browsers in the project directory.

## Project Structure

```
BugPilot/
├── venv/                       # Local Python virtualenv
├── tools/                      # Downloaded binaries (subfinder, httpx, nuclei)
├── data/                       # SQLite database, sessions
├── reports/                    # Auto-generated findings
├── app/
│   ├── server.py               # FastAPI web server
│   ├── scan_pipeline.py        # Orchestration: recon → crawl → detect → report
│   ├── recon/                  # Subdomain/host discovery + tech fingerprinting
│   ├── crawler/                # JS-aware Playwright crawler
│   ├── detectors/              # Vulnerability detectors (plugin architecture)
│   │   ├── base.py             # Detector + Endpoint + Finding base classes
│   │   ├── sqli.py             # SQL injection detectors
│   │   ├── xss.py              # XSS detectors
│   │   ├── ssrf.py             # SSRF detectors
│   │   ├── ssti.py             # Server-side template injection
│   │   ├── advanced.py         # Clickjacking, LDAP, XPath, DOM Clobber,
│   │   │                       #   Prototype Pollution, PostMessage, Blind XSS,
│   │   │                       #   Admin Panel, Weak TLS, Price/Qty, AI/LLM
│   │   └── __init__.py         # Detector registry
│   ├── reporting/              # HackerOne + BugCrowd report templates
│   ├── scoring/                # CVSS 3.1 scoring
│   ├── validation/             # Finding storage, dedup, proof validation
│   └── templates/              # Web UI templates
├── cli.py                      # Typer CLI entrypoint
├── pyproject.toml              # Package config, dependencies
└── bootstrap.sh                # One-shot installer
```

## Architecture Overview

1. **CLI entry** (`cli.py`) — Typer commands: `scan`, `findings`, `report`, `serve`
2. **Scan pipeline** (`app/scan_pipeline.py`) — orchestrates the full workflow:
   - Recon → Crawl → Detect → Finalize
3. **Detectors** (`app/detectors/`) — each implements `applies_to()` and `run()`, returns `Finding` objects
4. **Findings** — stored in SQLite with dedup by `vuln_class|host|param`
5. **Reporting** — auto-generates markdown reports in HackerOne or BugCrowd format

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

- Python 3.10+
- Type hints required
- `black` for formatting, `ruff` for linting
- No emojis in code or output

## Adding a Detector

See `app/detectors/base.py` for the `Detector` base class. Your detector must implement:
- `name` (string identifier)
- `vuln_class` (display name)
- `cvss_vector_template`
- `bugcrowd_vrt_category`
- `applies_to(endpoint)` → bool
- `async run(endpoint)` → List[Finding]

Register it in `app/detectors/__init__.py` and add its CVSS vector in `app/scoring/cvss.py`.

## Submitting Changes

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run verification: `./venv/bin/python scripts/verify_setup.py`
5. Commit with a descriptive message
6. Open a Pull Request

**Do NOT commit**:
- `.env` files (contains sensitive config)
- Database files (`data/*.db`)
- Generated reports (`reports/`)
- Large binaries in `tools/`
