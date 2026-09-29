# Changelog

All notable changes to BugPilot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Subdomain discovery** — subfinder + httpx integration for live host enumeration
- **API path fuzzing** — auto-discovers `/api/v1`, `/graphql`, `/wp-json`, `/admin` and 15+ common API endpoints
- **Host-scope crawler restriction** — crawler only follows links within the same root domain
- **32 vulnerability detectors**:
  - Injection: SQLi (error/boolean/time), NoSQLi, Command Injection, LDAP, XPath, XXE
  - XSS: Reflected, Stored, DOM-based, Blind (OOB)
  - SSRF: Basic, Blind (OOB), Cloud metadata (AWS/GCP/Azure), Filter bypasses
  - Auth/Access: IDOR, BOLA, Privilege Escalation, JWT
  - SSTI: Jinja2, Twig, Freemarker, Velocity, ERB, Thymeleaf, Express
  - Client-side: Clickjacking, CSRF, CORS, postMessage, DOM Clobbering, Prototype Pollution
  - Infrastructure: Subdomain takeover, Admin panel, Weak TLS
  - API Security: OpenAPI exposure, unauthenticated endpoints
  - AI/LLM: Prompt injection, data exposure
- **Built-in OOB callback server** — DNS + HTTP callback for blind vulnerability validation
- **Auto-report generation** — HackerOne + BugCrowd (VRT) markdown format with CVSS scoring
- **Interactive CLI menu** — `bugpilot` with no arguments launches full-screen menu
- **Web UI** — FastAPI server with real-time progress tracking

### Changed
- Dedup hash now includes host (not full URL) to prevent duplicate findings across pages
- Reduced API path list to 20 essential endpoints
- Endpoint scan cap at 30 targets to prevent excessive runtime
- Renamed project from BugHunter to BugPilot

### Fixed
- Background task GC in FastAPI server (asyncio.Task reference leak)
- Blocking socket calls in HTTP request smuggling detector (asyncio.to_thread)
- Playwright page lifecycle leaks in XSS detector
- Recon timeout resilience with fallback to target URL
- Missing await in crawl timeout fallback
- Report evidence key naming (`response_snippet` → `response_body_snippet`)
