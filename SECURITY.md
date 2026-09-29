# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |
| 0.1.x   | No        |

## Reporting a Vulnerability

**Do not report security vulnerabilities through the public issue tracker.**

If you discover a security vulnerability in BugPilot, please report it responsibly:

- **Email**: security@bugpilot.dev (PGP key available on request)
- **HackerOne**: https://hackerone.com/bug-pilot (if available)

Include in your report:
1. Description of the vulnerability
2. Steps to reproduce
3. Affected version/commit (if known)
4. Potential impact
5. Your contact information

## Scope

This project is a security testing tool. Vulnerabilities in this tool's own code are in scope. Vulnerabilities in third-party tools (nuclei, subfinder, httpx, Playwright) should be reported to their respective maintainers.

## Response Timeline

- Acknowledgment within 3 business days
- Triage complete within 7 business days
- Fix release targeted within 30 days for critical issues

## Bug Bounty

BugPilot itself is not in scope for any bug bounty program. This policy applies only to security issues in the tool's own source code.
