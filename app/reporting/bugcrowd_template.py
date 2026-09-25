BUGCROWD_TEMPLATE = """# {vuln_class} — {endpoint}

**Priority:** {priority}
**VRT Category:** {vrt_category}
**CVSS:** {cvss_score} ({cvss_vector})

## Description
{description}

## Business Impact
{impact}

## Steps to Reproduce
{steps_to_reproduce}

## Proof of Concept

### Request
```
{request}
```

### Response
```
{response}
```

{screenshot_section}

## Browser / Environment
{browser_env}

## Recommendation
{remediation}
"""

VRT_MAP = {
    "reflected_xss": "Client-Side > Cross-Site Scripting (XSS) > Reflected XSS",
    "stored_xss": "Client-Side > Cross-Site Scripting (XSS) > Stored XSS",
    "dom_xss": "Client-Side > Cross-Site Scripting (XSS) > DOM-based XSS",
    "sqli": "Injection > SQL Injection",
    "nosqli": "Injection > NoSQL Injection",
    "command_injection": "Injection > OS Command Injection",
    "ssrf": "Server-Side > Server-Side Request Forgery (SSRF)",
    "open_redirect": "Client-Side > Open Redirect",
    "csrf": "Client-Side > Cross-Site Request Forgery (CSRF)",
    "http_request_smuggling": "Server-Side > HTTP Request Smuggling",
    "xxe": "Injection > XML External Entity Injection (XXE)",
    "idor": "Access Control > Insecure Direct Object Reference (IDOR)",
    "bola": "Access Control > Broken Object Level Authorization (BOLA)",
    "privilege_escalation": "Access Control > Privilege Escalation",
    "jwt_flaws": "Authentication > JSON Web Token (JWT) Vulnerabilities",
    "ssti": "Injection > Server-Side Template Injection (SSTI)",
    "file_upload": "File Upload > Unrestricted File Upload",
    "race_condition": "Business Logic > Race Condition",
    "cors": "Configuration > CORS Misconfiguration",
    "subdomain_takeover": "Configuration > Subdomain Takeover",
}


def render_bugcrowd(finding: dict) -> str:
    screenshot_section = ""
    if finding.get("evidence", {}).get("screenshot"):
        screenshot_section = f"\n### Screenshot\n![PoC Screenshot]({finding['evidence']['screenshot']})\n"

    request_str = finding.get("evidence", {}).get("request_url", "")
    if finding.get("evidence", {}).get("payload"):
        request_str += f"\n\nPayload: {finding['evidence']['payload']}"

    response_str = finding.get("evidence", {}).get("response_body_snippet", "")
    if finding.get("evidence", {}).get("response_body"):
        response_str = finding["evidence"]["response_body"][:2000]

    vuln_key = finding.get("vuln_class", "").lower().replace(" ", "_")

    return BUGCROWD_TEMPLATE.format(
        vuln_class=finding.get("vuln_class", "Unknown"),
        endpoint=finding.get("endpoint", ""),
        priority=finding.get("priority", "P3"),
        vrt_category=VRT_MAP.get(vuln_key, "Uncategorized"),
        cvss_score=finding.get("cvss_score", 0.0),
        cvss_vector=finding.get("cvss_vector", ""),
        description=finding.get("description", ""),
        impact=finding.get("impact", ""),
        steps_to_reproduce=finding.get("steps_to_reproduce", ""),
        request=request_str,
        response=response_str,
        screenshot_section=screenshot_section,
        browser_env="Tested via automated browser (Playwright/Chromium)",
        remediation=finding.get("remediation", ""),
    )