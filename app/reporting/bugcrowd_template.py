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
    "cross-site_scripting_(xss)": "Client-Side > Cross-Site Scripting (XSS)",
    "sqli": "Injection > SQL Injection",
    "sql_injection": "Injection > SQL Injection",
    "nosqli": "Injection > NoSQL Injection",
    "nosql_injection": "Injection > NoSQL Injection",
    "command_injection": "Injection > OS Command Injection",
    "os_command_injection": "Injection > OS Command Injection",
    "ssrf": "Server-Side > Server-Side Request Forgery (SSRF)",
    "server-side_request_forgery_(ssrf)": "Server-Side > Server-Side Request Forgery (SSRF)",
    "open_redirect": "Client-Side > Open Redirect",
    "csrf": "Client-Side > Cross-Site Request Forgery (CSRF)",
    "cross-site_request_forgery_(csrf)": "Client-Side > Cross-Site Request Forgery (CSRF)",
    "xxe": "Injection > XML External Entity Injection (XXE)",
    "xml_external_entity_injection_(xxe)": "Injection > XML External Entity Injection (XXE)",
    "idor": "Access Control > Insecure Direct Object Reference (IDOR)",
    "insecure_direct_object_reference_(idor)": "Access Control > Insecure Direct Object Reference (IDOR)",
    "bola": "Access Control > Broken Object Level Authorization (BOLA)",
    "broken_object_level_authorization_(bola)": "Access Control > Broken Object Level Authorization (BOLA)",
    "privilege_escalation": "Access Control > Privilege Escalation",
    "jwt_flaws": "Authentication > JSON Web Token (JWT) Vulnerabilities",
    "jwt_vulnerabilities": "Authentication > JSON Web Token (JWT) Vulnerabilities",
    "ssti": "Injection > Server-Side Template Injection (SSTI)",
    "server-side_template_injection_(ssti)": "Injection > Server-Side Template Injection (SSTI)",
    "file_upload": "File Upload > Unrestricted File Upload",
    "unrestricted_file_upload": "File Upload > Unrestricted File Upload",
    "race_condition": "Business Logic > Race Condition",
    "race_condition_(toctou)": "Business Logic > Race Condition",
    "cors": "Configuration > CORS Misconfiguration",
    "cors_misconfiguration": "Configuration > CORS Misconfiguration",
    "clickjacking": "Client-Side > Clickjacking",
    "dom_clobbering": "Client-Side > DOM Clobbering",
    "prototype_pollution": "Client-Side > Prototype Pollution",
    "insecure_postmessage_usage": "Client-Side > postMessage",
    "postmessage": "Client-Side > postMessage",
    "blind_xss": "Client-Side > Blind Cross-Site Scripting (XSS)",
    "ldap_injection": "Injection > LDAP Injection",
    "ldap": "Injection > LDAP Injection",
    "xpath_injection": "Injection > XPath Injection",
    "xpath": "Injection > XPath Injection",
    "exposed_admin_panel": "Infrastructure > Admin Panel Detection",
    "admin_panel": "Infrastructure > Admin Panel Detection",
    "weak_tls_configuration": "Infrastructure > Weak TLS",
    "weak_tls": "Infrastructure > Weak TLS",
    "price_or_quantity_manipulation": "Business Logic > Price Manipulation",
    "price_manipulation": "Business Logic > Price Manipulation",
    "ai_llm_security_vulnerability": "Business Logic > AI MLM Security",
    "http_request_smuggling": "Server-Side > HTTP Request Smuggling",
    "subdomain_takeover": "Configuration > Subdomain Takeover",
    "smart_contract_vulnerability": "Blockchain > Smart Contract Vulnerability",
    "os_command_injection": "Injection > OS Command Injection",
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