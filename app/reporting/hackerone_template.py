HACKERONE_TEMPLATE = """# [{severity}] {vuln_class} in {endpoint}

## Summary
{summary}

## Severity
{severity} (CVSS 3.1: {cvss_score} — {cvss_vector})

## Description
{description}

## Steps To Reproduce
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

## Impact
{impact}

## Supporting Material / References
{oob_section}
- CWE: {cwe_link}

## Suggested Remediation
{remediation}
"""

HACKERONE_TEMPLATE_MINIMAL = """# [{severity}] {vuln_class} in {endpoint}

## Summary
{summary}

## Severity
{severity} (CVSS 3.1: {cvss_score} — {cvss_vector})

## Proof of Concept
{request}

## Impact
{impact}

## Remediation
{remediation}
"""


def render_hackerone(finding: dict) -> str:
    screenshot_section = ""
    if finding.get("evidence", {}).get("screenshot"):
        screenshot_section = f"\n### Screenshot\n![PoC Screenshot]({finding['evidence']['screenshot']})\n"

    oob_section = ""
    if finding.get("evidence", {}).get("callback"):
        cb = finding["evidence"]["callback"]
        oob_section = f"- OOB Callback: {cb.get('type', 'unknown')} at {cb.get('timestamp', 'unknown')} from {cb.get('data', {}).get('remote', 'unknown')}\n"

    request_str = finding.get("evidence", {}).get("request_url", "")
    if finding.get("evidence", {}).get("payload"):
        request_str += f"\n\nPayload: {finding['evidence']['payload']}"

    response_str = finding.get("evidence", {}).get("response_body_snippet", "")
    if finding.get("evidence", {}).get("response_body"):
        response_str = finding["evidence"]["response_body"][:2000]

    cwe_map = {
        "reflected_xss": "CWE-79",
        "stored_xss": "CWE-79",
        "dom_xss": "CWE-79",
        "sqli": "CWE-89",
        "sql_injection": "CWE-89",
        "nosqli": "CWE-943",
        "nosql_injection": "CWE-943",
        "command_injection": "CWE-78",
        "os_command_injection": "CWE-78",
        "ssrf": "CWE-918",
        "server-side_request_forgery_(ssrf)": "CWE-918",
        "open_redirect": "CWE-601",
        "csrf": "CWE-352",
        "cross-site_request_forgery_(csrf)": "CWE-352",
        "xxe": "CWE-611",
        "xml_external_entity_injection_(xxe)": "CWE-611",
        "idor": "CWE-639",
        "insecure_direct_object_reference_(idor)": "CWE-639",
        "bola": "CWE-639",
        "broken_object_level_authorization_(bola)": "CWE-639",
        "privilege_escalation": "CWE-269",
        "jwt_flaws": "CWE-345",
        "jwt_vulnerabilities": "CWE-345",
        "ssti": "CWE-1336",
        "server-side_template_injection_(ssti)": "CWE-1336",
        "file_upload": "CWE-434",
        "unrestricted_file_upload": "CWE-434",
        "race_condition": "CWE-362",
        "race_condition_(toctou)": "CWE-362",
        "cors": "CWE-942",
        "cors_misconfiguration": "CWE-942",
        "clickjacking": "CWE-1021",
        "dom_clobbering": "CWE-1233",
        "prototype_pollution": "CWE-1300",
        "insecure_postmessage_usage": "CWE-269",
        "postmessage": "CWE-269",
        "blind_xss": "CWE-79",
        "ldap_injection": "CWE-90",
        "ldap": "CWE-90",
        "xpath_injection": "CWE-90",
        "xpath": "CWE-90",
        "exposed_admin_panel": "CWE-284",
        "admin_panel": "CWE-284",
        "weak_tls_configuration": "CWE-326",
        "weak_tls": "CWE-326",
        "price_or_quantity_manipulation": "CWE-841",
        "price_manipulation": "CWE-841",
        "ai_llm_security_vulnerability": "CWE-20",
        "http_request_smuggling": "CWE-77",
        "subdomain_takeover": "CWE-346",
        "smart_contract_vulnerability": "CWE-1023",
    }

    return HACKERONE_TEMPLATE.format(
        severity=finding.get("severity_label", "Medium"),
        vuln_class=finding.get("vuln_class", "Unknown"),
        endpoint=finding.get("endpoint", ""),
        cvss_score=finding.get("cvss_score", 0.0),
        cvss_vector=finding.get("cvss_vector", ""),
        summary=finding.get("summary", ""),
        description=finding.get("description", ""),
        steps_to_reproduce=finding.get("steps_to_reproduce", ""),
        request=request_str,
        response=response_str,
        screenshot_section=screenshot_section,
        impact=finding.get("impact", ""),
        oob_section=oob_section,
        cwe_link=cwe_map.get(finding.get("vuln_class", "").lower().replace(" ", "_"), "CWE-200"),
        remediation=finding.get("remediation", ""),
    )