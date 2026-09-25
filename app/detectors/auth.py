import asyncio
import re
from typing import List, Optional, Dict, Any, Set
from app.detectors.base import Detector, Endpoint, Finding, Validator
from app.config import settings


class IDORDetector(Detector):
    name = "idor"
    vuln_class = "Insecure Direct Object Reference (IDOR)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
    bugcrowd_vrt_category = "Access Control > Insecure Direct Object Reference (IDOR)"

    ID_PATTERNS = [
        r"/users?/(\d+)",
        r"/accounts?/(\d+)",
        r"/profiles?/(\d+)",
        r"/orders?/(\d+)",
        r"/invoices?/(\d+)",
        r"/documents?/(\d+)",
        r"/files?/(\d+)",
        r"/tickets?/(\d+)",
        r"/messages?/(\d+)",
        r"/api/v\d+/users?/(\d+)",
        r"/api/v\d+/accounts?/(\d+)",
        r"id[=/](\d+)",
        r"user_id[=/](\d+)",
        r"account_id[=/](\d+)",
    ]

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self.auth_sessions = []

    def set_auth_sessions(self, sessions: List[Dict]):
        self.auth_sessions = sessions

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(self._extract_object_ids(endpoint.url))

    def _extract_object_ids(self, url: str) -> List[str]:
        ids = []
        for pattern in self.ID_PATTERNS:
            matches = re.findall(pattern, url, re.IGNORECASE)
            ids.extend(matches)
        return list(set(ids))

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        if len(self.auth_sessions) < 2:
            return findings

        object_ids = self._extract_object_ids(endpoint.url)
        if not object_ids:
            return findings

        for obj_id in object_ids:
            finding = await self._test_idor(endpoint, obj_id)
            if finding:
                findings.append(finding)

        return findings

    async def _test_idor(self, endpoint: Endpoint, obj_id: str) -> Optional[Finding]:
        session_a = self.auth_sessions[0]
        session_b = self.auth_sessions[1]

        url_with_id = endpoint.url
        resp_a = await self._fetch_with_session(url_with_id, session_a)
        resp_b = await self._fetch_with_session(url_with_id, session_b)

        if not resp_a or not resp_b:
            return None

        if resp_a["status"] == 200 and resp_b["status"] == 200:
            diff = Validator.diff_responses(
                {"body": resp_a["body"], "headers": resp_a["headers"]},
                {"body": resp_b["body"], "headers": resp_b["headers"]}
            )

            if diff["body_length_diff"] != 0 or diff["headers_changed"]:
                return self._make_finding(
                    endpoint=endpoint,
                    param="object_id",
                    confidence="confirmed",
                    evidence={
                        "object_id": obj_id,
                        "session_a_user": session_a.get("user_id", "user_a"),
                        "session_b_user": session_b.get("user_id", "user_b"),
                        "session_a_status": resp_a["status"],
                        "session_b_status": resp_b["status"],
                        "body_length_diff": diff["body_length_diff"],
                        "session_a_body_snippet": resp_a["body"][:200],
                        "session_b_body_snippet": resp_b["body"][:200],
                    },
                    summary=f"IDOR: User B can access User A's object (ID: {obj_id})",
                    description=(
                        f"The endpoint {endpoint.url} exposes object ID {obj_id} without proper "
                        f"authorization checks. Authenticated user B can access user A's data."
                    ),
                    steps_to_reproduce=(
                        f"1. Login as user A, access {url_with_id}\n"
                        f"2. Login as user B, access same URL\n"
                        f"3. Observe user B receives user A's data"
                    ),
                    impact="Horizontal privilege escalation: users can access other users' data.",
                    remediation="Implement proper authorization checks. Verify the requesting user owns the requested object. Use UUIDs instead of sequential IDs.",
                )

        return None

    async def _fetch_with_session(self, url: str, session: Dict) -> Optional[Dict[str, Any]]:
        try:
            headers = session.get("headers", {}).copy()
            cookies = session.get("cookies", {})

            resp = await self.http_client.get(
                url,
                headers=headers,
                cookies=cookies,
                timeout=settings.REQUEST_TIMEOUT,
            )
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class BOLADetector(Detector):
    name = "bola"
    vuln_class = "Broken Object Level Authorization (BOLA)"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    bugcrowd_vrt_category = "Access Control > Broken Object Level Authorization (BOLA)"

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self.auth_sessions = []

    def set_auth_sessions(self, sessions: List[Dict]):
        self.auth_sessions = sessions

    def applies_to(self, endpoint: Endpoint) -> bool:
        return "/api/" in endpoint.url and endpoint.method in ("GET", "POST", "PUT", "PATCH", "DELETE")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        if len(self.auth_sessions) < 2:
            return findings

        finding = await self._test_bola(endpoint)
        if finding:
            findings.append(finding)

        return findings

    async def _test_bola(self, endpoint: Endpoint) -> Optional[Finding]:
        session_a = self.auth_sessions[0]
        session_b = self.auth_sessions[1]

        test_url = endpoint.url
        if endpoint.method == "GET":
            resp_a = await self._fetch_with_session(test_url, session_a)
            resp_b = await self._fetch_with_session(test_url, session_b)
        else:
            data = {p: endpoint.get_param_value(p) or "test" for p in endpoint.params}
            resp_a = await self._post_with_session(test_url, data, session_a)
            resp_b = await self._post_with_session(test_url, data, session_b)

        if not resp_a or not resp_b:
            return None

        if resp_a["status"] == 200 and resp_b["status"] == 200:
            if len(resp_a["body"]) != len(resp_b["body"]):
                return self._make_finding(
                    endpoint=endpoint,
                    param="api_object",
                    confidence="confirmed",
                    evidence={
                        "endpoint": test_url,
                        "method": endpoint.method,
                        "session_a_user": session_a.get("user_id", "user_a"),
                        "session_b_user": session_b.get("user_id", "user_b"),
                        "session_a_status": resp_a["status"],
                        "session_b_status": resp_b["status"],
                        "body_length_diff": len(resp_b["body"]) - len(resp_a["body"]),
                        "session_a_body_snippet": resp_a["body"][:300],
                        "session_b_body_snippet": resp_b["body"][:300],
                    },
                    summary=f"BOLA: API endpoint {endpoint.method} {test_url} lacks object-level authorization",
                    description=(
                        f"The API endpoint {endpoint.method} {test_url} returns different data "
                        f"for different users without verifying object ownership. This is the #1 "
                        f"API security risk per OWASP API Top 10."
                    ),
                    steps_to_reproduce=(
                        f"1. Call API as user A: {endpoint.method} {test_url}\n"
                        f"2. Call same API as user B\n"
                        f"3. Compare responses - different data indicates BOLA"
                    ),
                    impact="Attackers can access, modify, or delete other users' data via API.",
                    remediation="Implement object-level authorization checks in every API endpoint. Verify user owns/has access to the requested object ID.",
                )

        return None

    async def _fetch_with_session(self, url: str, session: Dict) -> Optional[Dict[str, Any]]:
        try:
            headers = session.get("headers", {}).copy()
            cookies = session.get("cookies", {})

            resp = await self.http_client.get(url, headers=headers, cookies=cookies, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None

    async def _post_with_session(self, url: str, data: Dict, session: Dict) -> Optional[Dict[str, Any]]:
        try:
            headers = session.get("headers", {}).copy()
            cookies = session.get("cookies", {})

            resp = await self.http_client.post(url, json=data, headers=headers, cookies=cookies, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class PrivilegeEscalationDetector(Detector):
    name = "privilege_escalation"
    vuln_class = "Privilege Escalation"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Access Control > Privilege Escalation"

    ADMIN_PATHS = [
        "/admin", "/administrator", "/manage", "/management",
        "/dashboard", "/console", "/control-panel",
        "/api/admin", "/api/v1/admin", "/api/internal",
        "/api/management", "/api/v1/users", "/api/v1/roles",
    ]

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self.auth_sessions = []

    def set_auth_sessions(self, sessions: List[Dict]):
        self.auth_sessions = sessions

    def applies_to(self, endpoint: Endpoint) -> bool:
        return True

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        if len(self.auth_sessions) < 2:
            return findings

        low_priv = self.auth_sessions[0]
        for admin_path in self.ADMIN_PATHS:
            test_url = endpoint.url.rstrip("/") + admin_path
            finding = await self._test_admin_access(test_url, low_priv)
            if finding:
                findings.append(finding)

        return findings

    async def _test_admin_access(self, url: str, session: Dict) -> Optional[Finding]:
        resp = await self._fetch_with_session(url, session)
        if not resp:
            return None

        if resp["status"] == 200:
            admin_indicators = [
                "admin", "administrator", "dashboard", "management",
                "user management", "role management", "system config",
            ]
            body_lower = resp["body"].lower()
            if any(ind in body_lower for ind in admin_indicators):
                return self._make_finding(
                    endpoint=Endpoint(url=url, method="GET"),
                    param=None,
                    confidence="confirmed",
                    evidence={
                        "url": url,
                        "response_status": resp["status"],
                        "response_body_snippet": resp["body"][:500],
                        "session_user": session.get("user_id", "low_priv_user"),
                    },
                    summary=f"Privilege Escalation: Low-priv user accesses admin panel at {url}",
                    description=(
                        f"A low-privileged user can access administrative functionality at {url}. "
                        f"The response contains admin-panel indicators without proper authorization checks."
                    ),
                    steps_to_reproduce=(f"1. Login as low-priv user\n2. Navigate to {url}\n3. Observe admin functionality accessible"),
                    impact="Vertical privilege escalation: regular users gain administrative access.",
                    remediation="Implement role-based access control (RBAC). Check user roles/permissions on every admin endpoint. Use middleware for authorization.",
                )
        return None

    async def _fetch_with_session(self, url: str, session: Dict) -> Optional[Dict[str, Any]]:
        try:
            headers = session.get("headers", {}).copy()
            cookies = session.get("cookies", {})

            resp = await self.http_client.get(url, headers=headers, cookies=cookies, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text}
        except Exception:
            return None


class JWTDetector(Detector):
    name = "jwt_flaws"
    vuln_class = "JWT Vulnerabilities"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Authentication > JSON Web Token (JWT) Vulnerabilities"

    def applies_to(self, endpoint: Endpoint) -> bool:
        return True

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        for param in endpoint.params:
            value = endpoint.get_param_value(param) or ""
            if self._is_jwt(value):
                finding = await self._analyze_jwt(endpoint, param, value)
                if finding:
                    findings.append(finding)

        for header_name in ["authorization", "cookie"]:
            if header_name in endpoint.headers:
                value = endpoint.headers[header_name]
                if "bearer" in value.lower():
                    token = value.split()[-1]
                    if self._is_jwt(token):
                        finding = await self._analyze_jwt(endpoint, header_name, token)
                        if finding:
                            findings.append(finding)

        return findings

    def _is_jwt(self, token: str) -> bool:
        parts = token.split(".")
        return len(parts) == 3 and all(part for part in parts)

    async def _analyze_jwt(self, endpoint: Endpoint, source: str, token: str) -> Optional[Finding]:
        import base64
        import json

        try:
            parts = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
        except Exception:
            return None

        issues = []

        if header.get("alg") == "none":
            issues.append("Algorithm 'none' accepted")

        if header.get("alg") in ("HS256", "HS384", "HS512"):
            issues.append("HMAC algorithm - test for weak secret")

        if "kid" in header:
            kid = header["kid"]
            if any(c in kid for c in ["'", '"', ";", "../", "..\\"]):
                issues.append(f"KID header injection possible: {kid}")

        if "exp" not in payload:
            issues.append("No expiration claim (exp)")

        if issues:
            return self._make_finding(
                endpoint=endpoint,
                param=source,
                confidence="suspected" if "weak secret" in " ".join(issues) else "confirmed",
                evidence={
                    "token_source": source,
                    "header": header,
                    "payload": payload,
                    "issues": issues,
                    "token": token[:50] + "...",
                },
                summary=f"JWT Vulnerabilities in {source}: {', '.join(issues)}",
                description=(
                    f"The JWT in {source} has the following issues: {', '.join(issues)}. "
                    f"These can lead to token forgery, privilege escalation, or authentication bypass."
                ),
                steps_to_reproduce=(
                    f"1. Extract JWT from {source}\n"
                    f"2. Decode header: {json.dumps(header)}\n"
                    f"3. Decode payload: {json.dumps(payload)}\n"
                    f"4. Test identified issues"
                ),
                impact="JWT flaws can lead to authentication bypass, privilege escalation, or token forgery.",
                remediation="Use RS256/ES256. Validate alg header. Verify signature. Use short exp. Validate kid against allowlist. Rotate keys.",
            )
        return None