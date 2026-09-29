from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from abc import ABC, abstractmethod
import hashlib
import json
from app.config import settings


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    tech_fingerprint: Dict[str, Any] = field(default_factory=dict)
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    depth: int = 0

    def with_param(self, param: str, value: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(self.url)
        query = parse_qs(parsed.query)
        query[param] = [value]
        new_query = urlencode(query, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def get_param_value(self, param: str) -> Optional[str]:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.url)
        query = parse_qs(parsed.query)
        return query.get(param, [None])[0]


@dataclass
class Finding:
    vuln_class: str
    endpoint: str
    method: str
    param: Optional[str]
    confidence: str
    evidence: Dict[str, Any]
    cvss_vector: Optional[str] = None
    summary: str = ""
    description: str = ""
    steps_to_reproduce: str = ""
    impact: str = ""
    remediation: str = ""
    bugcrowd_vrt_category: Optional[str] = None

    @property
    def dedup_hash(self) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(self.endpoint)
        parts = parsed.netloc.split(":")[0].split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else parsed.netloc.split(":")[0]
        key = f"{self.vuln_class}|{root_domain}|{self.param or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:64]

    @property
    def severity(self) -> str:
        if not self.cvss_vector:
            return "info"
        try:
            from cvss import CVSS3
            cvss = CVSS3(self.cvss_vector)
            score = cvss.scores()[0]
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            elif score > 0.0:
                return "low"
            return "info"
        except Exception:
            return "info"

    @property
    def cvss_score(self) -> Optional[float]:
        if not self.cvss_vector:
            return None
        try:
            from cvss import CVSS3
            cvss = CVSS3(self.cvss_vector)
            return cvss.scores()[0]
        except Exception:
            return None


class Detector(ABC):
    name: str = ""
    vuln_class: str = ""
    cvss_vector_template: Optional[str] = None
    bugcrowd_vrt_category: Optional[str] = None

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        self.http_client = http_client
        self.oob_server = oob_server
        self.playwright_browser = playwright_browser

    @abstractmethod
    def applies_to(self, endpoint: Endpoint) -> bool:
        pass

    @abstractmethod
    async def run(self, endpoint: Endpoint) -> List[Finding]:
        pass

    def _make_finding(
        self,
        endpoint: Endpoint,
        param: Optional[str],
        confidence: str,
        evidence: Dict[str, Any],
        **kwargs
    ) -> Finding:
        cvss_vector = kwargs.pop("cvss_vector", self.cvss_vector_template)
        return Finding(
            vuln_class=self.vuln_class,
            endpoint=endpoint.url,
            method=endpoint.method,
            param=param,
            confidence=confidence,
            evidence=evidence,
            cvss_vector=cvss_vector,
            bugcrowd_vrt_category=self.bugcrowd_vrt_category,
            **kwargs
        )


class ValidationResult:
    def __init__(self, confirmed: bool, evidence: Dict[str, Any], notes: str = ""):
        self.confirmed = confirmed
        self.evidence = evidence
        self.notes = notes


class Validator:
    @staticmethod
    def diff_responses(control: Dict, test: Dict, ignore_headers: List[str] = None) -> Dict[str, Any]:
        ignore_headers = ignore_headers or ["date", "server", "set-cookie", "expires", "cache-control"]
        diff = {
            "status_changed": control.get("status") != test.get("status"),
            "body_length_diff": len(test.get("body", "")) - len(control.get("body", "")),
            "headers_changed": {},
            "body_snippet_diff": "",
        }

        control_headers = {k.lower(): v for k, v in control.get("headers", {}).items() if k.lower() not in ignore_headers}
        test_headers = {k.lower(): v for k, v in test.get("headers", {}).items() if k.lower() not in ignore_headers}

        all_keys = set(control_headers.keys()) | set(test_headers.keys())
        for k in all_keys:
            if control_headers.get(k) != test_headers.get(k):
                diff["headers_changed"][k] = {
                    "control": control_headers.get(k),
                    "test": test_headers.get(k)
                }

        return diff

    @staticmethod
    def timing_delta(control_time: float, test_time: float, threshold: float = 2.0) -> bool:
        return (test_time - control_time) >= threshold

    @staticmethod
    def boolean_based_sqli(control: Dict, true_payload: Dict, false_payload: Dict) -> ValidationResult:
        control_len = len(control.get("body", ""))
        true_len = len(true_payload.get("body", ""))
        false_len = len(false_payload.get("body", ""))

        diff_true = abs(true_len - control_len)
        diff_false = abs(false_len - control_len)

        if diff_true < diff_false * 0.5 and diff_false > control_len * 0.1:
            return ValidationResult(
                confirmed=True,
                evidence={
                    "control_length": control_len,
                    "true_length": true_len,
                    "false_length": false_len,
                    "diff_ratio": diff_false / max(diff_true, 1)
                },
                notes="Boolean-based SQLi detected: true payload similar to control, false payload significantly different"
            )
        return ValidationResult(confirmed=False, evidence={}, notes="No boolean differential detected")

    @staticmethod
    def timing_based_sqli(control_time: float, sleep_time: float, threshold: float = 2.0) -> ValidationResult:
        delta = sleep_time - control_time
        if delta >= threshold:
            return ValidationResult(
                confirmed=True,
                evidence={
                    "control_time": control_time,
                    "sleep_time": sleep_time,
                    "delta": delta
                },
                notes=f"Time-based SQLi detected: {delta:.2f}s delay"
            )
        return ValidationResult(confirmed=False, evidence={}, notes="No significant timing delta")

    @staticmethod
    async def xss_executed(page, marker: str) -> ValidationResult:
        try:
            fired = await page.evaluate(f"() => window.__xss_fired__ === '{marker}'")
            if fired:
                return ValidationResult(
                    confirmed=True,
                    evidence={"marker": marker, "executed": True},
                    notes="XSS payload executed in browser context"
                )
        except Exception as e:
            pass
        return ValidationResult(confirmed=False, evidence={}, notes="XSS not executed")

    @staticmethod
    def ssti_evaluated(response_body: str, expected: str) -> ValidationResult:
        if expected in response_body:
            return ValidationResult(
                confirmed=True,
                evidence={"expected": expected, "found_in_response": True},
                notes=f"SSTI confirmed: expression evaluated to '{expected}'"
            )
        return ValidationResult(confirmed=False, evidence={}, notes="SSTI not confirmed")

    @staticmethod
    async def oob_callback_received(oob_server, token: str, timeout: int = 10) -> ValidationResult:
        import asyncio
        start = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start < timeout:
            callback = oob_server.get_callback(token)
            if callback:
                return ValidationResult(
                    confirmed=True,
                    evidence={"callback": callback},
                    notes=f"OOB callback received: {callback.get('type', 'unknown')}"
                )
            await asyncio.sleep(0.5)
        return ValidationResult(confirmed=False, evidence={}, notes="No OOB callback received")