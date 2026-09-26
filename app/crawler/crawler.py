import asyncio
import re
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import httpx
from playwright.async_api import async_playwright
from app.config import settings
from app.detectors.base import Endpoint


class Crawler:
    def __init__(self, http_client: httpx.AsyncClient, playwright_browser=None):
        self.http_client = http_client
        self.playwright_browser = playwright_browser
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []
        self.max_depth = 3
        self.max_pages = 100
        self.base_domain: str = ""
        self._external_hosts: Set[str] = set()

    async def crawl(self, start_url: str, auth_sessions: List[Dict] = None, scope_config: Dict = None) -> List[Endpoint]:
        self.visited.clear()
        self.endpoints = []
        self.base_domain = urlparse(start_url).netloc.split(":")[0]
        self._external_hosts.clear()

        if self.playwright_browser:
            await self._crawl_js(start_url, auth_sessions, scope_config)
            await self._crawl_js(start_url, auth_sessions, scope_config)
        else:
            await self._crawl_static(start_url, auth_sessions, scope_config)

        return self.endpoints

    async def _crawl_static(self, start_url: str, auth_sessions: List[Dict], scope_config: Dict):
        queue = [(start_url, 0, auth_sessions[0] if auth_sessions else None)]

        while queue and len(self.visited) < self.max_pages:
            url, depth, session = queue.pop(0)

            if depth > self.max_depth:
                continue

            normalized = self._normalize_url(url)
            if normalized in self.visited:
                continue

            if not self._in_scope(normalized, scope_config or {}):
                continue

            self.visited.add(normalized)

            endpoints = await self._fetch_and_parse(normalized, session)
            self.endpoints.extend(endpoints)

            for ep in endpoints:
                for link in self._extract_links(ep):
                    if link not in self.visited:
                        queue.append((link, depth + 1, session))

    async def _crawl_js(self, start_url: str, auth_sessions: List[Dict], scope_config: Dict):
        page = await self.playwright_browser.new_page()

        if auth_sessions:
            await self._apply_auth(page, auth_sessions[0])

        try:
            await page.goto(start_url, wait_until="domcontentloaded", timeout=settings.REQUEST_TIMEOUT * 1000)
        except Exception as e:
            print(f"[Crawler] Initial page load failed for {start_url}: {e}")
            try:
                await page.goto(start_url, timeout=settings.REQUEST_TIMEOUT * 1000)
            except Exception:
                await page.close()
                await self._crawl_static(start_url, auth_sessions, scope_config)
                return

        for wait_state in ["networkidle", "load"]:
            try:
                await page.wait_for_load_state(wait_state, timeout=10000)
            except Exception:
                pass

        await self._extract_from_page(page, start_url, auth_sessions[0] if auth_sessions else None)

        links = await page.evaluate("""
            () => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => links.add(a.href));
                document.querySelectorAll('form[action]').forEach(f => links.add(f.action));
                document.querySelectorAll('[data-href], [data-url], [onclick]').forEach(el => {
                    const val = el.getAttribute('data-href') || el.getAttribute('data-url') || el.onclick?.toString();
                    if (val) links.add(val);
                });
                return Array.from(links);
            }
        """)

        for link in links[:50]:
            normalized = self._normalize_url(link)
            if normalized not in self.visited and self._in_scope(normalized, scope_config or {}):
                self.visited.add(normalized)
                await self._crawl_single_js(page, normalized, auth_sessions[0] if auth_sessions else None)

    async def _crawl_single_js(self, page, url: str, session: Dict):
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=settings.REQUEST_TIMEOUT * 1000)
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            await self._extract_from_page(page, url, session)
        except Exception:
            pass

    async def _extract_from_page(self, page, url: str, session: Dict):
        content = await page.content()
        soup = BeautifulSoup(content, "html.parser")

        endpoint = await self._parse_page(url, soup, session, page)
        if endpoint:
            self.endpoints.append(endpoint)

    async def _parse_page(self, url: str, soup: BeautifulSoup, session: Dict, page=None) -> Optional[Endpoint]:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())

        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", url)
            method = form.get("method", "GET").upper()
            inputs = form.find_all(["input", "select", "textarea"])
            form_params = [inp.get("name") for inp in inputs if inp.get("name")]
            params.extend(form_params)

        tech_fingerprint = self._fingerprint_tech(soup)

        endpoint = Endpoint(
            url=url,
            method="GET",
            params=list(set(params)),
            tech_fingerprint=tech_fingerprint,
            depth=len(self.visited),
        )

        if session:
            endpoint.cookies = session.get("cookies", {})
            endpoint.headers = session.get("headers", {})
            endpoint.auth_required = True

        return endpoint

    async def _fetch_and_parse(self, url: str, session: Dict) -> List[Endpoint]:
        endpoints = []
        try:
            headers = session.get("headers", {}) if session else {}
            cookies = session.get("cookies", {}) if session else {}

            resp = await self.http_client.get(url, headers=headers, cookies=cookies, timeout=settings.REQUEST_TIMEOUT, follow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")

            endpoint = await self._parse_page(url, soup, session)
            if endpoint:
                endpoint.response_status = resp.status_code
                endpoint.response_headers = dict(resp.headers)
                endpoint.response_body = resp.text
                endpoints.append(endpoint)

        except Exception:
            pass
        return endpoints

    def _extract_links(self, endpoint: Endpoint) -> List[str]:
        links = []
        if not endpoint.response_body:
            return links

        soup = BeautifulSoup(endpoint.response_body, "html.parser")

        for a in soup.find_all("a", href=True):
            links.append(urljoin(endpoint.url, a["href"]))

        for form in soup.find_all("form", action=True):
            links.append(urljoin(endpoint.url, form["action"]))

        return links

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _in_scope(self, url: str, scope_config: Dict) -> bool:
        include = scope_config.get("include", [])
        exclude = scope_config.get("exclude", [])

        if exclude:
            if any(pattern.lower() in url.lower() for pattern in exclude):
                return False

        if include:
            if not any(pattern.lower() in url.lower() for pattern in include):
                return False

        if self.base_domain:
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0]
            target_root = ".".join(self.base_domain.split(".")[-2:])
            host_root = ".".join(host.split(".")[-2:])
            if host_root != target_root:
                return False

        return True

    def _fingerprint_tech(self, soup: BeautifulSoup) -> Dict[str, Any]:
        tech = {}
        html = str(soup)

        meta_gen = soup.find("meta", {"name": "generator"})
        if meta_gen:
            tech["generator"] = meta_gen.get("content", "")

        scripts = soup.find_all("script", src=True)
        tech["scripts"] = [s["src"] for s in scripts[:20]]

        return tech

    async def _apply_auth(self, page, session: Dict):
        cookies = session.get("cookies", {})
        if cookies:
            await page.context.add_cookies([
                {"name": k, "value": v, "domain": urlparse(page.url).netloc, "path": "/"}
                for k, v in cookies.items()
            ])