import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from concurrent.futures import TimeoutError as FuturesTimeoutError
from urllib.parse import urlparse, urljoin

from app.database import get_db_session
from app.models import ScanSession, ScanStatus, CrawlData, AuthSession
from app.recon.recon import ReconModule
from app.crawler.crawler import Crawler
from app.detectors import get_all_detectors
from app.detectors.base import Endpoint
from app.validation.store import FindingStore
from app.scoring.cvss import CVSSScorer
from app.oob_server import get_oob_server
from app.config import settings
import httpx
from playwright.async_api import async_playwright


COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
    "/api/v6", "/api/v7", "/api/v8", "/api/json", "/api/rest",
    "/rest", "/rest/v1", "/rest/v2", "/graphql", "/graphql/graphql",
    "/gql", "/wp-json", "/wp-json/wp/v2", "/admin", "/admin/api",
    "/admin/api/v1", "/api/admin", "/api/users", "/api/auth",
    "/api/login", "/api/search", "/api/data", "/api/config",
    "/api/status", "/api/health", "/api/version", "/api/docs",
    "/api/swagger", "/api/openapi", "/api/swagger.json",
    "/api/swaggerui", "/api/redoc", "/api/v1/api", "/v1", "/v2",
    "/v3", "/internal", "/internal/api", "/debug", "/debug/vars",
    "/metrics", "/prometheus", "/api/metrics", "/api/config.json",
    "/api/settings", "/api/info", "/api/me", "/api/profile",
    "/api/account", "/api/orders", "/api/products", "/api/cart",
    "/api/checkout", "/api/payment", "/api/webhook", "/api/callback",
]

BLACKLISTED_HOSTS = {"youtube.com", "youtu.be", "linkedin.com", "linkedin.com", 
                      "facebook.com", "twitter.com", "instagram.com", "tiktok.com",
                      "linkedin.com", "google.com", "google.co.uk", "bing.com",
                      "googleapis.com", "gstatic.com", "cloudflare.com", "akamai.net"}


class ScanPipeline:
    def __init__(self, scan_session_id: int):
        self.scan_session_id = scan_session_id
        self.db = get_db_session()
        self.oob_server = get_oob_server()
        self.playwright_browser = None
        self.http_client = None
        self.findings_store = FindingStore(self.db)
        self.scan_session = None
        self.tool_status = {}
        self.recon_results: Dict[str, Any] = {}
        self._playwright = None

    async def initialize(self):
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.REQUEST_TIMEOUT),
            follow_redirects=True,
            verify=False,
        )

        self._playwright = await async_playwright().start()
        self.playwright_browser = await self._playwright.chromium.launch(headless=True)

        await self.oob_server.start()

        self.scan_session = self.db.query(ScanSession).filter(ScanSession.id == self.scan_session_id).first()
        if self.scan_session:
            self.scan_session.status = ScanStatus.RUNNING
            self.scan_session.started_at = datetime.utcnow()
            self.db.commit()

    async def cleanup(self):
        if self.http_client:
            await self.http_client.aclose()
        if self.playwright_browser:
            try:
                await self.playwright_browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
        await self.oob_server.stop()
        self.db.close()

    async def run(self, progress_callback=None):
        try:
            await self._update_progress("Initializing scan...", 0)

            target_url = self.scan_session.target_url
            config = self.scan_session.config or {}
            scope_config = config.get("scope", {})
            selected_detectors = config.get("detectors", [])
            auth_sessions = self._load_auth_sessions()

            await self._update_progress("Running reconnaissance...", 10)
            recon_results = {"errors": [], "tool_status": {}, "live_hosts": []}
            try:
                recon_results = await asyncio.wait_for(
                    self._run_recon(target_url, scope_config),
                    timeout=45,
                )
                self.recon_results = recon_results
                self.tool_status = recon_results.get("tool_status", {})
                self.scan_session.config = {**(self.scan_session.config or {}), "tool_status": self.tool_status, "recon_errors": recon_results.get("errors", [])}
                self.db.commit()
            except asyncio.TimeoutError:
                self.scan_session.config = {**(self.scan_session.config or {}), "recon_errors": ["Reconnaissance timed out (45s)"]}
                self.db.commit()

            await self._update_progress("Discovering subdomains and API endpoints...", 25)
            host_urls = self._collect_host_urls(target_url, recon_results)

            await self._update_progress("Crawling application...", 30)
            try:
                endpoints = await asyncio.wait_for(
                    self._run_crawl(target_url, auth_sessions, scope_config, host_urls),
                    timeout=90,
                )
            except asyncio.TimeoutError:
                await self._update_progress("Crawl timed out, using target URL as fallback endpoint", 50)
                endpoints = [Endpoint(url=target_url, method="GET", params=[])]

            await self._update_progress("Running detectors...", 50)
            findings = await asyncio.wait_for(
                self._run_detectors(endpoints, auth_sessions, selected_detectors),
                timeout=300,
            )

            await self._update_progress("Finalizing...", 90)
            await self._finalize(findings)

            await self._update_progress("Scan completed", 100)

            self.scan_session.status = ScanStatus.COMPLETED
            self.scan_session.completed_at = datetime.utcnow()
            self.db.commit()

        except asyncio.TimeoutError:
            self.scan_session.status = ScanStatus.COMPLETED
            self.scan_session.completed_at = datetime.utcnow()
            self.db.commit()
        except Exception as e:
            if self.scan_session:
                self.scan_session.status = ScanStatus.FAILED
                self.scan_session.error_message = str(e)
                self.scan_session.completed_at = datetime.utcnow()
                self.db.commit()
            raise

    async def _update_progress(self, message: str, percent: int):
        if self.scan_session:
            self.scan_session.config = {**(self.scan_session.config or {}), "progress_message": message, "progress_percent": percent}
            self.db.commit()

    def _load_auth_sessions(self) -> List[Dict]:
        sessions = self.db.query(AuthSession).filter(AuthSession.scan_session_id == self.scan_session_id).all()
        return [
            {
                "user_id": s.name,
                "cookies": s.cookies,
                "headers": s.headers,
                "tokens": s.tokens,
            }
            for s in sessions
        ]

    async def _run_recon(self, target_url: str, scope_config: Dict) -> Dict:
        recon = ReconModule(self.http_client)
        return await recon.run(target_url, scope_config)

    def _collect_host_urls(self, target_url: str, recon_results: Dict) -> List[str]:
        parsed = urlparse(target_url)
        target_domain = parsed.netloc.split(":")[0]
        target_scheme = parsed.scheme or "https"
        
        host_urls: List[str] = [target_url]
        visited_hosts: Set[str] = {f"{target_scheme}://{target_domain}"}

        for host in recon_results.get("live_hosts", []):
            if isinstance(host, dict):
                host_url = host.get("url") or host.get("input", "")
            else:
                host_url = host
            if not host_url:
                continue
            if not host_url.startswith(("http://", "https://")):
                host_url = f"{target_scheme}://{host_url}"
            host_domain = urlparse(host_url).netloc.split(":")[0]
            if host_domain in BLACKLISTED_HOSTS or self._is_external_domain(host_domain, target_domain):
                continue
            if host_url in visited_hosts:
                continue
            visited_hosts.add(host_url)
            host_urls.append(host_url)

        return host_urls

    @staticmethod
    def _is_external_domain(host_domain: str, target_domain: str) -> bool:
        target_root = ".".join(target_domain.split(".")[-2:])
        host_root = ".".join(host_domain.split(".")[-2:])
        return target_root != host_root

    async def _run_crawl(self, target_url: str, auth_sessions: List[Dict], scope_config: Dict, host_urls: List[str] = None) -> List:
        if host_urls is None:
            host_urls = [target_url]

        crawler = Crawler(self.http_client, self.playwright_browser)
        all_endpoints: List[Endpoint] = []
        seen_urls: Set[str] = set()

        for host_url in host_urls:
            try:
                endpoints = await asyncio.wait_for(
                    crawler.crawl(host_url, auth_sessions, scope_config),
                    timeout=90,
                )
            except (asyncio.TimeoutError, Exception):
                endpoints = []

            for ep in endpoints:
                if ep.url not in seen_urls:
                    seen_urls.add(ep.url)
                    all_endpoints.append(ep)

            api_endpoints = await self._discover_api_paths(host_url)
            for api_url in api_endpoints:
                if api_url not in seen_urls:
                    seen_urls.add(api_url)
                    all_endpoints.append(Endpoint(url=api_url, method="GET", params=[]))

        for ep in all_endpoints:
            crawl_data = CrawlData(
                scan_session_id=self.scan_session_id,
                url=ep.url,
                method=ep.method,
                params=ep.params,
                headers=ep.headers,
                tech_fingerprint=ep.tech_fingerprint,
                auth_required=1 if ep.auth_required else 0,
                depth=ep.depth,
            )
            self.db.add(crawl_data)
        self.db.commit()

        return all_endpoints

    async def _discover_api_paths(self, base_url: str) -> List[str]:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        api_urls: List[str] = []

        for path in COMMON_API_PATHS:
            url = base + path
            try:
                resp = await self.http_client.get(url, timeout=10, follow_redirects=True)
                if resp.status_code < 400:
                    api_urls.append(url)
            except Exception:
                pass

        return api_urls

    async def _run_detectors(self, endpoints: List, auth_sessions: List[Dict], selected_detectors: List[str]) -> List:
        all_detectors = get_all_detectors(self.http_client, self.oob_server, self.playwright_browser)

        if selected_detectors:
            all_detectors = [d for d in all_detectors if d.name in selected_detectors]

        for detector in all_detectors:
            if hasattr(detector, "set_auth_sessions"):
                detector.set_auth_sessions(auth_sessions)

        all_findings = []
        concurrency = self.scan_session.config.get("concurrency", 5) if self.scan_session and self.scan_session.config else 5
        semaphore = asyncio.Semaphore(max(concurrency, 5))

        # Run detectors concurrently across endpoints, limited by semaphore
        async def run_detector_on_endpoint(detector, endpoint):
            if not detector.applies_to(endpoint):
                return []
            async with semaphore:
                try:
                    return await asyncio.wait_for(detector.run(endpoint), timeout=20)
                except (asyncio.TimeoutError, Exception):
                    return []

        tasks = []
        for endpoint in endpoints:
            for detector in all_detectors:
                tasks.append(run_detector_on_endpoint(detector, endpoint))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception) or not result:
                continue
            for finding in result:
                try:
                    cvss_result = CVSSScorer.score(finding.vuln_class, finding.cvss_vector)
                    finding.cvss_vector = cvss_result["vector"]
                    model = self.findings_store.save(finding, self.scan_session_id)
                    all_findings.append(model)
                except Exception:
                    pass

        return all_findings

    async def _finalize(self, findings: List):
        from app.reporting import generate_report

        target_url = self.scan_session.target_url if self.scan_session else None
        seen_ids = set()
        unique_findings = []
        for f in findings:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                unique_findings.append(f)

        report_paths = []
        for finding in unique_findings:
            try:
                path = generate_report(finding, "hackerone", target_url)
                report_paths.append(path)
            except Exception:
                pass

        if report_paths:
            print(f"[BugHunter] Auto-generated {len(report_paths)} report(s)")
            for p in report_paths:
                print(f"  - {p}")
