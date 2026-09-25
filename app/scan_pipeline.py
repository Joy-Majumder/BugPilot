import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.database import get_db_session
from app.models import ScanSession, ScanStatus, CrawlData, AuthSession
from app.recon.recon import ReconModule
from app.crawler.crawler import Crawler
from app.detectors import get_all_detectors
from app.validation.store import FindingStore
from app.scoring.cvss import CVSSScorer
from app.oob_server import get_oob_server
from app.config import settings
import httpx
from playwright.async_api import async_playwright


class ScanPipeline:
    def __init__(self, scan_session_id: int):
        self.scan_session_id = scan_session_id
        self.db = get_db_session()
        self.oob_server = get_oob_server()
        self.playwright_browser = None
        self.http_client = None
        self.findings_store = FindingStore(self.db)
        self.scan_session = None

    async def initialize(self):
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.REQUEST_TIMEOUT),
            follow_redirects=True,
            verify=False,
        )

        playwright = await async_playwright().start()
        self.playwright_browser = await playwright.chromium.launch(headless=True)

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
            await self.playwright_browser.close()
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
            recon_results = await self._run_recon(target_url, scope_config)

            await self._update_progress("Crawling application...", 30)
            endpoints = await self._run_crawl(target_url, auth_sessions, scope_config)

            await self._update_progress("Running detectors...", 50)
            findings = await self._run_detectors(endpoints, auth_sessions, selected_detectors)

            await self._update_progress("Finalizing...", 90)
            await self._finalize(findings)

            await self._update_progress("Scan completed", 100)

            self.scan_session.status = ScanStatus.COMPLETED
            self.scan_session.completed_at = datetime.utcnow()
            self.db.commit()

        except Exception as e:
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

    async def _run_crawl(self, target_url: str, auth_sessions: List[Dict], scope_config: Dict) -> List:
        crawler = Crawler(self.http_client, self.playwright_browser)
        endpoints = await crawler.crawl(target_url, auth_sessions, scope_config)

        for ep in endpoints:
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

        return endpoints

    async def _run_detectors(self, endpoints: List, auth_sessions: List[Dict], selected_detectors: List[str]) -> List:
        all_detectors = get_all_detectors(self.http_client, self.oob_server, self.playwright_browser)

        if selected_detectors:
            all_detectors = [d for d in all_detectors if d.name in selected_detectors]

        for detector in all_detectors:
            if hasattr(detector, "set_auth_sessions"):
                detector.set_auth_sessions(auth_sessions)

        all_findings = []

        for endpoint in endpoints:
            for detector in all_detectors:
                if detector.applies_to(endpoint):
                    try:
                        findings = await detector.run(endpoint)
                        for finding in findings:
                            cvss_result = CVSSScorer.score(finding.vuln_class, finding.cvss_vector)
                            finding.cvss_vector = cvss_result["vector"]

                            model = self.findings_store.save(finding, self.scan_session_id)
                            all_findings.append(model)
                    except Exception:
                        pass

        return all_findings

    async def _finalize(self, findings: List):
        pass