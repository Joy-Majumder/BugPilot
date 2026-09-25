import asyncio
import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
import httpx
from app.config import settings


class ReconModule:
    def __init__(self, http_client: httpx.AsyncClient):
        self.http_client = http_client
        self.tools_dir = settings.TOOLS_DIR

    async def run(self, target_url: str, scope_config: Dict = None) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(":")[0]

        results = {
            "target_domain": domain,
            "subdomains": [],
            "live_hosts": [],
            "tech_stack": {},
            "open_ports": [],
            "nuclei_findings": [],
        }

        subdomains = await self._run_subfinder(domain)
        results["subdomains"] = subdomains

        live_hosts = await self._run_httpx(subdomains)
        results["live_hosts"] = live_hosts

        for host in live_hosts[:10]:
            tech = await self._fingerprint_tech(host)
            if tech:
                results["tech_stack"][host] = tech

        nuclei_results = await self._run_nuclei(live_hosts[:20])
        results["nuclei_findings"] = nuclei_results

        return results

    async def _run_subfinder(self, domain: str) -> List[str]:
        subfinder_path = self.tools_dir / "subfinder"
        if not subfinder_path.exists():
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                str(subfinder_path), "-d", domain, "-silent", "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            subdomains = set()
            for line in stdout.decode().strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        host = data.get("host", "")
                        if host:
                            subdomains.add(host)
                    except Exception:
                        pass
            return sorted(subdomains)
        except Exception:
            return []

    async def _run_httpx(self, hosts: List[str]) -> List[Dict[str, Any]]:
        httpx_path = self.tools_dir / "httpx"
        if not httpx_path.exists():
            return []

        live = []
        for host in hosts:
            try:
                proc = await asyncio.create_subprocess_exec(
                    str(httpx_path), "-u", host, "-silent", "-json", "-title", "-tech-detect", "-status-code",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                for line in stdout.decode().strip().split("\n"):
                    if line:
                        try:
                            data = json.loads(line)
                            live.append(data)
                        except Exception:
                            pass
            except Exception:
                pass
        return live

    async def _fingerprint_tech(self, url: str) -> Dict[str, Any]:
        try:
            resp = await self.http_client.get(url, timeout=10, follow_redirects=True)
            tech = {}

            server = resp.headers.get("server", "")
            if server:
                tech["server"] = server

            powered_by = resp.headers.get("x-powered-by", "")
            if powered_by:
                tech["x-powered-by"] = powered_by

            body = resp.text.lower()
            tech["frameworks"] = self._detect_frameworks(body, resp.headers)
            tech["cms"] = self._detect_cms(body, resp.headers)
            tech["languages"] = self._detect_languages(resp.headers)

            return tech
        except Exception:
            return {}

    def _detect_frameworks(self, body: str, headers: Dict) -> List[str]:
        frameworks = []
        patterns = {
            "react": [r"react", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
            "vue": [r"vue\.js", r"vuejs", r"__VUE__"],
            "angular": [r"angular", r"ng-app", r"ng-controller"],
            "nextjs": [r"__NEXT_DATA__", r"_next/static"],
            "nuxt": [r"__NUXT__", r"_nuxt/"],
            "svelte": [r"svelte", r"__SVELTE__"],
            "django": [r"csrfmiddlewaretoken", r"django"],
            "rails": [r"rails", r"csrf-param"],
            "laravel": [r"laravel", r"LARAVEL_SESSION"],
            "express": [r"express", r"x-powered-by: express"],
            "spring": [r"spring", r"jsessionid"],
            "asp.net": [r"asp\.net", r"__VIEWSTATE", r"x-aspnet-version"],
        }
        for fw, patterns_list in patterns.items():
            if any(re.search(p, body, re.IGNORECASE) for p in patterns_list):
                frameworks.append(fw)
        return frameworks

    def _detect_cms(self, body: str, headers: Dict) -> List[str]:
        cms = []
        patterns = {
            "wordpress": [r"wp-content", r"wp-includes", r"wordpress"],
            "drupal": [r"drupal", r"sites/default/files"],
            "joomla": [r"joomla", r"com_content"],
            "magento": [r"magento", r"mage/"],
            "shopify": [r"shopify", r"shopify-digital-wallet"],
        }
        for c, patterns_list in patterns.items():
            if any(re.search(p, body, re.IGNORECASE) for p in patterns_list):
                cms.append(c)
        return cms

    def _detect_languages(self, headers: Dict) -> List[str]:
        languages = []
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()

        if "php" in server or "php" in powered_by:
            languages.append("php")
        if "python" in server or "python" in powered_by:
            languages.append("python")
        if "node" in server or "express" in powered_by:
            languages.append("nodejs")
        if "java" in server or "tomcat" in server or "jetty" in server:
            languages.append("java")
        if "go" in server or "golang" in server:
            languages.append("go")
        if "asp.net" in powered_by:
            languages.append("c#")

        return languages

    async def _run_nuclei(self, hosts: List[Dict]) -> List[Dict[str, Any]]:
        nuclei_path = self.tools_dir / "nuclei"
        templates_dir = settings.NUCLEI_TEMPLATES_DIR
        if not nuclei_path.exists() or not templates_dir.exists():
            return []

        findings = []
        urls = [h.get("url") or h.get("input") for h in hosts if h.get("url") or h.get("input")]

        for url in urls[:20]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    str(nuclei_path),
                    "-u", url,
                    "-t", str(templates_dir),
                    "-silent",
                    "-json",
                    "-severity", "critical,high,medium",
                    "-rate-limit", "10",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

                for line in stdout.decode().strip().split("\n"):
                    if line:
                        try:
                            data = json.loads(line)
                            findings.append(data)
                        except Exception:
                            pass
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
        return findings