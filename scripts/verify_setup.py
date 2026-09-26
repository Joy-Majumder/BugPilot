#!/usr/bin/env python3
"""
BugHunter Installation Verification Script
Verifies all dependencies, tools, and configuration are properly set up.
"""
import sys
import os
import subprocess
from pathlib import Path

# Add project root to path
PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(PROJECT_DIR))


def check_python_version():
    """Verify Python version is 3.10+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        return False, f"Python {version.major}.{version.minor} detected. Python 3.10+ required."
    return True, f"Python {version.major}.{version.minor}.{version.micro} OK"


def check_package_import(name, import_name=None):
    """Check if a Python package is importable"""
    import_name = import_name or name
    try:
        __import__(import_name)
        mod = sys.modules[import_name]
        version = getattr(mod, "__version__", "unknown")
        return True, f"{name} {version} OK"
    except ImportError as e:
        return False, f"{name} NOT FOUND: {e}"


def check_required_packages():
    """Check all required Python packages"""
    packages = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("jinja2", "jinja2"),
        ("playwright", "playwright"),
        ("httpx", "httpx"),
        ("sqlalchemy", "sqlalchemy"),
        ("cvss", "cvss"),
        ("pydantic", "pydantic"),
        ("pydantic-settings", "pydantic_settings"),
        ("aiohttp", "aiohttp"),
        ("dnspython", "dns"),
        ("beautifulsoup4", "bs4"),
        ("lxml", "lxml"),
        ("tldextract", "tldextract"),
        ("rich", "rich"),
    ]

    results = []
    all_ok = True
    for name, import_name in packages:
        ok, msg = check_package_import(name, import_name)
        results.append((ok, msg))
        if not ok:
            all_ok = False

    return all_ok, results


def check_external_tools():
    """Check if external tools are available"""
    from app.config import settings

    tools = ["subfinder", "httpx", "nuclei"]
    results = []
    all_found = True

    for tool in tools:
        tool_path = settings.TOOLS_DIR / tool
        if tool_path.exists():
            try:
                result = subprocess.run(
                    [str(tool_path), "-version"],
                    capture_output=True, text=True, timeout=5
                )
                version = (result.stdout or result.stderr).strip()
                results.append((True, f"{tool} available. Version: {version}"))
            except Exception as e:
                results.append((True, f"{tool} found at {tool_path}, but version check failed: {e}"))
        else:
            results.append((False, f"{tool} NOT FOUND at {tool_path}"))
            all_found = False

    return all_found, results


def check_directories():
    """Check that required directories exist"""
    from app.config import settings

    dirs = [
        ("PROJECT_DIR", settings.PROJECT_DIR),
        ("TOOLS_DIR", settings.TOOLS_DIR),
        ("DATA_DIR", settings.DATA_DIR),
        ("REPORTS_DIR", settings.REPORTS_DIR),
        ("NUCLEI_TEMPLATES_DIR", settings.NUCLEI_TEMPLATES_DIR),
        ("PLAYWRIGHT_BROWSERS_PATH", settings.PLAYWRIGHT_BROWSERS_PATH),
    ]

    results = []
    all_ok = True
    for name, path in dirs:
        if path.exists():
            results.append((True, f"{name}: {path} OK"))
        else:
            results.append((False, f"{name}: {path} MISSING"))
            all_ok = False

    return all_ok, results


def check_database():
    """Check database can be initialized"""
    try:
        from app.database import init_db, get_db_session, SessionLocal
        init_db()
        db = SessionLocal()
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db.close()
        return True, "Database (SQLite) OK"
    except Exception as e:
        return False, f"Database error: {e}"


def check_detectors():
    """Check all detectors can be imported and instantiated"""
    try:
        from app.detectors import get_all_detectors
        from app.config import settings
        import httpx

        http_client = httpx.AsyncClient()
        detectors = get_all_detectors(http_client)

        names = [d.name for d in detectors]
        expected = [
            "reflected_xss", "stored_xss", "dom_xss", "blind_xss",
            "sqli", "nosqli", "command_injection", "ldap", "xpath",
            "ssrf", "open_redirect", "csrf", "http_request_smuggling", "xxe",
            "idor", "bola", "privilege_escalation", "jwt_flaws",
            "ssti", "file_upload", "race_condition", "price_manipulation", "cors", "subdomain_takeover",
            "clickjacking", "dom_clobbering", "prototype_pollution", "postmessage",
            "admin_panel", "weak_tls", "ai_llm_security",
            "smart_contract",
        ]

        missing = set(expected) - set(names)
        extra = set(names) - set(expected)

        if missing:
            return False, f"Missing detectors: {missing}"
        if extra:
            return True, f"All {len(names)} detectors OK (extra: {extra})"
        return True, f"All {len(names)} detectors OK"
    except Exception as e:
        return False, f"Detector import error: {e}"


def check_playwright_browsers():
    """Check if Playwright browsers are installed"""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True, "Playwright Chromium browser OK"
    except Exception as e:
        return False, f"Playwright browser not installed: {e}. Run: playwright install --with-deps"


def check_server():
    """Check if the FastAPI server can be imported"""
    try:
        from app.server import app
        return True, "FastAPI server module OK"
    except Exception as e:
        return False, f"Server module error: {e}"


def check_cvss():
    """Verify CVSS module works"""
    try:
        from cvss import CVSS3
        cvss = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        scores = cvss.scores()
        if scores and len(scores) > 0:
            return True, f"CVSS3 module OK (score: {scores[0]})"
        return False, "CVSS3 returned no scores"
    except Exception as e:
        return False, f"CVSS module error: {e}"


def check_cors_detector():
    """Quick check that CORS scanner works correctly"""
    try:
        from app.detectors.other import CORSScanner
        from app.detectors.base import Endpoint
        scanner = CORSScanner(None, None, None)
        ep = Endpoint(url="http://example.com", method="GET")
        assert scanner.applies_to(ep)
        return True, "CORS scanner OK"
    except Exception as e:
        return False, f"CORS scanner error: {e}"


def check_ssrf_bypasses():
    """Verify apply_bypasses method exists and works"""
    try:
        from app.detectors.ssrf import SSRFDetector
        detector = SSRFDetector(None, None, None)
        result = detector.apply_bypasses("127.0.0.1")
        if isinstance(result, list) and len(result) > 0:
            return True, f"SSRF apply_bypasses OK ({len(result)} bypass variants generated)"
        return False, f"SSRF apply_bypasses returned unexpected result: {result}"
    except AttributeError as e:
        return False, f"SSRF apply_bypasses method missing: {e}"
    except Exception as e:
        return False, f"SSRF apply_bypasses error: {e}"


def main():
    print("=" * 60)
    print("BugHunter Installation Verification")
    print("=" * 60)

    all_passed = True

    # Python version
    ok, msg = check_python_version()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] Python Version: {msg}")
    if not ok:
        all_passed = False

    # Required packages
    print("\n--- Python Packages ---")
    ok, results = check_required_packages()
    for ok_pkg, msg in results:
        status = "PASS" if ok_pkg else "FAIL"
        print(f"[{status}] {msg}")
        if not ok_pkg:
            all_passed = False

    # CVSS module
    ok, msg = check_cvss()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] CVSS: {msg}")
    if not ok:
        all_passed = False

    # Database
    ok, msg = check_database()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] Database: {msg}")
    if not ok:
        all_passed = False

    # Directories
    print("\n--- Directories ---")
    ok, results = check_directories()
    for ok_dir, msg in results:
        status = "PASS" if ok_dir else "WARN"
        print(f"[{status}] {msg}")
        if not ok_dir:
            all_passed = False

    # External tools
    print("\n--- External Tools ---")
    ok, results = check_external_tools()
    for ok_tool, msg in results:
        status = "PASS" if ok_tool else "WARN"
        print(f"[{status}] {msg}")

    # Playwright browsers
    ok, msg = check_playwright_browsers()
    status = "PASS" if ok else "WARN"
    print(f"\n[{status}] Playwright: {msg}")
    if not ok:
        all_passed = False

    # Server module
    ok, msg = check_server()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] Server: {msg}")
    if not ok:
        all_passed = False

    # Detectors
    ok, msg = check_detectors()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] Detectors: {msg}")
    if not ok:
        all_passed = False

    # CORS detector check
    ok, msg = check_cors_detector()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] CORS Scanner: {msg}")
    if not ok:
        all_passed = False

    # SSRF bypasses
    ok, msg = check_ssrf_bypasses()
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] SSRF Bypasses: {msg}")
    if not ok:
        all_passed = False

    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL CHECKS PASSED - BugHunter is ready to run!")
        print(f"Start server: cd {PROJECT_DIR.parent} && python -m app.server")
        print(f"Or:           cd {PROJECT_DIR.parent} && uvicorn app.server:app --host 127.0.0.1 --port 8080")
    else:
        print("SOME CHECKS FAILED - See errors above.")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
