from typing import List, Dict, Type
from app.detectors.base import Detector
from app.detectors.xss import ReflectedXSSDetector, StoredXSSDetector, DOMXSSDetector
from app.detectors.sqli import SQLIDetector, NoSQLIDetector, CommandInjectionDetector
from app.detectors.ssrf import SSRFDetector, OpenRedirectDetector, CSRFDetector, HTTPRequestSmugglingDetector, XXEDetector
from app.detectors.auth import IDORDetector, BOLADetector, PrivilegeEscalationDetector, JWTDetector
from app.detectors.other import SSTIDetector, FileUploadDetector, RaceConditionDetector, CORSScanner, SubdomainTakeoverDetector
from app.detectors.advanced import (
    ClickjackingDetector, LDAPInjectionDetector, XPathInjectionDetector,
    DOMClobberDetector, PrototypePollutionDetector, PostMessageDetector,
    BlindXSSDetector, AdminPanelDetector, WeakTLSDetector,
    PriceQuantityManipulationDetector, AILMLMDetector,
)
from app.detectors.smart_contracts import SmartContractDetector


DETECTOR_CLASSES: List[Type[Detector]] = [
    ReflectedXSSDetector,
    StoredXSSDetector,
    DOMXSSDetector,
    BlindXSSDetector,
    SQLIDetector,
    NoSQLIDetector,
    CommandInjectionDetector,
    LDAPInjectionDetector,
    XPathInjectionDetector,
    SSRFDetector,
    OpenRedirectDetector,
    CSRFDetector,
    HTTPRequestSmugglingDetector,
    XXEDetector,
    IDORDetector,
    BOLADetector,
    PrivilegeEscalationDetector,
    JWTDetector,
    SSTIDetector,
    FileUploadDetector,
    RaceConditionDetector,
    PriceQuantityManipulationDetector,
    CORSScanner,
    SubdomainTakeoverDetector,
    ClickjackingDetector,
    DOMClobberDetector,
    PrototypePollutionDetector,
    PostMessageDetector,
    AdminPanelDetector,
    WeakTLSDetector,
    AILMLMDetector,
    SmartContractDetector,
]

DETECTOR_MAP: Dict[str, Type[Detector]] = {cls.name: cls for cls in DETECTOR_CLASSES}


def get_all_detectors(http_client, oob_server=None, playwright_browser=None) -> List[Detector]:
    return [cls(http_client, oob_server, playwright_browser) for cls in DETECTOR_CLASSES]


def get_detector_by_name(name: str, http_client, oob_server=None, playwright_browser=None) -> Detector:
    cls = DETECTOR_MAP.get(name)
    if cls:
        return cls(http_client, oob_server, playwright_browser)
    raise ValueError(f"Unknown detector: {name}")


def get_detectors_by_category(category: str, http_client, oob_server=None, playwright_browser=None) -> List[Detector]:
    category_map = {
        "injection": ["sqli", "nosqli", "command_injection", "ldap", "xpath", "xxe", "ssti"],
        "xss": ["reflected_xss", "stored_xss", "blind_xss", "dom_xss"],
        "ssrf": ["ssrf", "open_redirect", "csrf", "http_request_smuggling"],
        "auth": ["idor", "bola", "privilege_escalation", "jwt_flaws"],
        "other": ["file_upload", "race_condition", "price_manipulation", "cors", "subdomain_takeover"],
        "client_side": ["clickjacking", "dom_clobbering", "prototype_pollution", "postmessage"],
        "infrastructure": ["admin_panel", "weak_tls"],
        "ai": ["ai_llm_security"],
        "blockchain": ["smart_contract"],
    }
    names = category_map.get(category, [])
    return [get_detector_by_name(n, http_client, oob_server, playwright_browser) for n in names]