from cvss import CVSS3
from typing import Optional, Dict, Any
from app.detectors.base import Finding as DetectorFinding


class CVSSScorer:
    DEFAULT_VECTORS = {
        "reflected_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "stored_xss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        "dom_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "blind_xss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
        "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "nosqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "ldap": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "xpath": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "http_request_smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "bola": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "privilege_escalation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "jwt_flaws": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "file_upload": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "race_condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "price_manipulation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
        "cors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
        "subdomain_takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "clickjacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "dom_clobbering": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "prototype_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "postmessage": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "admin_panel": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "weak_tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "ai_llm_security": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    }

    @classmethod
    def score(cls, vuln_class: str, custom_vector: str = None) -> Dict[str, Any]:
        vector = custom_vector or cls.DEFAULT_VECTORS.get(vuln_class.lower().replace(" ", "_"), "")
        if not vector:
            return {"score": 0.0, "severity": "info", "vector": ""}

        try:
            cvss = CVSS3(vector)
            scores = cvss.scores()
            base_score = scores[0]

            if base_score >= 9.0:
                severity = "critical"
            elif base_score >= 7.0:
                severity = "high"
            elif base_score >= 4.0:
                severity = "medium"
            elif base_score > 0.0:
                severity = "low"
            else:
                severity = "info"

            return {
                "score": base_score,
                "severity": severity,
                "vector": vector,
            }
        except Exception:
            return {"score": 0.0, "severity": "info", "vector": vector}

    @classmethod
    def map_to_hackerone(cls, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        elif cvss_score > 0.0:
            return "Low"
        return "Informational"

    @classmethod
    def map_to_bugcrowd(cls, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "P1"
        elif cvss_score >= 7.0:
            return "P2"
        elif cvss_score >= 4.0:
            return "P3"
        elif cvss_score > 0.0:
            return "P4"
        return "P5"