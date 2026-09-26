import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from app.config import settings
from app.reporting.hackerone_template import render_hackerone
from app.reporting.bugcrowd_template import render_bugcrowd
from app.models import Finding as FindingModel


class ReportGenerator:
    def __init__(self):
        self.reports_dir = settings.REPORTS_DIR

    def generate(self, finding: FindingModel, format: str = "hackerone", target_url: str = None) -> str:
        finding_dict = {
            "id": finding.id,
            "vuln_class": finding.vuln_class,
            "endpoint": finding.endpoint,
            "method": finding.method,
            "param": finding.param,
            "confidence": finding.confidence.value,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score / 10 if finding.cvss_score else 0.0,
            "cvss_vector": finding.cvss_vector,
            "evidence": finding.evidence,
            "summary": finding.summary,
            "description": finding.description,
            "steps_to_reproduce": finding.steps_to_reproduce,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "bugcrowd_vrt_category": finding.bugcrowd_vrt_category,
            "severity_label": finding.severity.value.capitalize(),
            "priority": self._map_priority(finding.severity.value, finding.cvss_score / 10 if finding.cvss_score else 0.0),
        }

        if format == "bugcrowd":
            content = render_bugcrowd(finding_dict)
        else:
            content = render_hackerone(finding_dict)

        # Use provided target_url or fallback to finding.endpoint
        base_url = target_url or finding.endpoint
        safe_url = base_url.replace("://", "_").replace("/", "_").replace(":", "_")
        target_dir = self.reports_dir / safe_url / datetime.utcnow().strftime("%Y%m%d")
        target_dir.mkdir(parents=True, exist_ok=True)

        filename = f"finding_{finding.id}_{finding.vuln_class.lower().replace(' ', '_')}.md"
        filepath = target_dir / filename

        with open(filepath, "w") as f:
            f.write(content)

        return str(filepath)

    def _map_priority(self, severity: str, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "P1"
        elif cvss_score >= 7.0:
            return "P2"
        elif cvss_score >= 4.0:
            return "P3"
        elif cvss_score > 0.0:
            return "P4"
        return "P5"


def generate_report(finding: FindingModel, format: str = "hackerone", target_url: str = None) -> str:
    generator = ReportGenerator()
    return generator.generate(finding, format, target_url)