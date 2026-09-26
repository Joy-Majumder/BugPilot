import hashlib
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models import Finding as FindingModel, ConfidenceLevel, SeverityLevel
from app.detectors.base import Finding as DetectorFinding
from app.config import settings


class DedupEngine:
    def __init__(self, db: Session):
        self.db = db

    def is_duplicate(self, finding: DetectorFinding) -> bool:
        existing = self.db.query(FindingModel).filter(
            FindingModel.dedup_hash == finding.dedup_hash
        ).first()
        return existing is not None

    def get_existing(self, finding: DetectorFinding, scan_session_id: int = None) -> Optional[FindingModel]:
        query = self.db.query(FindingModel).filter(
            FindingModel.dedup_hash == finding.dedup_hash
        )
        if scan_session_id is not None:
            query = query.filter(FindingModel.scan_session_id == scan_session_id)
        return query.first()

    def is_duplicate(self, finding: DetectorFinding, scan_session_id: int = None) -> bool:
        return self.get_existing(finding, scan_session_id) is not None


class FindingStore:
    def __init__(self, db: Session):
        self.db = db
        self.dedup = DedupEngine(db)

    def save(self, finding: DetectorFinding, scan_session_id: int) -> FindingModel:
        existing = self.dedup.get_existing(finding, scan_session_id)
        if existing:
            existing.confidence = ConfidenceLevel(finding.confidence)
            existing.evidence = finding.evidence
            existing.cvss_vector = finding.cvss_vector
            existing.cvss_score = int(finding.cvss_score * 10) if finding.cvss_score else None
            existing.updated_at = __import__("datetime").datetime.utcnow()
            self.db.commit()
            self.db.refresh(existing)
            return existing

        model = FindingModel(
            scan_session_id=scan_session_id,
            vuln_class=finding.vuln_class,
            endpoint=finding.endpoint,
            method=finding.method,
            param=finding.param,
            confidence=ConfidenceLevel(finding.confidence),
            severity=SeverityLevel(finding.severity),
            cvss_score=int(finding.cvss_score * 10) if finding.cvss_score else None,
            cvss_vector=finding.cvss_vector,
            evidence=finding.evidence,
            summary=finding.summary,
            description=finding.description,
            steps_to_reproduce=finding.steps_to_reproduce,
            impact=finding.impact,
            remediation=finding.remediation,
            bugcrowd_vrt_category=finding.bugcrowd_vrt_category,
            dedup_hash=finding.dedup_hash,
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model

    def get_findings(self, scan_session_id: int, confidence: str = None) -> List[FindingModel]:
        query = self.db.query(FindingModel).filter(FindingModel.scan_session_id == scan_session_id)
        if confidence:
            query = query.filter(FindingModel.confidence == ConfidenceLevel(confidence))
        return query.order_by(FindingModel.severity.desc(), FindingModel.created_at.desc()).all()

    def get_finding(self, finding_id: int) -> Optional[FindingModel]:
        return self.db.query(FindingModel).filter(FindingModel.id == finding_id).first()

    def update_finding(self, finding_id: int, **kwargs) -> Optional[FindingModel]:
        finding = self.get_finding(finding_id)
        if finding:
            for key, value in kwargs.items():
                if hasattr(finding, key):
                    setattr(finding, key, value)
            self.db.commit()
            self.db.refresh(finding)
        return finding