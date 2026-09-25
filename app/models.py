import enum
import json
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Enum, ForeignKey, Index, JSON
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON

Base = declarative_base()


class ConfidenceLevel(str, enum.Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(String(500), nullable=False)
    name = Column(String(200))
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    config = Column(SQLiteJSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan_session", cascade="all, delete-orphan")
    crawl_data = relationship("CrawlData", back_populates="scan_session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scan_sessions_target_url", "target_url"),
        Index("ix_scan_sessions_status", "status"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    vuln_class = Column(String(100), nullable=False)
    endpoint = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False)
    param = Column(String(100), nullable=True)
    confidence = Column(Enum(ConfidenceLevel), default=ConfidenceLevel.SUSPECTED)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.INFO)
    cvss_score = Column(Integer, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    evidence = Column(SQLiteJSON, default={})
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    steps_to_reproduce = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    bugcrowd_vrt_category = Column(String(200), nullable=True)
    dedup_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_session = relationship("ScanSession", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_scan_session", "scan_session_id"),
        Index("ix_findings_vuln_class", "vuln_class"),
        Index("ix_findings_confidence", "confidence"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_dedup_hash", "dedup_hash"),
    )


class CrawlData(Base):
    __tablename__ = "crawl_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    url = Column(String(500), nullable=False)
    method = Column(String(10), default="GET")
    params = Column(SQLiteJSON, default=[])
    headers = Column(SQLiteJSON, default={})
    response_status = Column(Integer, nullable=True)
    response_headers = Column(SQLiteJSON, default={})
    response_body_hash = Column(String(64), nullable=True)
    tech_fingerprint = Column(SQLiteJSON, default={})
    auth_required = Column(Integer, default=0)
    depth = Column(Integer, default=0)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan_session = relationship("ScanSession", back_populates="crawl_data")

    __table_args__ = (
        Index("ix_crawl_data_session", "scan_session_id"),
        Index("ix_crawl_data_url", "url"),
    )


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    type = Column(String(50), nullable=False)
    cookies = Column(SQLiteJSON, default={})
    headers = Column(SQLiteJSON, default={})
    tokens = Column(SQLiteJSON, default={})
    login_flow = Column(SQLiteJSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_auth_sessions_scan", "scan_session_id"),
    )


class OOBCallback(Base):
    __tablename__ = "oob_callbacks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(64), nullable=False, unique=True)
    callback_type = Column(String(20), nullable=False)
    source_ip = Column(String(45), nullable=True)
    request_data = Column(SQLiteJSON, default={})
    received_at = Column(DateTime, default=datetime.utcnow)
    matched_finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)

    __table_args__ = (
        Index("ix_oob_callbacks_received", "received_at"),
    )


class PayloadLibrary(Base):
    __tablename__ = "payload_library"

    id = Column(Integer, primary_key=True, autoincrement=True)
    category = Column(String(50), nullable=False, index=True)
    context = Column(String(50), nullable=False)
    payload = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(SQLiteJSON, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_payload_category_context", "category", "context"),
    )