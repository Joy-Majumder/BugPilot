from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import json
from datetime import datetime
from pathlib import Path

from app.database import init_db, get_db_session
from app.models import ScanSession, ScanStatus, Finding as FindingModel, AuthSession, CrawlData, ConfidenceLevel, SeverityLevel
from app.scan_pipeline import ScanPipeline
from app.reporting import generate_report
from app.config import settings


app = FastAPI(title="BugHunter", description="Personal Bug Bounty Automation Tool")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

init_db()

active_scans: Dict[int, ScanPipeline] = {}
websocket_connections: Dict[int, List[WebSocket]] = {}


class ScanCreateRequest(BaseModel):
    target_url: str
    name: Optional[str] = None
    auth_sessions: List[Dict[str, Any]] = []
    scope: Dict[str, Any] = {}
    detectors: List[str] = []
    rate_limit: int = 10
    concurrency: int = 5


class AuthSessionCreate(BaseModel):
    name: str
    type: str
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    tokens: Dict[str, str] = {}
    login_flow: Dict[str, Any] = {}


@app.on_event("startup")
async def startup():
    pass


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    db = get_db_session()
    scans = db.query(ScanSession).order_by(ScanSession.created_at.desc()).limit(20).all()
    db.close()
    return templates.TemplateResponse("index.html", {"request": request, "scans": scans})


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int):
    db = get_db_session()
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = db.query(FindingModel).filter(FindingModel.scan_session_id == scan_id).all()
    db.close()

    return templates.TemplateResponse("scan_detail.html", {"request": request, "scan": scan, "findings": findings})


@app.post("/api/scans")
async def create_scan(scan_req: ScanCreateRequest):
    db = get_db_session()
    scan = ScanSession(
        target_url=scan_req.target_url,
        name=scan_req.name or scan_req.target_url,
        config={
            "scope": scan_req.scope,
            "detectors": scan_req.detectors,
            "rate_limit": scan_req.rate_limit,
            "concurrency": scan_req.concurrency,
        },
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for auth in scan_req.auth_sessions:
        auth_session = AuthSession(
            scan_session_id=scan.id,
            name=auth["name"],
            type=auth["type"],
            cookies=auth.get("cookies", {}),
            headers=auth.get("headers", {}),
            tokens=auth.get("tokens", {}),
            login_flow=auth.get("login_flow", {}),
        )
        db.add(auth_session)
    db.commit()

    db.close()
    return {"scan_id": scan.id, "status": "created"}


@app.post("/api/scans/{scan_id}/start")
async def start_scan(scan_id: int):
    db = get_db_session()
    scan = db.query(ScanSession).filter(ScanSession.id == scan_id).first()
    if not scan:
        db.close()
        raise HTTPException(404, "Scan not found")

    if scan.status == ScanStatus.RUNNING:
        db.close()
        return {"status": "already_running"}

    db.close()

    pipeline = ScanPipeline(scan_id)
    await pipeline.initialize()
    active_scans[scan_id] = pipeline

    asyncio.create_task(run_scan_with_cleanup(scan_id, pipeline))

    return {"status": "started"}


async def run_scan_with_cleanup(scan_id: int, pipeline: ScanPipeline):
    try:
        async def progress_callback(msg: str, percent: int):
            await broadcast_progress(scan_id, msg, percent)

        await pipeline.run(progress_callback)
    finally:
        await pipeline.cleanup()
        active_scans.pop(scan_id, None)


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: int):
    pipeline = active_scans.get(scan_id)
    if pipeline:
        pipeline.scan_session.status = ScanStatus.STOPPED
        pipeline.db.commit()
        await pipeline.cleanup()
        active_scans.pop(scan_id, None)
        return {"status": "stopped"}
    raise HTTPException(404, "Scan not running")


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: int):
    await websocket.accept()

    if scan_id not in websocket_connections:
        websocket_connections[scan_id] = []
    websocket_connections[scan_id].append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_connections[scan_id].remove(websocket)


async def broadcast_progress(scan_id: int, message: str, percent: int):
    if scan_id in websocket_connections:
        data = json.dumps({"message": message, "percent": percent, "timestamp": datetime.utcnow().isoformat()})
        for ws in websocket_connections[scan_id]:
            try:
                await ws.send_text(data)
            except Exception:
                pass


@app.get("/api/scans/{scan_id}/findings")
async def get_findings(scan_id: int, confidence: Optional[str] = None):
    db = get_db_session()
    query = db.query(FindingModel).filter(FindingModel.scan_session_id == scan_id)
    if confidence:
        query = query.filter(FindingModel.confidence == ConfidenceLevel(confidence))
    findings = query.order_by(FindingModel.severity.desc(), FindingModel.created_at.desc()).all()
    db.close()

    return [
        {
            "id": f.id,
            "vuln_class": f.vuln_class,
            "endpoint": f.endpoint,
            "method": f.method,
            "param": f.param,
            "confidence": f.confidence.value,
            "severity": f.severity.value,
            "cvss_score": f.cvss_score / 10 if f.cvss_score else 0,
            "cvss_vector": f.cvss_vector,
            "summary": f.summary,
            "evidence": f.evidence,
        }
        for f in findings
    ]


@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: int):
    db = get_db_session()
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    db.close()

    if not finding:
        raise HTTPException(404, "Finding not found")

    return {
        "id": finding.id,
        "vuln_class": finding.vuln_class,
        "endpoint": finding.endpoint,
        "method": finding.method,
        "param": finding.param,
        "confidence": finding.confidence.value,
        "severity": finding.severity.value,
        "cvss_score": finding.cvss_score / 10 if finding.cvss_score else 0,
        "cvss_vector": finding.cvss_vector,
        "evidence": finding.evidence,
        "summary": finding.summary,
        "description": finding.description,
        "steps_to_reproduce": finding.steps_to_reproduce,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "bugcrowd_vrt_category": finding.bugcrowd_vrt_category,
    }


@app.post("/api/findings/{finding_id}/report")
async def generate_finding_report(finding_id: int, format: str = Form("hackerone")):
    db = get_db_session()
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    db.close()

    if not finding:
        raise HTTPException(404, "Finding not found")

    if format not in ("hackerone", "bugcrowd"):
        raise HTTPException(400, "Invalid format")

    report_path = generate_report(finding, format)

    return {"report_path": report_path, "format": format}


@app.get("/api/findings/{finding_id}/report/download")
async def download_report(finding_id: int, format: str = "hackerone"):
    db = get_db_session()
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    db.close()

    if not finding:
        raise HTTPException(404, "Finding not found")

    report_path = generate_report(finding, format)
    return FileResponse(report_path, filename=Path(report_path).name)


@app.get("/api/scans")
async def list_scans():
    db = get_db_session()
    scans = db.query(ScanSession).order_by(ScanSession.created_at.desc()).all()
    db.close()

    return [
        {
            "id": s.id,
            "target_url": s.target_url,
            "name": s.name,
            "status": s.status.value,
            "created_at": s.created_at.isoformat(),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]


@app.get("/api/payloads")
async def list_payloads(category: Optional[str] = None):
    db = get_db_session()
    from app.models import PayloadLibrary
    query = db.query(PayloadLibrary)
    if category:
        query = query.filter(PayloadLibrary.category == category)
    payloads = query.all()
    db.close()

    return [
        {
            "id": p.id,
            "category": p.category,
            "context": p.context,
            "payload": p.payload,
            "description": p.description,
            "tags": p.tags,
        }
        for p in payloads
    ]


@app.post("/api/payloads")
async def add_payload(payload: Dict[str, Any]):
    db = get_db_session()
    from app.models import PayloadLibrary
    p = PayloadLibrary(
        category=payload["category"],
        context=payload["context"],
        payload=payload["payload"],
        description=payload.get("description", ""),
        tags=payload.get("tags", []),
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    db.close()
    return {"id": p.id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.SERVER_HOST, port=settings.SERVER_PORT)