#!/usr/bin/env python3
import sys
import asyncio
from rich.console import Console
from rich.table import Table

from app.database import init_db, get_db_session
from app.models import ScanSession, ScanStatus, Finding as FindingModel, ConfidenceLevel
from app.scan_pipeline import ScanPipeline
from app.reporting import generate_report
from app.config import settings

console = Console()


def init_cmd():
    """Initialize the database and directory structure."""
    init_db()
    console.print("[green]Database initialized[/green]")
    console.print(f"Data dir: {settings.DATA_DIR}")
    console.print(f"Reports dir: {settings.REPORTS_DIR}")
    console.print(f"Tools dir: {settings.TOOLS_DIR}")


def scan_cmd(target: str, name: str = "", detectors: str = "", rate_limit: int = 10, concurrency: int = 5):
    """Create and start a new scan."""
    db = get_db_session()

    scan = ScanSession(
        target_url=target,
        name=name or target,
        config={
            "detectors": detectors.split(",") if detectors else [],
            "rate_limit": rate_limit,
            "concurrency": concurrency,
        },
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    console.print(f"[green]Created scan #{scan.id}: {target}[/green]")

    async def run_scan():
        pipeline = ScanPipeline(scan.id)
        await pipeline.initialize()

        async def progress(msg, percent):
            console.print(f"[cyan]{percent}%[/cyan] {msg}")

        try:
            await pipeline.run(progress)
            console.print("[green]Scan completed![/green]")
        finally:
            await pipeline.cleanup()

    asyncio.run(run_scan())
    db.close()


def list_cmd():
    """List all scans."""
    db = get_db_session()
    scans = db.query(ScanSession).order_by(ScanSession.created_at.desc()).all()
    db.close()

    table = Table(title="Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Name")
    table.add_column("Status", style="yellow")
    table.add_column("Created")

    for s in scans:
        table.add_row(str(s.id), s.target_url, s.name or "-", s.status.value, s.created_at.strftime("%Y-%m-%d %H:%M"))

    console.print(table)


def findings_cmd(scan_id: int, confidence: str = ""):
    """List findings for a scan."""
    db = get_db_session()
    query = db.query(FindingModel).filter(FindingModel.scan_session_id == scan_id)
    if confidence:
        query = query.filter(FindingModel.confidence == ConfidenceLevel(confidence))
    findings = query.order_by(FindingModel.severity.desc()).all()
    db.close()

    table = Table(title=f"Findings for Scan #{scan_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Confidence", style="yellow")
    table.add_column("Class", style="green")
    table.add_column("Endpoint")
    table.add_column("Param")
    table.add_column("CVSS")

    for f in findings:
        table.add_row(
            str(f.id),
            f.severity.value,
            f.confidence.value,
            f.vuln_class,
            f.endpoint[:60] + "..." if len(f.endpoint) > 60 else f.endpoint,
            f.param or "-",
            f"{f.cvss_score/10:.1f}" if f.cvss_score else "N/A"
        )

    console.print(table)


def report_cmd(finding_id: int, format: str = "hackerone"):
    """Generate a report for a finding."""
    db = get_db_session()
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    db.close()

    if not finding:
        console.print(f"[red]Finding #{finding_id} not found[/red]")
        sys.exit(1)

    path = generate_report(finding, format)
    console.print(f"[green]Report generated: {path}[/green]")

    with open(path) as f:
        console.print(f.read())


def serve_cmd(host: str = "127.0.0.1", port: int = 8080):
    """Start the web UI server."""
    import uvicorn
    console.print(f"[green]Starting server on http://{host}:{port}[/green]")
    uvicorn.run("app.server:app", host=host, port=port, reload=False)


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m cli <command> [args...]")
        print("Commands: init, scan, list, findings, report, serve")
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "init":
        init_cmd()
    elif cmd == "scan":
        if len(args) < 1:
            print("Usage: scan <target> [--name NAME] [--detectors DETECTORS] [--rate-limit N] [--concurrency N]")
            sys.exit(1)
        # Simple arg parsing
        target = args[0]
        name = ""
        detectors = ""
        rate_limit = 10
        concurrency = 5
        i = 1
        while i < len(args):
            if args[i] == "--name" and i + 1 < len(args):
                name = args[i + 1]
                i += 2
            elif args[i] == "--detectors" and i + 1 < len(args):
                detectors = args[i + 1]
                i += 2
            elif args[i] == "--rate-limit" and i + 1 < len(args):
                rate_limit = int(args[i + 1])
                i += 2
            elif args[i] == "--concurrency" and i + 1 < len(args):
                concurrency = int(args[i + 1])
                i += 2
            else:
                i += 1
        scan_cmd(target, name, detectors, rate_limit, concurrency)
    elif cmd == "list":
        list_cmd()
    elif cmd == "findings":
        if len(args) < 1:
            print("Usage: findings <scan_id> [--confidence CONFIDENCE]")
            sys.exit(1)
        scan_id = int(args[0])
        confidence = ""
        if len(args) > 2 and args[1] == "--confidence":
            confidence = args[2]
        findings_cmd(scan_id, confidence)
    elif cmd == "report":
        if len(args) < 1:
            print("Usage: report <finding_id> [--format hackerone|bugcrowd]")
            sys.exit(1)
        finding_id = int(args[0])
        format = "hackerone"
        if len(args) > 2 and args[1] == "--format":
            format = args[2]
        report_cmd(finding_id, format)
    elif cmd == "serve":
        host = "127.0.0.1"
        port = 8080
        i = 0
        while i < len(args):
            if args[i] == "--host" and i + 1 < len(args):
                host = args[i + 1]
                i += 2
            elif args[i] == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
                i += 2
            else:
                i += 1
        serve_cmd(host, port)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()