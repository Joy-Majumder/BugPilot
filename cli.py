#!/usr/bin/env python3
"""BugPilot CLI - Typer-based command-line interface."""
import sys
import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from app.database import init_db, get_db_session
from app.models import ScanSession, ScanStatus, Finding as FindingModel, ConfidenceLevel
from app.scan_pipeline import ScanPipeline
from app.reporting import generate_report
from app.config import settings

console = Console()
app = typer.Typer(add_completion=False, help="BugPilot — Open-source bug bounty automation that finds, validates, and reports web vulnerabilities.")


def _print_banner():
    console.print(Panel.fit(
        "[bold cyan]BugPilot[/bold cyan]\n"
        "[dim]Open-source bug bounty automation tool[/dim]",
        border_style="cyan",
    ))


@app.command()
def init():
    """Initialize the database and directory structure."""
    init_db()
    console.print("[green]Database initialized[/green]")
    console.print(f"  Data dir:    [dim]{settings.DATA_DIR}[/dim]")
    console.print(f"  Reports dir: [dim]{settings.REPORTS_DIR}[/dim]")
    console.print(f"  Tools dir:   [dim]{settings.TOOLS_DIR}[/dim]")


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL (e.g. https://example.com)"),
    name: str = typer.Option("", "--name", "-n", help="Scan name"),
    detectors: str = typer.Option("", "--detectors", "-d", help="Comma-separated detector names (empty = all)"),
    rate_limit: int = typer.Option(10, "--rate-limit", "-r", help="Requests per second"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Concurrent workers"),
):
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
    scan_id = scan.id
    db.close()

    console.print(f"[green]Created scan #{scan_id}: {target}[/green]")

    async def run_scan():
        pipeline = ScanPipeline(scan_id)
        await pipeline.initialize()

        async def progress(msg, pct):
            console.print(f"[cyan]{pct:>3}%[/cyan] {msg}")

        try:
            await pipeline.run(progress)
            console.print("[green]Scan completed![/green]")
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")
        finally:
            await pipeline.cleanup()

    asyncio.run(run_scan())


@app.command()
def list_scans():
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
        status_style = {
            "completed": "green",
            "failed": "red",
            "running": "yellow",
            "pending": "dim",
            "stopped": "magenta",
        }.get(s.status.value, "yellow")
        table.add_row(
            str(s.id),
            s.target_url,
            s.name or "-",
            f"[{status_style}]{s.status.value}[/{status_style}]",
            s.created_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


@app.command(name="findings")
def findings(
    scan_id: int = typer.Option(..., "--scan-id", "-s", help="Scan ID"),
    confidence: str = typer.Option("", "--confidence", "-c", help="Filter by confidence (confirmed/suspected)"),
):
    """List findings for a scan."""
    db = get_db_session()
    query = db.query(FindingModel).filter(FindingModel.scan_session_id == scan_id)
    if confidence:
        query = query.filter(FindingModel.confidence == ConfidenceLevel(confidence))
    findings = query.order_by(FindingModel.severity.desc(), FindingModel.created_at.desc()).all()
    db.close()

    table = Table(title=f"Findings for Scan #{scan_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Conf.", style="yellow")
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
            f"{f.cvss_score / 10:.1f}" if f.cvss_score else "N/A",
        )

    console.print(table)


@app.command()
def report(
    finding_id: int = typer.Option(..., "--finding-id", "-f", help="Finding ID"),
    format: str = typer.Option("hackerone", "--format", help="Report format (hackerone|bugcrowd)"),
):
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


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind"),
):
    """Start the web UI server."""
    import uvicorn

    console.print(f"[green]Starting BugPilot web UI on http://{host}:{port}[/green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    uvicorn.run("app.server:app", host=host, port=port, reload=False)


def _interactive_menu():
    """Interactive menu when run with no arguments."""
    _print_banner()
    console.print("\n[bold]Available commands:[/bold]\n")
    console.print("  [cyan]1)[/cyan] init     - Initialize database and directories")
    console.print("  [cyan]2)[/cyan] scan     - Run a vulnerability scan")
    console.print("  [cyan]3)[/cyan] list     - List all scans")
    console.print("  [cyan]4)[/cyan] findings  - View findings for a scan")
    console.print("  [cyan]5)[/cyan] report    - Generate a report for a finding")
    console.print("  [cyan]6)[/cyan] serve    - Start the web UI server")
    console.print("  [cyan]7)[/cyan] exit     - Quit\n")

    while True:
        choice = Prompt.ask(
            "[bold cyan]Select option[/bold cyan]",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            default="7",
        )

        try:
            if choice == "1":
                init()
            elif choice == "2":
                target = Prompt.ask("Enter target URL", default="http://httpbin.org")
                name = Prompt.ask("Scan name (optional)", default="", show_default=False)
                dets = Prompt.ask("Detectors (comma-separated, empty=all)", default="", show_default=False)
                rl = Prompt.ask("Rate limit", default="10")
                cc = Prompt.ask("Concurrency", default="5")
                asyncio.run(_run_scan_interactive(
                    target, name or target, dets, int(rl), int(cc)
                ))
            elif choice == "3":
                list_scans()
            elif choice == "4":
                sid = Prompt.ask("Enter scan ID")
                conf = Prompt.ask("Confidence filter (empty=none)", default="", show_default=False)
                findings(int(sid), conf)
            elif choice == "5":
                fid = Prompt.ask("Enter finding ID")
                fmt = Prompt.ask("Format (hackerone|bugcrowd)", default="hackerone")
                report(int(fid), fmt)
            elif choice == "6":
                host = Prompt.ask("Host", default="127.0.0.1")
                port = Prompt.ask("Port", default="8080")
                serve(host, int(port))
            elif choice == "7":
                console.print("[yellow]Goodbye![/yellow]")
                break
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

        console.print()


async def _run_scan_interactive(target, name, detectors_str, rate_limit, concurrency):
    """Run a scan interactively with progress display."""
    db = get_db_session()
    scan = ScanSession(
        target_url=target,
        name=name,
        config={
            "detectors": detectors_str.split(",") if detectors_str else [],
            "rate_limit": rate_limit,
            "concurrency": concurrency,
        },
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()
    console.print(f"[green]Created scan #{scan_id}: {target}[/green]")

    pipeline = ScanPipeline(scan_id)
    await pipeline.initialize()

    async def progress(msg, pct):
        console.print(f"[cyan]{pct:>3}%[/cyan] {msg}")

    try:
        await pipeline.run(progress)
        console.print("[green]Scan completed![/green]")

        db = get_db_session()
        db_findings = db.query(FindingModel).filter(FindingModel.scan_session_id == scan_id).all()
        db.close()
        console.print(f"[green]Found {len(db_findings)} findings[/green]")
        if db_findings:
            console.print(f"\nRun [cyan]bugpilot findings -s {scan_id}[/cyan] to view details")
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
    finally:
        await pipeline.cleanup()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
):
    """BugPilot — Open-source bug bounty automation that finds, validates, and reports web vulnerabilities.

    Without arguments, launches an interactive menu.
    Pass a command to run it directly.
    """
    if ctx.invoked_subcommand is None:
        _interactive_menu()


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Goodbye![/yellow]")
