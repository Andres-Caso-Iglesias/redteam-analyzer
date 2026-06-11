"""Rich output helpers for redteam-analyzer CLI."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from redteam_analyzer.core.models import Finding, ScanResult, Severity

console = Console()


def create_progress_bar() -> Progress:
    """Create a Rich progress bar for scan operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )


def create_findings_table(findings: list[Finding]) -> Table:
    """Create a Rich table from a list of findings.
    
    Columns: Severity (color-coded), Type, Title, Location
    Sort by severity (critical first).
    """
    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=20)
    table.add_column("Title", min_width=30)
    table.add_column("Location", min_width=20)
    
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }
    
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
    
    for finding in sorted_findings:
        color = severity_colors.get(finding.severity, "white")
        table.add_row(
            Text(finding.severity.value.upper(), style=color),
            finding.type.value,
            finding.title,
            finding.location,
        )
    
    return table


def print_finding(finding: Finding) -> None:
    """Print a single finding as a Rich panel with full details."""
    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red", 
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }
    color = severity_colors.get(finding.severity, "white")
    
    details = []
    details.append(f"[bold]Type:[/bold] {finding.type.value}")
    details.append(f"[bold]Severity:[/bold] [{color}]{finding.severity.value.upper()}[/{color}]")
    details.append(f"[bold]Location:[/bold] {finding.location}")
    if finding.description:
        details.append(f"[bold]Description:[/bold] {finding.description}")
    if finding.cve_id:
        details.append(f"[bold]CVE:[/bold] {finding.cve_id}")
    if finding.cvss_score is not None:
        details.append(f"[bold]CVSS:[/bold] {finding.cvss_score}")
    if finding.remediation:
        details.append(f"[bold]Remediation:[/bold] {finding.remediation}")
    
    content = "\n".join(details)
    panel = Panel(content, title=finding.title, border_style=color, expand=True)
    console.print(panel)


def print_summary(scan_result: ScanResult) -> None:
    """Print a scan summary panel with finding counts by severity."""
    findings = scan_result.findings
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)
    info = sum(1 for f in findings if f.severity == Severity.INFO)
    
    summary_lines = [
        f"[bold]Target:[/bold] {scan_result.target.primary}",
        f"[bold]Total Findings:[/bold] {total}",
        "",
        f"  [bold red]Critical: {critical}[/bold red]",
        f"  [bold red]High: {high}[/bold red]",
        f"  [yellow]Medium: {medium}[/yellow]",
        f"  [cyan]Low: {low}[/cyan]",
        f"  [dim]Info: {info}[/dim]",
    ]
    
    if scan_result.errors:
        summary_lines.append("")
        summary_lines.append(f"[bold red]Errors ({len(scan_result.errors)}):[/bold red]")
        for error in scan_result.errors:
            summary_lines.append(f"  - {error}")
    
    panel = Panel("\n".join(summary_lines), title="Scan Summary", border_style="blue", expand=False)
    console.print(panel)