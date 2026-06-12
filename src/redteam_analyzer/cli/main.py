"""CLI entry point for redteam-analyzer.

Typer app with scan, recon, report, config, and plugin commands.
"""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
import yaml
from rich.console import Console

from redteam_analyzer.core.engine import Engine
from redteam_analyzer.core.models import ScanConfig, ScopeConfig, Target
from redteam_analyzer.core.plugin_manager import PluginManager
from redteam_analyzer.cli.output import (
    console,
    create_findings_table,
    create_progress_bar,
    print_finding,
    print_summary,
)
from redteam_analyzer.utils.external_tools import parse_nmap_progress
from redteam_analyzer.cli.terminal import open_new_terminal, build_rta_command

app = typer.Typer(
    name="redteam-analyzer",
    help="Red team security analysis tool — reconnaissance, scanning, vulnerability detection, and reporting.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Subcommands
plugin_app = typer.Typer(help="Manage and list scan plugins.")
config_app = typer.Typer(help="Configuration management.")
app.add_typer(plugin_app, name="plugin")
app.add_typer(config_app, name="config")


def _load_config(config_path: Optional[str] = None) -> ScanConfig:
    """Load ScanConfig from YAML file or return defaults."""
    if config_path and Path(config_path).exists():
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
        scope = ScopeConfig(**data.pop("scope", {}))
        return ScanConfig(**data, scope=scope, config_path=config_path)
    return ScanConfig()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, hostname, URL, or CIDR"),
    modules: Optional[List[str]] = typer.Option(
        None, "--module", "-m", help="Modules to run (default: all)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    output_format: Optional[List[str]] = typer.Option(
        None, "--format", "-f", help="Output format: json, html, markdown"
    ),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Config file path"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-d", help="Show what would run without executing"
    ),
    auth_token: Optional[str] = typer.Option(
        None, "--auth-token", "-t", help="Auth token for intrusive modules"
    ),
    passive_only: bool = typer.Option(
        False, "--passive-only", "-p", help="Passive reconnaissance only"
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True,
        help="Verbosity: -v (findings), -vv (+ nmap progress), -vvv (+ raw nmap output)"
    ),
    new_terminal: bool = typer.Option(
        False, "--new-terminal", "-T", help="Open scan in a new terminal window"
    ),
    profile: str = typer.Option(
        "stealth", "--profile",
        help="Scan profile: stealth (quiet), normal, aggressive (noisy)"
    ),
) -> None:
    """Run a security scan against a target.

    Verbosity levels:
      -v    Show detailed findings after scan
      -vv   Also show nmap progress percentage
      -vvv  Also show raw nmap stderr output
    """
    # If --new-terminal, relaunch in new terminal and exit
    if new_terminal:
        cmd_args = ["scan", target]
        if modules:
            for m in modules:
                cmd_args.extend(["-m", m])
        if output:
            cmd_args.extend(["-o", output])
        if output_format:
            for fmt in output_format:
                cmd_args.extend(["-f", fmt])
        if config:
            cmd_args.extend(["-c", config])
        if dry_run:
            cmd_args.append("-d")
        if auth_token:
            cmd_args.extend(["-t", auth_token])
        if passive_only:
            cmd_args.append("-p")
        for _ in range(verbose):
            cmd_args.append("-v")

        full_cmd = build_rta_command(cmd_args)
        if open_new_terminal(full_cmd):
            console.print("[green]Scan opened in new terminal[/green]")
        else:
            console.print("[yellow]Could not open new terminal, running here[/yellow]")
        return

    # Build target
    target_obj = _parse_target(target)

    # Load config
    scan_config = _load_config(config)
    scan_config.dry_run = dry_run
    scan_config.auth_token = auth_token
    scan_config.passive_only = passive_only
    scan_config.scan_profile = profile
    if modules:
        scan_config.modules = modules
    if output:
        scan_config.output_path = output
    if output_format:
        scan_config.output_format = output_format

    # Execute scan
    console.print(f"[bold blue]Starting scan against:[/bold blue] {target_obj.primary}")

    if dry_run:
        console.print("[yellow]DRY RUN MODE — no network calls will be made[/yellow]")

    engine = Engine(scan_config)

    with create_progress_bar() as progress:
        task = progress.add_task("Scanning...", total=None)

        # Progress callback: parse nmap stderr and update progress display
        # Verbosity levels:
        #   0 = just spinner (default)
        #   1 = show port discoveries and key events
        #   2 = show percentage progress
        #   3 = show raw nmap output
        def _on_progress(line: str):
            info = parse_nmap_progress(line)
            if not info:
                return

            if info["type"] == "progress":
                # Percentage progress: "SYN Stealth Scan: 15.35% done"
                pct = info["percent"]
                phase = info["scan_phase"]
                remaining = info["remaining"]
                if verbose >= 2:
                    progress.update(
                        task,
                        description=f"[cyan]{phase}[/cyan] {pct:.1f}% done (ETA {remaining})",
                    )
                elif verbose >= 1:
                    progress.update(task, description=f"{phase}: {pct:.1f}%")

            elif info["type"] == "scanning":
                progress.update(task, description=f"Scanning {info['ports']} ports...")

            elif info["type"] == "port_found":
                if verbose >= 1:
                    console.print(f"  [green]+ Port {info['port']}/{info['protocol']} open[/green]")

            elif info["type"] == "completed":
                progress.update(task, description=f"Done in {info['elapsed']}s")

            elif info["type"] == "stats":
                if verbose >= 2:
                    progress.update(
                        task,
                        description=f"Elapsed {info['elapsed']} | {info['current_scan']}",
                    )

            elif info["type"] == "delay_increase":
                if verbose >= 2:
                    console.print(
                        f"  [yellow]! Network delay increased: {info['from_ms']}→{info['to_ms']}ms[/yellow]"
                    )

            elif info["type"] == "info" and verbose >= 3:
                raw = info.get("raw", "")
                if len(raw) > 70:
                    raw = raw[:67] + "..."
                progress.update(task, description=raw)

        scan_config.on_progress = _on_progress
        result = asyncio.run(engine.scan(target_obj))
        progress.update(task, completed=True, description="Scan complete")

    # Output results
    print_summary(result)

    if result.findings:
        table = create_findings_table(result.findings)
        console.print(table)

        if verbose >= 1:
            console.print("\n[bold]Detailed Findings:[/bold]")
            for finding in result.findings:
                print_finding(finding)

    # Save report if output specified
    if output:
        console.print(f"\n[green]Report saved to: {output}[/green]")


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target hostname or domain"),
    passive_only: bool = typer.Option(
        False, "--passive-only", "-p", help="Passive recon only (no direct requests)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True,
        help="Verbosity: -v (findings), -vv (+ details)"
    ),
    new_terminal: bool = typer.Option(
        False, "--new-terminal", "-T", help="Open recon in a new terminal window"
    ),
) -> None:
    """Run reconnaissance against a target."""
    # If --new-terminal, relaunch in new terminal and exit
    if new_terminal:
        cmd_args = ["recon", target]
        if passive_only:
            cmd_args.append("-p")
        if output:
            cmd_args.extend(["-o", output])
        for _ in range(verbose):
            cmd_args.append("-v")

        full_cmd = build_rta_command(cmd_args)
        if open_new_terminal(full_cmd):
            console.print("[green]Recon opened in new terminal[/green]")
        else:
            console.print("[yellow]Could not open new terminal, running here[/yellow]")
        return

    target_obj = _parse_target(target)
    
    config = ScanConfig(
        modules=["recon"],
        passive_only=passive_only,
        output_path=output,
    )
    
    console.print(f"[bold blue]Starting recon against:[/bold blue] {target_obj.primary}")
    
    engine = Engine(config)
    
    with create_progress_bar() as progress:
        task = progress.add_task("Reconning...", total=None)
        result = asyncio.run(engine.scan(target_obj))
        progress.update(task, completed=True)
    
    print_summary(result)
    
    if result.findings:
        table = create_findings_table(result.findings)
        console.print(table)
        
        if verbose >= 1:
            for finding in result.findings:
                print_finding(finding)


@app.command()
def report(
    file: str = typer.Argument(..., help="Scan results file (JSON) to generate report from"),
    format: List[str] = typer.Option(
        ["json"], "--format", "-f", help="Output format: json, html, markdown"
    ),
    template: str = typer.Option(
        "default", "--template", "-t", help="HTML template: default or executive"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
) -> None:
    """Generate a report from existing scan results."""
    import json
    
    result_path = Path(file)
    if not result_path.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(code=1)
    
    # Load scan results from JSON
    with open(result_path, "r") as f:
        data = json.load(f)
    
    # Reconstruct ScanResult
    from redteam_analyzer.core.models import Finding, ScanMetadata, Severity, FindingType, Evidence
    
    target_data = data.get("target", {})
    target_obj = Target(**target_data)
    
    findings = []
    for f_data in data.get("findings", []):
        evidence_data = f_data.pop("evidence", {})
        evidence = Evidence(**evidence_data) if evidence_data else Evidence()
        f_data["type"] = FindingType(f_data["type"])
        f_data["severity"] = Severity(f_data["severity"])
        f_data["evidence"] = evidence
        findings.append(Finding(**f_data))
    
    metadata = []
    for m_data in data.get("metadata", []):
        metadata.append(ScanMetadata(**m_data))
    
    scan_result = ScanResult(
        target=target_obj,
        findings=findings,
        metadata=metadata,
        errors=data.get("errors", []),
    )
    
    config = ScanConfig(
        modules=["report"],
        output_format=format,
        output_path=output,
        report_template=template,
        scan_results=scan_result,
    )
    
    console.print(f"[bold blue]Generating report from:[/bold blue] {file}")
    
    from redteam_analyzer.modules.report.plugin import ReportPlugin
    plugin = ReportPlugin()
    asyncio.run(plugin.run(target_obj, config))
    
    if output:
        console.print(f"[green]Report saved to: {output}[/green]")
    else:
        console.print("[yellow]Report printed to stdout[/yellow]")


@config_app.command("validate")
def config_validate(
    config_path: str = typer.Argument("config.yaml", help="Config file to validate"),
) -> None:
    """Validate a configuration file."""
    path = Path(config_path)
    if not path.exists():
        console.print(f"[red]Config file not found: {config_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        
        if not isinstance(data, dict):
            console.print("[red]Invalid config: root must be a mapping[/red]")
            raise typer.Exit(code=1)
        
        # Try to construct ScanConfig
        scope_data = data.pop("scope", {})
        scope = ScopeConfig(**scope_data)
        config = ScanConfig(**data, scope=scope)
        
        console.print(f"[green]Config file is valid: {config_path}[/green]")
        console.print(f"  Modules: {config.modules}")
        console.print(f"  Output format: {config.output_format}")
        console.print(f"  Dry run: {config.dry_run}")
    except Exception as e:
        console.print(f"[red]Config validation failed: {e}[/red]")
        raise typer.Exit(code=1)


@plugin_app.command("list")
def plugin_list() -> None:
    """List all available scan plugins."""
    pm = PluginManager()
    discovered = pm.discover_plugins()
    
    if not discovered:
        console.print("[yellow]No plugins found[/yellow]")
        return
    
    from rich.table import Table
    table = Table(title="Available Plugins")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Requires Auth")
    
    for name in sorted(discovered):
        plugin = pm.load_plugin(name)
        if plugin:
            table.add_row(
                name,
                plugin.description,
                "Yes" if plugin.requires_auth else "No",
            )
    
    console.print(table)


def _parse_target(target_str: str) -> Target:
    """Parse a target string into a Target object.
    
    Supports: IP, hostname, URL, CIDR.
    """
    import re
    
    # CIDR notation
    if "/" in target_str and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target_str):
        return Target(cidr=target_str)
    
    # URL
    if target_str.startswith(("http://", "https://")):
        return Target(url=target_str)
    
    # IP address
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target_str):
        return Target(ip=target_str)
    
    # Hostname/domain
    return Target(hostname=target_str)


if __name__ == "__main__":
    app()