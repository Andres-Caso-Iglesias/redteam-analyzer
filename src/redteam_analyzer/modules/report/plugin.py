"""Report generation plugin for redteam-analyzer.

Exports scan results to JSON, HTML, and Markdown formats.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template

from redteam_analyzer.core.models import (
    ScanConfig,
    ScanMetadata,
    ScanResult,
    Severity,
    Target,
)
from redteam_analyzer.modules.base import BasePlugin
from redteam_analyzer.modules.report.templates import DEFAULT_TEMPLATE, EXECUTIVE_TEMPLATE

logger = logging.getLogger(__name__)


class ReportPlugin(BasePlugin):
    """Report generation plugin supporting JSON, HTML, and Markdown."""

    name = "report"
    description = "Generate reports in JSON, HTML, and Markdown formats"
    requires_auth = False

    async def run(self, target: Target, config: ScanConfig) -> ScanResult:
        """Generate report from scan results.

        Args:
            target: Target that was scanned
            config: Scan configuration with results data

        Returns:
            ScanResult with report metadata
        """
        start_time = time.time()
        errors = []

        # Get scan results from config (passed by engine)
        scan_results = getattr(config, "scan_results", None)

        # Determine output formats
        formats = config.output_format or ["json"]
        output_path = config.output_path

        # Generate reports
        for fmt in formats:
            try:
                if fmt == "json":
                    self._generate_json(scan_results, target, output_path)
                elif fmt == "html":
                    template = getattr(config, "report_template", "default")
                    self._generate_html(scan_results, target, output_path, template)
                elif fmt == "markdown":
                    self._generate_markdown(scan_results, target, output_path)
                else:
                    logger.warning(f"Unknown format: {fmt}")
            except Exception as e:
                error_msg = f"Failed to generate {fmt} report: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        # Build result
        duration = time.time() - start_time
        metadata = ScanMetadata(
            plugin_name=self.name,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            dry_run=config.dry_run,
        )

        return ScanResult(
            target=target,
            findings=[],
            metadata=[metadata],
            errors=errors,
        )

    def _generate_json(
        self,
        scan_results: Optional[ScanResult],
        target: Target,
        output_path: Optional[str],
    ) -> None:
        """Generate JSON report.

        Args:
            scan_results: Scan results to export
            target: Target scanned
            output_path: Output file path
        """
        if not scan_results:
            logger.warning("No scan results to export")
            return

        # Build report data
        report = {
            "target": target.model_dump(),
            "findings": [f.model_dump() for f in scan_results.findings],
            "metadata": [m.model_dump() for m in scan_results.metadata],
            "errors": scan_results.errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": self._build_summary(scan_results),
        }

        # Output
        if output_path:
            path = Path(output_path)
            # Ensure correct extension
            if path.suffix != ".json":
                path = path.parent / (path.name + ".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            logger.info(f"JSON report saved to {path}")
        else:
            print(json.dumps(report, indent=2, default=str))

    def _generate_html(
        self,
        scan_results: Optional[ScanResult],
        target: Target,
        output_path: Optional[str],
        template_name: str = "default",
    ) -> None:
        """Generate HTML report.

        Args:
            scan_results: Scan results to export
            target: Target scanned
            output_path: Output file path
            template_name: Template to use ("default" or "executive")
        """
        if not scan_results:
            logger.warning("No scan results to export")
            return

        # Select template
        if template_name == "executive":
            template_str = EXECUTIVE_TEMPLATE
        else:
            template_str = DEFAULT_TEMPLATE

        template = Template(template_str)

        # Build context
        summary = self._build_summary(scan_results)
        context = {
            "target": target.primary,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "findings": scan_results.findings,
            "metadata": scan_results.metadata,
            "errors": scan_results.errors,
            "version": "0.1.0",
            **summary,
        }

        # Render
        html = template.render(**context)

        # Output
        if output_path:
            path = Path(output_path)
            # Ensure correct extension
            if path.suffix != ".html":
                path = path.parent / (path.name + ".html")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html, encoding="utf-8")
            logger.info(f"HTML report saved to {path}")
        else:
            print(html)

    def _generate_markdown(
        self,
        scan_results: Optional[ScanResult],
        target: Target,
        output_path: Optional[str],
    ) -> None:
        """Generate Markdown report.

        Args:
            scan_results: Scan results to export
            target: Target scanned
            output_path: Output file path
        """
        if not scan_results:
            logger.warning("No scan results to export")
            return

        summary = self._build_summary(scan_results)

        # Build markdown
        lines = [
            f"# Red Team Report — {target.primary}",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | {summary['total_findings']} |",
            f"| Critical | {summary['critical_count']} |",
            f"| High | {summary['high_count']} |",
            f"| Medium | {summary['medium_count']} |",
            f"| Low | {summary['low_count']} |",
            f"| Info | {summary['info_count']} |",
            "",
        ]

        # Findings by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_findings = [
                f for f in scan_results.findings if f.severity.value == severity
            ]
            if severity_findings:
                lines.extend([
                    f"## {severity.upper()} ({len(severity_findings)})",
                    "",
                ])
                for finding in severity_findings:
                    lines.extend([
                        f"### {finding.title}",
                        "",
                        f"- **Location:** `{finding.location}`",
                        f"- **Type:** {finding.type.value}",
                    ])
                    if finding.cve_id:
                        lines.append(f"- **CVE:** {finding.cve_id}")
                    if finding.cvss_score:
                        lines.append(f"- **CVSS:** {finding.cvss_score}")
                    if finding.description:
                        lines.extend(["", finding.description])
                    if finding.remediation:
                        lines.extend(["", f"**Remediation:** {finding.remediation}"])
                    lines.extend(["", "---", ""])

        # Metadata
        if scan_results.metadata:
            lines.extend([
                "## Scan Metadata",
                "",
                "| Plugin | Duration | Timestamp |",
                "|--------|----------|-----------|",
            ])
            for meta in scan_results.metadata:
                lines.append(
                    f"| {meta.plugin_name} | {meta.duration_seconds}s | {meta.timestamp} |"
                )
            lines.extend(["", ""])

        # Errors
        if scan_results.errors:
            lines.extend(["## Errors", ""])
            for error in scan_results.errors:
                lines.append(f"- {error}")
            lines.extend(["", ""])

        # Footer
        lines.extend([
            "---",
            f"*Generated by redteam-analyzer v0.1.0*",
        ])

        markdown = "\n".join(lines)

        # Output
        if output_path:
            path = Path(output_path)
            # Ensure correct extension
            if path.suffix != ".md":
                path = path.parent / (path.name + ".md")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            logger.info(f"Markdown report saved to {path}")
        else:
            print(markdown)

    def _build_summary(self, scan_results: ScanResult) -> Dict[str, Any]:
        """Build summary statistics from scan results.

        Args:
            scan_results: Scan results

        Returns:
            Summary dictionary
        """
        findings = scan_results.findings
        return {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high_count": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium_count": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low_count": sum(1 for f in findings if f.severity == Severity.LOW),
            "info_count": sum(1 for f in findings if f.severity == Severity.INFO),
        }

    def validate_dependencies(self) -> bool:
        """Check if Jinja2 is available.

        Returns:
            True if dependencies are met
        """
        try:
            import jinja2

            return True
        except ImportError:
            logger.error("Jinja2 is required for HTML report generation")
            return False
