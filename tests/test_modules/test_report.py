"""Tests for report generation plugin."""

import json
import pytest
from pathlib import Path

from redteam_analyzer.core.models import (
    Evidence,
    Finding,
    FindingType,
    ScanConfig,
    ScanResult,
    ScanMetadata,
    ScopeConfig,
    Severity,
    Target,
)
from redteam_analyzer.modules.report.plugin import ReportPlugin


@pytest.fixture
def target():
    return Target(ip="192.168.1.1", hostname="example.com")


@pytest.fixture
def findings():
    return [
        Finding(
            type=FindingType.VULN_CVE,
            severity=Severity.CRITICAL,
            location="192.168.1.1:443",
            title="CVE-2021-41773: Apache Path Traversal",
            description="Apache HTTP Server path traversal vulnerability",
            cve_id="CVE-2021-41773",
            cvss_score=9.8,
            remediation="Update Apache to latest version",
        ),
        Finding(
            type=FindingType.PORT_OPEN,
            severity=Severity.HIGH,
            location="192.168.1.1:22",
            title="Port 22/tcp open (SSH)",
            description="SSH service detected",
        ),
        Finding(
            type=FindingType.TECH_DETECTED,
            severity=Severity.INFO,
            location="http://example.com",
            title="Server detected: nginx/1.18.0",
            description="Server header reveals nginx",
        ),
    ]


@pytest.fixture
def scan_result(target, findings):
    return ScanResult(
        target=target,
        findings=findings,
        metadata=[
            ScanMetadata(
                plugin_name="recon",
                duration_seconds=1.5,
                timestamp="2024-01-01T00:00:00Z",
            ),
            ScanMetadata(
                plugin_name="scan",
                duration_seconds=10.2,
                timestamp="2024-01-01T00:00:10Z",
            ),
        ],
        errors=[],
    )


@pytest.fixture
def config(scan_result):
    return ScanConfig(
        scope=ScopeConfig(),
        output_format=["json", "html", "markdown"],
        scan_results=scan_result,
    )


class TestReportPlugin:
    def test_plugin_init(self):
        plugin = ReportPlugin()
        assert plugin.name == "report"
        assert plugin.requires_auth is False

    def test_validate_dependencies(self):
        plugin = ReportPlugin()
        assert plugin.validate_dependencies() is True

    @pytest.mark.asyncio
    async def test_generate_json_to_stdout(self, target, config):
        plugin = ReportPlugin()
        result = await plugin.run(target, config)

        assert isinstance(result, ScanResult)
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_generate_json_to_file(self, target, config, tmp_path):
        config.output_path = str(tmp_path / "report.json")
        plugin = ReportPlugin()

        result = await plugin.run(target, config)

        assert len(result.errors) == 0
        report_path = tmp_path / "report.json"
        assert report_path.exists()

        # Verify JSON content
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert "target" in data
        assert "findings" in data
        assert len(data["findings"]) == 3

    @pytest.mark.asyncio
    async def test_generate_html_to_file(self, target, scan_result, tmp_path):
        config = ScanConfig(
            scope=ScopeConfig(),
            output_format=["html"],
            output_path=str(tmp_path / "report.html"),
            scan_results=scan_result,
        )
        plugin = ReportPlugin()

        result = await plugin.run(target, config)

        assert len(result.errors) == 0
        report_path = tmp_path / "report.html"
        assert report_path.exists()

        html_content = report_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_content
        assert "example.com" in html_content
        assert "CVE-2021-41773" in html_content

    @pytest.mark.asyncio
    async def test_generate_html_executive(self, target, scan_result, tmp_path):
        config = ScanConfig(
            scope=ScopeConfig(),
            output_format=["html"],
            output_path=str(tmp_path / "exec.html"),
            scan_results=scan_result,
        )
        config.report_template = "executive"
        plugin = ReportPlugin()

        result = await plugin.run(target, config)

        assert len(result.errors) == 0
        report_path = tmp_path / "exec.html"
        assert report_path.exists()

        html_content = report_path.read_text(encoding="utf-8")
        assert "Executive Summary" in html_content

    @pytest.mark.asyncio
    async def test_generate_markdown_to_file(self, target, scan_result, tmp_path):
        config = ScanConfig(
            scope=ScopeConfig(),
            output_format=["markdown"],
            output_path=str(tmp_path / "report.md"),
            scan_results=scan_result,
        )
        plugin = ReportPlugin()

        result = await plugin.run(target, config)

        assert len(result.errors) == 0
        report_path = tmp_path / "report.md"
        assert report_path.exists()

        md_content = report_path.read_text(encoding="utf-8")
        assert "# Red Team Report" in md_content
        assert "CVE-2021-41773" in md_content
        assert "CRITICAL" in md_content

    @pytest.mark.asyncio
    async def test_no_results(self, target):
        config = ScanConfig(scope=ScopeConfig(), output_format=["json"])
        plugin = ReportPlugin()

        result = await plugin.run(target, config)

        # Should not crash, just warn
        assert isinstance(result, ScanResult)

    def test_build_summary(self):
        plugin = ReportPlugin()
        scan_result = ScanResult(
            target=Target(ip="1.2.3.4"),
            findings=[
                Finding(type=FindingType.PORT_OPEN, severity=Severity.CRITICAL, location="a", title="c"),
                Finding(type=FindingType.PORT_OPEN, severity=Severity.HIGH, location="b", title="h"),
                Finding(type=FindingType.PORT_OPEN, severity=Severity.INFO, location="c", title="i"),
            ],
        )

        summary = plugin._build_summary(scan_result)

        assert summary["total_findings"] == 3
        assert summary["critical_count"] == 1
        assert summary["high_count"] == 1
        assert summary["info_count"] == 1

    @pytest.mark.asyncio
    async def test_multiple_formats(self, target, scan_result, tmp_path):
        config = ScanConfig(
            scope=ScopeConfig(),
            output_format=["json", "html", "markdown"],
            output_path=str(tmp_path / "report"),
            scan_results=scan_result,
        )
        plugin = ReportPlugin()

        result = await plugin.run(target, config)

        assert len(result.errors) == 0
