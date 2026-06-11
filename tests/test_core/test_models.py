"""Tests for core data models."""

import pytest

from redteam_analyzer.core.models import (
    Evidence,
    Finding,
    FindingType,
    OutputFormat,
    ScanConfig,
    ScanMetadata,
    ScanResult,
    ScopeConfig,
    Severity,
    Target,
    ToolInfo,
)


class TestTarget:
    def test_target_with_ip(self):
        target = Target(ip="192.168.1.1")
        assert target.primary == "192.168.1.1"
        assert target.domain is None

    def test_target_with_hostname(self):
        target = Target(hostname="example.com")
        assert target.primary == "example.com"
        assert target.domain == "example.com"

    def test_target_with_url(self):
        target = Target(url="https://example.com/path")
        assert target.primary == "https://example.com/path"
        assert target.domain == "example.com"

    def test_target_priority(self):
        # URL takes priority over hostname over IP
        target = Target(ip="1.2.3.4", hostname="example.com", url="https://test.com")
        assert target.primary == "https://test.com"

    def test_target_empty(self):
        target = Target()
        assert target.primary == ""


class TestFinding:
    def test_finding_creation(self):
        finding = Finding(
            type=FindingType.PORT_OPEN,
            severity=Severity.HIGH,
            location="192.168.1.1:443",
            title="Open port 443",
        )
        assert finding.type == FindingType.PORT_OPEN
        assert finding.severity == Severity.HIGH
        assert finding.cvss_score is None

    def test_finding_with_cvss(self):
        finding = Finding(
            type=FindingType.VULN_CVE,
            severity=Severity.CRITICAL,
            location="192.168.1.1:443",
            title="CVE-2024-1234",
            cvss_score=9.8,
            cve_id="CVE-2024-1234",
        )
        assert finding.cvss_score == 9.8
        assert finding.cve_id == "CVE-2024-1234"

    def test_finding_severity_serialization(self):
        finding = Finding(
            type=FindingType.PORT_OPEN,
            severity=Severity.CRITICAL,
            location="test",
            title="test",
        )
        data = finding.model_dump()
        assert data["severity"] == "critical"

    def test_finding_default_evidence(self):
        finding = Finding(
            type=FindingType.PORT_OPEN,
            severity=Severity.INFO,
            location="test",
            title="test",
        )
        assert finding.evidence.raw_output == ""
        assert finding.evidence.structured_data == {}


class TestScanResult:
    def test_empty_scan_result(self):
        target = Target(ip="127.0.0.1")
        result = ScanResult(target=target)
        assert len(result.findings) == 0
        assert len(result.metadata) == 0
        assert len(result.errors) == 0

    def test_merge_results(self):
        target = Target(ip="127.0.0.1")
        r1 = ScanResult(
            target=target,
            findings=[
                Finding(type=FindingType.PORT_OPEN, severity=Severity.INFO, location="127.0.0.1:80", title="Port 80"),
            ],
        )
        r2 = ScanResult(
            target=target,
            findings=[
                Finding(type=FindingType.PORT_OPEN, severity=Severity.INFO, location="127.0.0.1:443", title="Port 443"),
            ],
        )
        merged = r1.merge(r2)
        assert len(merged.findings) == 2

    def test_merge_deduplicates(self):
        target = Target(ip="127.0.0.1")
        finding = Finding(type=FindingType.PORT_OPEN, severity=Severity.INFO, location="127.0.0.1:80", title="Port 80")
        r1 = ScanResult(target=target, findings=[finding])
        r2 = ScanResult(target=target, findings=[finding])
        merged = r1.merge(r2)
        assert len(merged.findings) == 1

    def test_merge_preserves_metadata(self):
        target = Target(ip="127.0.0.1")
        m1 = ScanMetadata(plugin_name="recon", duration_seconds=1.0, timestamp="2024-01-01T00:00:00Z")
        m2 = ScanMetadata(plugin_name="scan", duration_seconds=2.0, timestamp="2024-01-01T00:00:01Z")
        r1 = ScanResult(target=target, metadata=[m1])
        r2 = ScanResult(target=target, metadata=[m2])
        merged = r1.merge(r2)
        assert len(merged.metadata) == 2


class TestScopeConfig:
    def test_default_scope(self):
        config = ScopeConfig()
        assert config.allowed_cidrs == []
        assert config.rate_limit_per_second == 10

    def test_custom_scope(self):
        config = ScopeConfig(
            allowed_cidrs=["10.0.0.0/8"],
            rate_limit_per_second=50,
        )
        assert config.allowed_cidrs == ["10.0.0.0/8"]
        assert config.rate_limit_per_second == 50


class TestScanConfig:
    def test_default_config(self):
        config = ScanConfig()
        assert config.dry_run is False
        assert config.auth_token is None
        assert "recon" in config.modules

    def test_config_with_auth(self):
        config = ScanConfig(auth_token="abc123")
        assert config.auth_token == "abc123"


class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_finding_type_values(self):
        assert FindingType.PORT_OPEN == "port_open"
        assert FindingType.VULN_CVE == "vuln_cve"

    def test_output_format_values(self):
        assert OutputFormat.JSON == "json"
        assert OutputFormat.HTML == "html"
        assert OutputFormat.MARKDOWN == "markdown"


class TestToolInfo:
    def test_tool_not_installed(self):
        tool = ToolInfo(name="nmap")
        assert tool.installed is False
        assert tool.path is None

    def test_tool_installed(self):
        tool = ToolInfo(name="nmap", path="/usr/bin/nmap", installed=True, version="7.94")
        assert tool.installed is True
        assert tool.version == "7.94"
