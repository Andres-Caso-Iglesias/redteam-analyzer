"""Tests for vulnerability scanning plugin."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from redteam_analyzer.core.models import ScanConfig, ScanResult, ScopeConfig, Target
from redteam_analyzer.modules.vuln.cve_matcher import match_cves, _version_compare
from redteam_analyzer.modules.vuln.nuclei_wrapper import (
    parse_nuclei_jsonl,
    is_intrusive,
    _parse_nuclei_entry,
)
from redteam_analyzer.modules.vuln.plugin import VulnPlugin
from redteam_analyzer.utils.external_tools import ToolNotFoundError


class TestCveMatcher:
    def test_match_known_cve(self):
        findings = match_cves("nginx", "1.18.0")
        assert len(findings) > 0
        assert findings[0].cve_id == "CVE-2021-23017"
        assert findings[0].severity.value == "high"

    def test_match_no_cve(self):
        findings = match_cves("nginx", "99.0.0")
        assert len(findings) == 0

    def test_match_unknown_product(self):
        findings = match_cves("unknown-product", "1.0.0")
        assert len(findings) == 0

    def test_match_case_insensitive(self):
        findings = match_cves("Nginx", "1.18.0")
        assert len(findings) > 0

    def test_match_apache_critical(self):
        findings = match_cves("apache", "2.4.49")
        assert len(findings) > 0
        assert findings[0].cve_id == "CVE-2021-41773"
        assert findings[0].severity.value == "critical"

    def test_version_compare(self):
        assert _version_compare("1.18.0", "1.17.0") == 1
        assert _version_compare("1.17.0", "1.18.0") == -1
        assert _version_compare("1.18.0", "1.18.0") == 0

    def test_version_compare_partial(self):
        assert _version_compare("1.18", "1.17") == 1


SAMPLE_NUCLEI_OUTPUT = """{"template-id":"cve-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical","description":"Apache HTTP Server path traversal","classification":{"cve-id":"CVE-2021-41773","cvss-score":"9.8"}},"matched-at":"http://example.com/cgi-bin/test","host":"http://example.com"}
{"template-id":"tech-detect-nginx","info":{"name":"Nginx Detected","severity":"info"},"matched-at":"http://example.com","host":"http://example.com"}"""


class TestNucleiWrapper:
    def test_parse_nuclei_jsonl(self):
        results = parse_nuclei_jsonl(SAMPLE_NUCLEI_OUTPUT)

        assert len(results["findings"]) == 2
        assert results["findings"][0].cve_id == "CVE-2021-41773"
        assert results["findings"][0].severity.value == "critical"
        assert results["findings"][1].severity.value == "info"

    def test_parse_nuclei_empty(self):
        results = parse_nuclei_jsonl("")
        assert len(results["findings"]) == 0

    def test_parse_nuclei_invalid(self):
        results = parse_nuclei_jsonl("not json\nalso not json")
        assert len(results["findings"]) == 0

    def test_is_intrusive_sqli(self):
        assert is_intrusive(tags=["sqli"]) is True
        assert is_intrusive(tags=["xss"]) is True
        assert is_intrusive(tags=["info"]) is False

    def test_is_intrusive_templates(self):
        assert is_intrusive(templates="cves/") is False
        assert is_intrusive(templates="vulnerabilities/sqli/") is True

    def test_parse_nuclei_entry_valid(self):
        entry = {
            "template-id": "test-template",
            "info": {
                "name": "Test Vulnerability",
                "severity": "high",
                "description": "A test vulnerability",
            },
            "matched-at": "http://test.com",
        }
        finding = _parse_nuclei_entry(entry)
        assert finding is not None
        assert finding.title == "Test Vulnerability"
        assert finding.severity.value == "high"

    def test_parse_nuclei_entry_no_template(self):
        entry = {"info": {"name": "Test"}}
        finding = _parse_nuclei_entry(entry)
        assert finding is None


class TestVulnPlugin:
    def test_plugin_init(self):
        plugin = VulnPlugin()
        assert plugin.name == "vuln"
        assert plugin.requires_auth is False

    @pytest.mark.asyncio
    async def test_plugin_run_nuclei(self):
        plugin = VulnPlugin()
        target = Target(url="http://example.com")
        config = ScanConfig(scope=ScopeConfig())

        from redteam_analyzer.core.models import Evidence, Finding, FindingType, Severity

        with patch("redteam_analyzer.modules.vuln.plugin.run_nuclei") as mock_nuclei:
            mock_nuclei.return_value = {
                "findings": [
                    Finding(
                        type=FindingType.VULN_NUCLEI,
                        severity=Severity.HIGH,
                        location="http://example.com",
                        title="Test Vuln",
                        description="A test vulnerability",
                    )
                ]
            }

            result = await plugin.run(target, config)

            assert isinstance(result, ScanResult)
            assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_plugin_run_nuclei_not_installed(self):
        plugin = VulnPlugin()
        target = Target(url="http://example.com")
        config = ScanConfig(scope=ScopeConfig())

        with patch("redteam_analyzer.modules.vuln.plugin.run_nuclei") as mock_nuclei:
            mock_nuclei.side_effect = ToolNotFoundError("nuclei")

            result = await plugin.run(target, config)

            assert len(result.errors) > 0
            assert "not installed" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_plugin_skips_intrusive_without_auth(self):
        plugin = VulnPlugin()
        target = Target(url="http://example.com")
        config = ScanConfig(scope=ScopeConfig(), auth_token=None)
        config.nuclei_config = {"tags": ["sqli"]}

        result = await plugin.run(target, config)

        # Should skip intrusive scan
        assert len(result.errors) > 0
        assert any("skipped" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_plugin_run_intrusive_with_auth(self):
        plugin = VulnPlugin()
        target = Target(url="http://example.com")
        config = ScanConfig(scope=ScopeConfig(), auth_token="test-token")
        config.nuclei_config = {"tags": ["sqli"]}

        with patch("redteam_analyzer.modules.vuln.plugin.run_nuclei") as mock_nuclei:
            mock_nuclei.return_value = {"findings": []}

            result = await plugin.run(target, config)

            assert isinstance(result, ScanResult)
            mock_nuclei.assert_called_once()
