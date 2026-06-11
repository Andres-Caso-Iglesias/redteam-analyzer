"""End-to-end integration tests for the full scan pipeline."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from redteam_analyzer.core.engine import Engine
from redteam_analyzer.core.models import (
    Finding, FindingType, ScanConfig, ScanResult, Severity, Target, ScopeConfig
)


@pytest.fixture
def e2e_config():
    """Config for E2E tests — all modules, dry-run disabled but mocked."""
    scope = ScopeConfig(
        allowed_cidrs=["127.0.0.0/8", "192.168.0.0/16"],
        allowed_domains=["localhost", "example.com", "*.example.com"],
        rate_limit_per_second=100,
    )
    return ScanConfig(
        dry_run=False,
        modules=["recon", "scan", "vuln"],
        scope=scope,
    )


@pytest.mark.e2e
class TestEndToEndScan:
    """Full pipeline integration tests."""

    @pytest.mark.asyncio
    async def test_dry_run全流程(self, e2e_config):
        """Test complete scan flow in dry-run mode."""
        e2e_config.dry_run = True
        engine = Engine(e2e_config)
        target = Target(hostname="example.com")

        result = await engine.scan(target)

        assert isinstance(result, ScanResult)
        assert result.target.hostname == "example.com"
        assert len(result.metadata) == len(e2e_config.modules)
        assert all(m.dry_run for m in result.metadata)

    @pytest.mark.asyncio
    async def test_scan_plugin_failure_does_not_crash(self, e2e_config):
        """Test that one plugin failing doesn't crash the entire scan."""
        engine = Engine(e2e_config)
        target = Target(hostname="example.com")

        failing_plugin = MagicMock()
        failing_plugin.name = "recon"
        failing_plugin.requires_auth = False
        failing_plugin.run = AsyncMock(side_effect=Exception("Plugin crashed"))

        ok_plugin = MagicMock()
        ok_plugin.name = "scan"
        ok_plugin.requires_auth = False
        ok_plugin.run = AsyncMock(return_value=ScanResult(
            target=target,
            findings=[Finding(
                type=FindingType.PORT_OPEN,
                severity=Severity.INFO,
                location="example.com:80",
                title="Port 80 open",
            )],
        ))

        with patch.object(engine.plugin_manager, 'load_plugin') as mock_load:
            def side_effect(name):
                if name == "recon":
                    return failing_plugin
                elif name == "scan":
                    return ok_plugin
                return None
            mock_load.side_effect = side_effect

            with patch.object(engine.plugin_manager, 'get_available_plugins', return_value=["recon", "scan"]):
                result = await engine.scan(target)

        assert isinstance(result, ScanResult)
        assert len(result.errors) > 0
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scope_violation_stops_scan(self, e2e_config):
        """Test that out-of-scope target raises ScopeError."""
        from redteam_analyzer.core.scope import ScopeError

        engine = Engine(e2e_config)
        target = Target(hostname="evil.com")

        with pytest.raises(ScopeError):
            await engine.scan(target)

    @pytest.mark.asyncio
    async def test_unauthorized_plugin_filtered(self):
        """Test that intrusive plugins are skipped without auth token."""
        scope = ScopeConfig(
            allowed_domains=["example.com"],
            rate_limit_per_second=100,
        )
        config = ScanConfig(
            dry_run=False,
            modules=["recon", "vuln"],
            scope=scope,
            auth_token=None,
        )
        engine = Engine(config)
        target = Target(hostname="example.com")

        recon_plugin = MagicMock()
        recon_plugin.name = "recon"
        recon_plugin.requires_auth = False
        recon_plugin.run = AsyncMock(return_value=ScanResult(target=target))

        vuln_plugin = MagicMock()
        vuln_plugin.name = "vuln"
        vuln_plugin.requires_auth = True
        vuln_plugin.run = AsyncMock(return_value=ScanResult(target=target))

        with patch.object(engine.plugin_manager, 'load_plugin') as mock_load:
            mock_load.side_effect = lambda name: recon_plugin if name == "recon" else vuln_plugin
            with patch.object(engine.plugin_manager, 'get_available_plugins', return_value=["recon", "vuln"]):
                result = await engine.scan(target)

        vuln_plugin.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_findings_merge_deduplication(self, e2e_config):
        """Test that merged findings are deduplicated."""
        engine = Engine(e2e_config)
        target = Target(hostname="example.com")

        finding = Finding(
            type=FindingType.PORT_OPEN,
            severity=Severity.INFO,
            location="example.com:443",
            title="HTTPS port open",
        )

        result1 = ScanResult(target=target, findings=[finding])
        result2 = ScanResult(target=target, findings=[finding])

        merged = result1.merge(result2)

        assert len(merged.findings) == 1

    @pytest.mark.asyncio
    async def test_audit_log_records_actions(self, e2e_config):
        """Test that engine actions are recorded in audit log."""
        e2e_config.dry_run = True
        engine = Engine(e2e_config)
        target = Target(hostname="example.com")

        await engine.scan(target)

        entries = engine.audit_logger.entries
        assert len(entries) > 0

        actions = [e.action for e in entries]
        assert "scan_start" in actions
        # dry_run returns before scan_complete — verify dry_run actions exist
        assert "dry_run" in actions
