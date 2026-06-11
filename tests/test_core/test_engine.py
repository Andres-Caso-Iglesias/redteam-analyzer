"""Tests for the scan engine."""

import pytest

from redteam_analyzer.core.engine import Engine
from redteam_analyzer.core.models import ScanConfig, ScanResult, ScopeConfig, Target
from redteam_analyzer.core.scope import ScopeError
from redteam_analyzer.modules.base import BasePlugin


class MockPlugin(BasePlugin):
    """Mock plugin for testing."""

    name = "mock"
    description = "Mock plugin"
    requires_auth = False

    async def run(self, target, config):
        from redteam_analyzer.core.models import Finding, FindingType, Severity

        return ScanResult(
            target=target,
            findings=[
                Finding(
                    type=FindingType.PORT_OPEN,
                    severity=Severity.INFO,
                    location=f"{target.primary}:80",
                    title="Mock finding",
                )
            ],
        )

    def validate_dependencies(self):
        return True


class FailingPlugin(BasePlugin):
    """Plugin that raises an exception."""

    name = "failing"
    description = "Failing plugin"
    requires_auth = False

    async def run(self, target, config):
        raise RuntimeError("Plugin failed intentionally")

    def validate_dependencies(self):
        return True


class AuthPlugin(BasePlugin):
    """Plugin that requires auth."""

    name = "auth_required"
    description = "Auth required plugin"
    requires_auth = True

    async def run(self, target, config):
        return ScanResult(target=target)

    def validate_dependencies(self):
        return True


@pytest.fixture
def config():
    return ScanConfig(
        dry_run=False,
        scope=ScopeConfig(allowed_cidrs=["127.0.0.0/8", "192.168.0.0/16"]),
    )


@pytest.fixture
def target():
    return Target(ip="127.0.0.1")


class TestEngine:
    def test_engine_init(self, config):
        engine = Engine(config)
        assert engine.config == config
        assert len(engine.results) == 0

    @pytest.mark.asyncio
    async def test_dry_run(self, target):
        config = ScanConfig(dry_run=True, scope=ScopeConfig(), modules=["mock"])
        engine = Engine(config)
        engine.plugin_manager._plugin_classes = {"mock": MockPlugin}

        result = await engine.scan(target)

        assert isinstance(result, ScanResult)
        assert len(result.findings) == 0
        assert len(result.metadata) == 1  # mock plugin only
        assert result.metadata[0].dry_run is True
        assert result.metadata[0].plugin_name == "mock"

    @pytest.mark.asyncio
    async def test_scope_validation(self, config):
        engine = Engine(config)
        target = Target(ip="10.0.0.1")  # Not in allowed CIDRs

        with pytest.raises(ScopeError):
            await engine.scan(target)

    @pytest.mark.asyncio
    async def test_plugin_failure_handling(self, target):
        config = ScanConfig(
            scope=ScopeConfig(allowed_cidrs=["127.0.0.0/8"]),
            modules=["failing"],
        )
        engine = Engine(config)
        engine.plugin_manager._plugin_classes = {"failing": FailingPlugin}

        result = await engine.scan(target)

        # Should not crash, should record error
        assert len(result.errors) == 1
        assert "failing" in result.errors[0]

    @pytest.mark.asyncio
    async def test_sequential_execution(self, target):
        config = ScanConfig(
            scope=ScopeConfig(allowed_cidrs=["127.0.0.0/8"]),
            modules=["mock"],
        )
        engine = Engine(config)
        engine.plugin_manager._plugin_classes = {"mock": MockPlugin}

        result = await engine.scan(target)

        assert len(result.findings) == 1
        assert result.findings[0].title == "Mock finding"

    @pytest.mark.asyncio
    async def test_auth_filtering(self, target):
        config = ScanConfig(
            scope=ScopeConfig(allowed_cidrs=["127.0.0.0/8"]),
            modules=["auth_required"],
            auth_token=None,
        )
        engine = Engine(config)
        engine.plugin_manager._plugin_classes = {"auth_required": AuthPlugin}

        result = await engine.scan(target)

        # Auth plugin should be skipped
        assert len(result.findings) == 0
        # Should have skipped_no_auth in audit log
        entries = engine.audit_logger.get_entries(module="auth_required")
        assert len(entries) > 0

    @pytest.mark.asyncio
    async def test_auth_provided(self, target):
        config = ScanConfig(
            scope=ScopeConfig(allowed_cidrs=["127.0.0.0/8"]),
            modules=["auth_required"],
            auth_token="test-token",
        )
        engine = Engine(config)
        engine.plugin_manager._plugin_classes = {"auth_required": AuthPlugin}

        result = await engine.scan(target)

        # Auth plugin should run
        assert len(result.metadata) >= 1
