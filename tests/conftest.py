"""Shared pytest fixtures for redteam-analyzer tests."""

import pytest

from redteam_analyzer.core.models import ScanConfig, ScopeConfig, Target


@pytest.fixture
def local_target():
    """Target pointing to localhost."""
    return Target(ip="127.0.0.1", hostname="localhost")


@pytest.fixture
def remote_target():
    """Target pointing to a remote host."""
    return Target(ip="192.168.1.100", hostname="example.com")


@pytest.fixture
def url_target():
    """Target with a full URL."""
    return Target(url="https://example.com", hostname="example.com")


@pytest.fixture
def scope_config():
    """Scope config with common test ranges."""
    return ScopeConfig(
        allowed_cidrs=["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"],
        allowed_domains=["localhost", "example.com", "*.example.com"],
        rate_limit_per_second=10,
        auth_rate_limit_per_second=100,
    )


@pytest.fixture
def scan_config(scope_config):
    """Scan config with dry-run enabled for safety."""
    return ScanConfig(
        dry_run=True,
        scope=scope_config,
        modules=["recon", "scan", "vuln", "report"],
    )


@pytest.fixture
def strict_scope():
    """Strict scope with only localhost allowed."""
    return ScopeConfig(
        allowed_cidrs=["127.0.0.0/8"],
        allowed_domains=["localhost"],
        rate_limit_per_second=5,
    )


@pytest.fixture
def strict_config(strict_scope):
    """Scan config with strict scope."""
    return ScanConfig(
        dry_run=True,
        scope=strict_scope,
        modules=["recon"],
    )
