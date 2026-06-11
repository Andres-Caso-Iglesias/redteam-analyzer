"""Tests for CLI commands."""

import json
import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock

from redteam_analyzer.cli.main import app
from redteam_analyzer.core.models import (
    Finding, FindingType, ScanResult, Severity, Target, ScanMetadata
)

runner = CliRunner()


def test_scan_help():
    """Test scan command help output."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Target" in result.output or "target" in result.output


def test_recon_help():
    """Test recon command help output."""
    result = runner.invoke(app, ["recon", "--help"])
    assert result.exit_code == 0


def test_report_help():
    """Test report command help output."""
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0


def test_plugin_list():
    """Test plugin list command."""
    result = runner.invoke(app, ["plugin", "list"])
    assert result.exit_code == 0
    # Should list at least recon, scan, vuln, report plugins
    assert "recon" in result.output or "scan" in result.output


def test_config_validate_missing_file():
    """Test config validate with missing file."""
    result = runner.invoke(app, ["config", "validate", "nonexistent.yaml"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_config_validate_valid_file(tmp_path):
    """Test config validate with valid config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
modules:
  - recon
  - scan
dry_run: false
scope:
  allowed_domains:
    - example.com
""")
    result = runner.invoke(app, ["config", "validate", str(config_file)])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_config_validate_invalid_yaml(tmp_path):
    """Test config validate with invalid YAML."""
    config_file = tmp_path / "bad.yaml"
    config_file.write_text("not: [valid: {config: true")
    result = runner.invoke(app, ["config", "validate", str(config_file)])
    assert result.exit_code == 1


@patch("redteam_analyzer.cli.main.Engine")
def test_scan_dry_run(MockEngine, tmp_path):
    """Test scan command in dry-run mode."""
    mock_instance = MockEngine.return_value
    mock_result = ScanResult(
        target=Target(hostname="example.com"),
        findings=[],
        metadata=[ScanMetadata(plugin_name="recon", duration_seconds=0.1, timestamp="2024-01-01T00:00:00", dry_run=True)],
    )
    mock_instance.scan = AsyncMock(return_value=mock_result)
    
    result = runner.invoke(app, ["scan", "example.com", "--dry-run"])
    assert result.exit_code == 0
    mock_instance.scan.assert_called_once()


def test_scan_missing_target():
    """Test scan command without target."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0


@patch("redteam_analyzer.cli.main.Engine")
def test_recon_passive_only(MockEngine):
    """Test recon command with passive-only flag."""
    mock_instance = MockEngine.return_value
    mock_result = ScanResult(
        target=Target(hostname="example.com"),
        findings=[],
        metadata=[],
    )
    mock_instance.scan = AsyncMock(return_value=mock_result)
    
    result = runner.invoke(app, ["recon", "example.com", "--passive-only"])
    assert result.exit_code == 0


def test_report_missing_file():
    """Test report command with missing file."""
    result = runner.invoke(app, ["report", "nonexistent.json"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


@patch("redteam_analyzer.cli.main.Engine")
def test_scan_with_modules(MockEngine):
    """Test scan command with specific modules."""
    mock_instance = MockEngine.return_value
    mock_result = ScanResult(
        target=Target(hostname="example.com"),
        findings=[],
        metadata=[],
    )
    mock_instance.scan = AsyncMock(return_value=mock_result)
    
    result = runner.invoke(app, ["scan", "example.com", "--module", "recon", "--module", "scan"])
    assert result.exit_code == 0