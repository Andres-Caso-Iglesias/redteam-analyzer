"""Configuration loading and management for redteam-analyzer.

Supports YAML config files with environment variable overrides.
"""

import os
from pathlib import Path
from typing import Optional, Tuple

import yaml

from redteam_analyzer.core.models import ScanConfig, ScopeConfig


def get_default_config() -> ScanConfig:
    """Return the default scan configuration.

    Returns:
        Default ScanConfig with safe defaults (dry_run=True, limited scope)
    """
    return ScanConfig(
        dry_run=True,
        modules=["recon", "scan", "vuln", "report"],
        output_format=["json"],
        passive_only=False,
        scan_backend="nmap",
        report_template="default",
    )


def load_config(path: Optional[str] = None) -> ScanConfig:
    """Load ScanConfig from a YAML file with environment variable overrides.

    Priority: env vars > config file > defaults

    Environment variables:
        RTA_DRY_RUN: Override dry_run (true/false)
        RTA_AUTH_TOKEN: Override auth_token
        RTA_MODULES: Comma-separated list of modules
        RTA_OUTPUT_FORMAT: Comma-separated output formats
        RTA_OUTPUT_PATH: Override output path
        RTA_PASSIVE_ONLY: Override passive_only (true/false)
        RTA_SCAN_BACKEND: Override scan_backend (nmap/masscan)
        RTA_REPORT_TEMPLATE: Override report_template (default/executive)
        RTA_SCOPE_RATE_LIMIT: Override rate_limit_per_second

    Args:
        path: Path to YAML config file. If None or file doesn't exist, returns defaults.

    Returns:
        ScanConfig with file values merged with env var overrides
    """
    if path and Path(path).exists():
        config = _load_from_file(path)
    else:
        config = get_default_config()

    config = _apply_env_overrides(config)

    return config


def _load_from_file(path: str) -> ScanConfig:
    """Load config from a YAML file.

    Args:
        path: Path to YAML config file

    Returns:
        ScanConfig constructed from file contents

    Raises:
        ValueError: If config file is invalid
    """
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid config file: root must be a mapping, got {type(data).__name__}"
        )

    scope_data = data.pop("scope", {})
    scope = ScopeConfig(**scope_data)

    valid_keys = set(ScanConfig.model_fields.keys())
    filtered = {k: v for k, v in data.items() if k in valid_keys}

    return ScanConfig(**filtered, scope=scope, config_path=path)


def _apply_env_overrides(config: ScanConfig) -> ScanConfig:
    """Apply environment variable overrides to config.

    Args:
        config: Config to override

    Returns:
        Updated config with env var values applied
    """
    dry_run = os.environ.get("RTA_DRY_RUN")
    if dry_run is not None:
        config.dry_run = dry_run.lower() in ("true", "1", "yes")

    passive_only = os.environ.get("RTA_PASSIVE_ONLY")
    if passive_only is not None:
        config.passive_only = passive_only.lower() in ("true", "1", "yes")

    auth_token = os.environ.get("RTA_AUTH_TOKEN")
    if auth_token is not None:
        config.auth_token = auth_token

    scan_backend = os.environ.get("RTA_SCAN_BACKEND")
    if scan_backend is not None:
        config.scan_backend = scan_backend

    report_template = os.environ.get("RTA_REPORT_TEMPLATE")
    if report_template is not None:
        config.report_template = report_template

    output_path = os.environ.get("RTA_OUTPUT_PATH")
    if output_path is not None:
        config.output_path = output_path

    modules = os.environ.get("RTA_MODULES")
    if modules is not None:
        config.modules = [m.strip() for m in modules.split(",") if m.strip()]

    output_format = os.environ.get("RTA_OUTPUT_FORMAT")
    if output_format is not None:
        config.output_format = [f.strip() for f in output_format.split(",") if f.strip()]

    rate_limit = os.environ.get("RTA_SCOPE_RATE_LIMIT")
    if rate_limit is not None:
        try:
            config.scope.rate_limit_per_second = int(rate_limit)
        except ValueError:
            pass

    return config


def validate_config_file(path: str) -> Tuple[bool, str]:
    """Validate a config file without loading it into a full ScanConfig.

    Args:
        path: Path to config file

    Returns:
        Tuple of (is_valid, message)
    """
    config_path = Path(path)
    if not config_path.exists():
        return False, f"File not found: {path}"

    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {e}"

    if not isinstance(data, dict):
        return False, f"Root must be a mapping, got {type(data).__name__}"

    try:
        scope_data = data.pop("scope", {})
        scope = ScopeConfig(**scope_data)
        valid_keys = set(ScanConfig.model_fields.keys())
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        ScanConfig(**filtered, scope=scope)
    except Exception as e:
        return False, f"Invalid config: {e}"

    return True, "Config is valid"
