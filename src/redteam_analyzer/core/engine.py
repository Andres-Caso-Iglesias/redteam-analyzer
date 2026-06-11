"""Main orchestration engine for redteam-analyzer.

Coordinates plugin execution, enforces guardrails, and manages scan lifecycle.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from redteam_analyzer.core.models import ScanConfig, ScanMetadata, ScanResult, Target
from redteam_analyzer.core.plugin_manager import PluginManager
from redteam_analyzer.core.scope import ScopeError, ScopeValidator
from redteam_analyzer.utils.audit_log import AuditLogger
from redteam_analyzer.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class Engine:
    """Main scan orchestration engine.

    The Engine is the single point of control for:
    - Plugin discovery and execution
    - Scope validation (before ANY network call)
    - Rate limiting (per-domain and global)
    - Audit logging (every action)
    - Error handling (plugin failures don't crash the scan)
    """

    def __init__(self, config: ScanConfig):
        """Initialize the engine.

        Args:
            config: Scan configuration
        """
        self.config = config
        self.plugin_manager = PluginManager()
        self.scope_validator = ScopeValidator(config.scope)
        self.rate_limiter = RateLimiter(config.scope)
        self.audit_logger = AuditLogger()
        self.results: List[ScanResult] = []

    async def scan(self, target: Target) -> ScanResult:
        """Execute a full scan against the target.

        Runs plugins in order: recon → scan → vuln → report

        Args:
            target: The target to scan

        Returns:
            Accumulated ScanResult from all plugins

        Raises:
            ScopeError: If target is out of scope
        """
        # Validate scope BEFORE anything else
        self._validate_scope(target)

        # Log scan start
        self._log_action("engine", "scan_start", target)

        # Discover plugins if not already done
        if not self.plugin_manager.get_available_plugins():
            self.plugin_manager.discover_plugins()

        # Filter modules based on config
        modules = self.config.modules

        # Check auth for intrusive modules
        if not self.config.auth_token:
            modules = self._filter_unauthorized(modules)

        # Dry run mode
        if self.config.dry_run:
            return self._dry_run(target, modules)

        # Execute plugins sequentially
        accumulated = ScanResult(target=target)

        for module_name in modules:
            plugin = self.plugin_manager.load_plugin(module_name)
            if not plugin:
                logger.warning(f"Plugin '{module_name}' not found, skipping")
                accumulated.errors.append(f"Plugin '{module_name}' not found")
                continue

            self._log_action(module_name, "plugin_start", target)

            try:
                result = await self.run_plugin(plugin, target)
                accumulated = accumulated.merge(result)
                self._log_action(module_name, "plugin_complete", target)
            except ScopeError as e:
                error_msg = f"Scope error in {module_name}: {e}"
                logger.error(error_msg)
                accumulated.errors.append(error_msg)
                self._log_action(module_name, "scope_error", target, success=False, error=str(e))
            except Exception as e:
                error_msg = f"Plugin '{module_name}' failed: {e}"
                logger.error(error_msg)
                accumulated.errors.append(error_msg)
                self._log_action(module_name, "plugin_error", target, success=False, error=str(e))

        # Log scan complete
        self._log_action("engine", "scan_complete", target)

        # Persist audit log
        self.audit_logger.save()

        self.results.append(accumulated)
        return accumulated

    async def run_plugin(self, plugin, target: Target) -> ScanResult:
        """Run a single plugin with guardrails.

        Args:
            plugin: The plugin to run
            target: The target to scan

        Returns:
            ScanResult from the plugin
        """
        start_time = time.time()

        # Check rate limiting
        domain = target.domain or target.primary
        await self.rate_limiter.acquire(domain)

        # Run the plugin
        result = await plugin.run(target, self.config)

        # Add metadata
        duration = time.time() - start_time
        metadata = ScanMetadata(
            plugin_name=plugin.name,
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            dry_run=self.config.dry_run,
        )
        result.metadata.append(metadata)

        return result

    def _validate_scope(self, target: Target) -> None:
        """Validate target is in scope. Raises ScopeError if not.

        Args:
            target: The target to validate

        Raises:
            ScopeError: If target is outside authorized scope
        """
        self.scope_validator.validate(target)

    def _log_action(
        self,
        module: str,
        action: str,
        target: Target,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """Log action to audit trail.

        Args:
            module: Module performing the action
            action: Description of the action
            target: Target being acted upon
            success: Whether the action succeeded
            error: Error message if action failed
        """
        self.audit_logger.log(
            target=target.primary,
            module=module,
            action=action,
            success=success,
            error=error,
        )

    def _filter_unauthorized(self, modules: List[str]) -> List[str]:
        """Filter out modules that require auth when no token is provided.

        Args:
            modules: List of module names

        Returns:
            Filtered list of module names
        """
        filtered = []
        for module_name in modules:
            plugin = self.plugin_manager.load_plugin(module_name)
            if plugin and plugin.requires_auth:
                logger.info(f"Skipping intrusive module '{module_name}' (no auth token)")
                self._log_action(
                    module_name,
                    "skipped_no_auth",
                    Target(),
                    success=False,
                    error="No auth token provided for intrusive module",
                )
                continue
            filtered.append(module_name)
        return filtered

    def _dry_run(self, target: Target, modules: List[str]) -> ScanResult:
        """Execute in dry-run mode — show what would run without executing.

        Args:
            target: The target that would be scanned
            modules: List of modules that would run

        Returns:
            ScanResult with dry-run metadata only
        """
        result = ScanResult(target=target)

        for module_name in modules:
            plugin = self.plugin_manager.load_plugin(module_name)
            metadata = ScanMetadata(
                plugin_name=module_name,
                duration_seconds=0.0,
                timestamp=datetime.now(timezone.utc).isoformat(),
                dry_run=True,
            )
            result.metadata.append(metadata)
            self._log_action(module_name, "dry_run", target)

        self.audit_logger.save()
        return result
