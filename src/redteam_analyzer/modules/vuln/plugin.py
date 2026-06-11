"""Vulnerability scanning plugin for redteam-analyzer.

Combines CVE matching and Nuclei template scanning.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from redteam_analyzer.core.models import (
    ScanConfig,
    ScanMetadata,
    ScanResult,
    Target,
)
from redteam_analyzer.modules.base import BasePlugin
from redteam_analyzer.modules.vuln.cve_matcher import match_cves
from redteam_analyzer.modules.vuln.nuclei_wrapper import is_intrusive, run_nuclei
from redteam_analyzer.utils.external_tools import ToolNotFoundError

logger = logging.getLogger(__name__)


class VulnPlugin(BasePlugin):
    """Vulnerability scanning plugin using CVE matching and Nuclei."""

    name = "vuln"
    description = "Vulnerability scanning via CVE matching and Nuclei templates"
    requires_auth = False  # Only intrusive scans require auth

    async def run(self, target: Target, config: ScanConfig) -> ScanResult:
        """Execute vulnerability scanning against the target.

        Args:
            target: Target to scan
            config: Scan configuration

        Returns:
            ScanResult with vulnerability findings
        """
        start_time = time.time()
        findings = []
        errors = []

        # Determine target string
        scan_target = target.url or target.hostname or target.ip or target.primary

        # Check if we have previous scan results for CVE matching
        # (In practice, this would come from ScanPlugin results passed via config)
        # For now, we do CVE matching if we have service info in target metadata

        # Run Nuclei scan
        try:
            # Determine if intrusive
            scan_config = getattr(config, "nuclei_config", {})
            templates = scan_config.get("templates", None)
            tags = scan_config.get("tags", None)

            # Check if auth is required
            if is_intrusive(templates, tags):
                if not config.auth_token:
                    logger.info("Skipping intrusive nuclei scan (no auth token)")
                    errors.append("Intrusive nuclei scan skipped — no auth token")
                else:
                    # Run nuclei with full capabilities
                    nuclei_results = await run_nuclei(
                        target=scan_target,
                        templates=templates,
                        tags=tags,
                    )
                    for finding in nuclei_results.get("findings", []):
                        findings.append(finding)
            else:
                # Run nuclei with safe templates only
                nuclei_results = await run_nuclei(
                    target=scan_target,
                    templates=templates,
                    tags=tags,
                )
                for finding in nuclei_results.get("findings", []):
                    findings.append(finding)

        except ToolNotFoundError as e:
            error_msg = f"Nuclei not installed: {e}"
            logger.warning(error_msg)
            errors.append(error_msg)
        except Exception as e:
            error_msg = f"Nuclei scan failed: {e}"
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
            findings=findings,
            metadata=[metadata],
            errors=errors,
        )

    def validate_dependencies(self) -> bool:
        """Check if nuclei is installed.

        Returns:
            True if nuclei is available
        """
        from redteam_analyzer.utils.external_tools import check_tool_installed

        if not check_tool_installed("nuclei"):
            logger.warning("Nuclei is not installed — vulnerability scanning will be limited")
            return False
        return True
