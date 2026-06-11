"""Reconnaissance plugin for redteam-analyzer.

Combines passive and active reconnaissance into a single plugin.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from redteam_analyzer.core.models import ScanConfig, ScanMetadata, ScanResult, Target
from redteam_analyzer.modules.base import BasePlugin
from redteam_analyzer.modules.recon.active import (
    directory_bust,
    header_analysis,
    tech_fingerprint,
)
from redteam_analyzer.modules.recon.passive import passive_recon

logger = logging.getLogger(__name__)


class ReconPlugin(BasePlugin):
    """Reconnaissance plugin combining passive and active recon."""

    name = "recon"
    description = "Passive and active reconnaissance (DNS, subdomains, dirbust, fingerprint)"
    requires_auth = False  # Passive recon is always allowed

    async def run(self, target: Target, config: ScanConfig) -> ScanResult:
        """Execute reconnaissance against the target.

        Args:
            target: Target to recon
            config: Scan configuration

        Returns:
            ScanResult with recon findings
        """
        start_time = time.time()
        findings = []
        errors = []

        # Determine if passive-only mode
        passive_only = getattr(config, "passive_only", False)

        # Get domain for passive recon
        domain = target.domain
        if not domain and target.url:
            from urllib.parse import urlparse

            parsed = urlparse(target.url)
            domain = parsed.hostname

        # Passive recon
        if domain:
            try:
                recon_data = await passive_recon(
                    domain=domain,
                    vt_api_key=config.scope.auth_tokens[0] if config.scope.auth_tokens else None,
                    shodan_api_key=None,  # TODO: Add Shodan API key support
                )

                # Convert subdomains to findings
                for subdomain in recon_data.get("subdomains", []):
                    from redteam_analyzer.core.models import Evidence, Finding, FindingType, Severity

                    findings.append(
                        Finding(
                            type=FindingType.SUBDOMAIN_FOUND,
                            severity=Severity.INFO,
                            location=subdomain,
                            title=f"Subdomain: {subdomain}",
                            description=f"Discovered subdomain via passive recon",
                            evidence=Evidence(
                                raw_output=str(recon_data.get("sources", {})),
                                structured_data={"subdomain": subdomain},
                                tool_name="recon/passive",
                            ),
                        )
                    )

                # DNS findings
                dns = recon_data.get("dns", {})
                if dns.get("ipv4"):
                    from redteam_analyzer.core.models import Evidence, Finding, FindingType, Severity

                    findings.append(
                        Finding(
                            type=FindingType.SERVICE_DETECTED,
                            severity=Severity.INFO,
                            location=domain,
                            title=f"DNS resolved: {', '.join(dns['ipv4'])}",
                            description=f"IPv4 addresses: {', '.join(dns['ipv4'])}",
                            evidence=Evidence(
                                raw_output=str(dns),
                                structured_data=dns,
                                tool_name="recon/dns",
                            ),
                        )
                    )

            except Exception as e:
                error_msg = f"Passive recon failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        # Active recon (skip if passive-only)
        if not passive_only and not config.dry_run:
            # Directory busting
            try:
                dir_findings = await directory_bust(target=target)
                findings.extend(dir_findings)
            except Exception as e:
                error_msg = f"Directory busting failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

            # Technology fingerprinting
            try:
                tech_findings = await tech_fingerprint(target=target)
                findings.extend(tech_findings)
            except Exception as e:
                error_msg = f"Tech fingerprinting failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

            # Header analysis
            try:
                header_findings = await header_analysis(target=target)
                findings.extend(header_findings)
            except Exception as e:
                error_msg = f"Header analysis failed: {e}"
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
        """Check if required dependencies are available.

        Returns:
            True if dependencies are met (httpx is the only requirement)
        """
        try:
            import httpx

            return True
        except ImportError:
            logger.error("httpx is required for recon plugin")
            return False
