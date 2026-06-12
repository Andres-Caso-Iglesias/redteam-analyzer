"""Port scanning plugin for redteam-analyzer.

Supports nmap and masscan backends for port scanning and service detection.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from redteam_analyzer.core.models import (
    Evidence,
    Finding,
    FindingType,
    ScanConfig,
    ScanResult,
    Severity,
    Target,
)
from redteam_analyzer.modules.base import BasePlugin
from redteam_analyzer.modules.scan.masscan_wrapper import (
    extract_open_ports as masscan_extract,
    run_masscan,
)
from redteam_analyzer.modules.scan.nmap_wrapper import (
    extract_open_ports as nmap_extract,
    run_nmap,
)
from redteam_analyzer.utils.external_tools import ToolNotFoundError, check_tool_installed

logger = logging.getLogger(__name__)


class ScanPlugin(BasePlugin):
    """Port scanning plugin supporting nmap and masscan."""

    name = "scan"
    description = "Port scanning, service detection, and OS fingerprinting"
    requires_auth = False

    async def run(self, target: Target, config: ScanConfig) -> ScanResult:
        """Execute port scan against the target.

        Args:
            target: Target to scan
            config: Scan configuration

        Returns:
            ScanResult with port scan findings
        """
        start_time = time.time()
        findings = []
        errors = []

        # Determine target string
        scan_target = target.ip or target.hostname or target.primary

        # Determine backend
        backend = getattr(config, "scan_backend", "nmap")

        # Get scan profile and progress callback from config
        scan_profile = getattr(config, "scan_profile", "stealth")
        on_progress = getattr(config, "on_progress", None)

        try:
            if backend == "masscan" and check_tool_installed("masscan"):
                # Masscan for fast discovery
                results = await run_masscan(scan_target)
                open_ports = masscan_extract(results)

                # Follow up with nmap for service detection on discovered ports
                if open_ports and check_tool_installed("nmap"):
                    port_list = ",".join(p["port"] for p in open_ports)
                    nmap_results = await run_nmap(
                        scan_target, ports=port_list, on_progress=on_progress, scan_profile=scan_profile
                    )
                    open_ports = nmap_extract(nmap_results)
            else:
                # Default: nmap
                results = await run_nmap(scan_target, on_progress=on_progress, scan_profile=scan_profile)
                open_ports = nmap_extract(results)

            # Convert to findings
            for port_info in open_ports:
                port = port_info.get("port", "")
                protocol = port_info.get("protocol", "tcp")
                service = port_info.get("service", "")
                product = port_info.get("product", "")
                version = port_info.get("version", "")

                # Build service string
                service_str = service
                if product:
                    service_str = f"{product}"
                if version:
                    service_str += f"/{version}"

                # Create finding
                location = f"{scan_target}:{port}"
                title = f"Port {port}/{protocol} open"
                if service_str:
                    title += f" ({service_str})"

                findings.append(
                    Finding(
                        type=FindingType.PORT_OPEN,
                        severity=Severity.INFO,
                        location=location,
                        title=title,
                        description=f"Port {port}/{protocol} is open with service: {service_str}",
                        evidence=Evidence(
                            raw_output=str(port_info),
                            structured_data=port_info,
                            tool_name=backend,
                        ),
                    )
                )

                # If we have service version, check for potential vulnerabilities
                if product and version:
                    findings.append(
                        Finding(
                            type=FindingType.SERVICE_DETECTED,
                            severity=Severity.INFO,
                            location=location,
                            title=f"Service: {product} {version}",
                            description=f"Detected {product} version {version} on port {port}",
                            evidence=Evidence(
                                raw_output=f"{product} {version}",
                                structured_data={
                                    "product": product,
                                    "version": version,
                                    "port": port,
                                },
                                tool_name=backend,
                            ),
                        )
                    )

        except ToolNotFoundError as e:
            error_msg = f"Required tool not installed: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
        except Exception as e:
            error_msg = f"Port scan failed: {e}"
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
        """Check if nmap or masscan is installed.

        Returns:
            True if at least one tool is available
        """
        has_nmap = check_tool_installed("nmap")
        has_masscan = check_tool_installed("masscan")

        if not has_nmap and not has_masscan:
            logger.error("Neither nmap nor masscan is installed")
            return False

        return True


# Need to import ScanMetadata
from redteam_analyzer.core.models import ScanMetadata
