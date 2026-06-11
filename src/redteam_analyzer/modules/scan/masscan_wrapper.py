"""Masscan subprocess wrapper for fast port scanning.

Executes masscan and parses JSON output into structured data.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from redteam_analyzer.utils.external_tools import (
    ToolNotFoundError,
    check_tool_installed,
    run_tool,
)

logger = logging.getLogger(__name__)


async def run_masscan(
    target: str,
    ports: Optional[str] = None,
    rate: int = 1000,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run masscan scan and parse JSON output.

    Args:
        target: Target IP or CIDR range
        ports: Port specification (e.g., "80,443", "1-1000", "-")
        rate: Packets per second
        timeout: Timeout in seconds

    Returns:
        Parsed masscan results dictionary

    Raises:
        ToolNotFoundError: If masscan is not installed
    """
    if not check_tool_installed("masscan"):
        raise ToolNotFoundError("masscan")

    cmd = ["masscan"]

    # Target
    cmd.append(target)

    # Ports
    if ports:
        cmd.extend(["-p", ports])

    # Rate
    cmd.extend(["--rate", str(rate)])

    # Output format
    cmd.extend(["-oJ", "-"])

    # Quiet mode
    cmd.append("--quiet")

    logger.info(f"Running masscan: {' '.join(cmd)}")

    output = await run_tool(cmd, timeout=timeout)

    return parse_masscan_json(output)


def parse_masscan_json(json_output: str) -> Dict[str, Any]:
    """Parse masscan JSON output.

    Args:
        json_output: Raw JSON string from masscan

    Returns:
        Parsed results dictionary
    """
    results = {
        "hosts": [],
        "raw_output": json_output,
    }

    try:
        # Masscan outputs JSON array, but may have trailing comma issues
        # Clean up the output
        cleaned = json_output.strip()
        if cleaned.endswith(","):
            cleaned = cleaned[:-1]
        if not cleaned.startswith("["):
            cleaned = "[" + cleaned
        if not cleaned.endswith("]"):
            cleaned = cleaned + "]"

        data = json.loads(cleaned)

        for entry in data:
            host = _parse_masscan_entry(entry)
            if host:
                results["hosts"].append(host)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse masscan JSON: {e}")
        results["error"] = str(e)

    return results


def _parse_masscan_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse a single masscan entry."""
    ip = entry.get("ip", "")
    if not ip:
        return None

    ports = []
    for port_entry in entry.get("ports", []):
        ports.append({
            "port": str(port_entry.get("port", "")),
            "protocol": port_entry.get("proto", "tcp"),
            "state": port_entry.get("status", "open"),
            "service": port_entry.get("service", {}).get("name", ""),
        })

    return {
        "ip": ip,
        "ports": ports,
        "timestamp": entry.get("timestamp", ""),
    }


def extract_open_ports(masscan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract open ports from parsed masscan results.

    Args:
        masscan_results: Parsed masscan results

    Returns:
        List of open port dictionaries
    """
    open_ports = []

    for host in masscan_results.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports.append({
                    "ip": host["ip"],
                    "port": port["port"],
                    "protocol": port["protocol"],
                    "service": port["service"],
                })

    return open_ports
