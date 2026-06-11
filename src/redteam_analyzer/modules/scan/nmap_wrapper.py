"""Nmap subprocess wrapper for port scanning.

Executes nmap and parses XML output into structured data.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional

from redteam_analyzer.utils.external_tools import (
    ToolNotFoundError,
    check_tool_installed,
    run_tool,
)

logger = logging.getLogger(__name__)

# Default nmap flags
DEFAULT_FLAGS = ["-sV", "-O", "--open"]


async def run_nmap(
    target: str,
    ports: Optional[str] = None,
    flags: Optional[List[str]] = None,
    timeout: int = 600,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Run nmap scan and parse XML output.

    Args:
        target: Target IP or hostname
        ports: Port specification (e.g., "80,443", "1-1000", "-")
        flags: Additional nmap flags
        timeout: Timeout in seconds
        on_progress: Optional callback for stderr progress lines

    Returns:
        Parsed nmap results dictionary

    Raises:
        ToolNotFoundError: If nmap is not installed
    """
    if not check_tool_installed("nmap"):
        raise ToolNotFoundError("nmap")

    cmd = ["nmap"]

    # Add flags
    cmd.extend(flags or DEFAULT_FLAGS)

    # Add port specification
    if ports:
        cmd.extend(["-p", ports])

    # Output format
    cmd.extend(["-oX", "-"])

    # Target
    cmd.append(target)

    logger.info(f"Running nmap: {' '.join(cmd)}")

    output = await run_tool(cmd, timeout=timeout, on_progress=on_progress)

    return parse_nmap_xml(output)


def parse_nmap_xml(xml_output: str) -> Dict[str, Any]:
    """Parse nmap XML output.

    Args:
        xml_output: Raw XML string from nmap

    Returns:
        Parsed results dictionary
    """
    results = {
        "hosts": [],
        "scan_info": {},
        "raw_output": xml_output,
    }

    try:
        root = ET.fromstring(xml_output)

        # Parse scan info
        results["scan_info"] = {
            "scanner": root.get("scanner", "nmap"),
            "args": root.get("args", ""),
            "start_time": root.get("start", ""),
        }

        # Parse hosts
        for host_elem in root.findall(".//host"):
            host = _parse_host(host_elem)
            if host:
                results["hosts"].append(host)

    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
        results["error"] = str(e)

    return results


def _parse_host(host_elem: ET.Element) -> Optional[Dict[str, Any]]:
    """Parse a single host element from nmap XML."""
    host = {
        "ip": "",
        "hostname": "",
        "state": "",
        "ports": [],
        "os": [],
    }

    # Parse address
    for addr in host_elem.findall(".//address"):
        if addr.get("addrtype") == "ipv4":
            host["ip"] = addr.get("addr", "")
        elif addr.get("addrtype") == "ipv6":
            host["ip"] = addr.get("addr", "")

    # Parse hostname
    for hostname in host_elem.findall(".//hostname"):
        host["hostname"] = hostname.get("name", "")

    # Parse state
    state_elem = host_elem.find(".//status")
    if state_elem is not None:
        host["state"] = state_elem.get("state", "")

    # Parse ports
    for port_elem in host_elem.findall(".//port"):
        port = _parse_port(port_elem)
        if port:
            host["ports"].append(port)

    # Parse OS
    for osmatch in host_elem.findall(".//osmatch"):
        os_info = {
            "name": osmatch.get("name", ""),
            "accuracy": osmatch.get("accuracy", ""),
        }
        host["os"].append(os_info)

    return host if host["ip"] else None


def _parse_port(port_elem: ET.Element) -> Optional[Dict[str, Any]]:
    """Parse a single port element from nmap XML."""
    port = {
        "port": port_elem.get("portid", ""),
        "protocol": port_elem.get("protocol", ""),
        "state": "",
        "service": {},
    }

    # Parse state
    state_elem = port_elem.find(".//state")
    if state_elem is not None:
        port["state"] = state_elem.get("state", "")

    # Parse service
    service_elem = port_elem.find(".//service")
    if service_elem is not None:
        port["service"] = {
            "name": service_elem.get("name", ""),
            "product": service_elem.get("product", ""),
            "version": service_elem.get("version", ""),
            "extrainfo": service_elem.get("extrainfo", ""),
        }

    return port if port["port"] else None


def extract_open_ports(nmap_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract open ports from parsed nmap results.

    Args:
        nmap_results: Parsed nmap results

    Returns:
        List of open port dictionaries
    """
    open_ports = []

    for host in nmap_results.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports.append({
                    "ip": host["ip"],
                    "port": port["port"],
                    "protocol": port["protocol"],
                    "service": port["service"].get("name", ""),
                    "product": port["service"].get("product", ""),
                    "version": port["service"].get("version", ""),
                })

    return open_ports
