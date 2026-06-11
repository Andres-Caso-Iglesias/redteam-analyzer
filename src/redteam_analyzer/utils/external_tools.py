"""Helpers for running external tools via subprocess.

Wraps nmap, masscan, nuclei, whatweb, etc. with structured output parsing.
"""

import asyncio
import json
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, Optional


class ToolNotFoundError(Exception):
    """Raised when a required external tool is not installed."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        super().__init__(
            f"Required tool '{tool_name}' is not installed. "
            f"Please install it: https://github.com/evilsocket/redteam-analyzer#dependencies"
        )


class ToolTimeoutError(Exception):
    """Raised when an external tool times out."""

    def __init__(self, tool_name: str, timeout: int):
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(f"Tool '{tool_name}' timed out after {timeout}s")


def check_tool_installed(name: str) -> bool:
    """Check if a tool is installed and available in PATH.

    Args:
        name: Name of the tool executable

    Returns:
        True if tool is found, False otherwise
    """
    return shutil.which(name) is not None


def get_tool_path(name: str) -> Optional[str]:
    """Get the full path to a tool executable.

    Args:
        name: Name of the tool executable

    Returns:
        Full path to the tool, or None if not found
    """
    return shutil.which(name)


async def run_tool(
    cmd: list[str],
    timeout: int = 300,
    input_data: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> str:
    """Run an external tool and capture its output.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        input_data: Optional stdin input
        on_progress: Optional callback for stderr progress lines

    Returns:
        Combined stdout output

    Raises:
        ToolNotFoundError: If the tool is not installed
        ToolTimeoutError: If the tool times out
    """
    if not cmd:
        raise ValueError("Command cannot be empty")

    tool_name = cmd[0]
    if not check_tool_installed(tool_name):
        raise ToolNotFoundError(tool_name)

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )

        # If no progress callback, use simple communicate()
        if not on_progress:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_data.encode() if input_data else None),
                timeout=timeout,
            )
            return stdout.decode(errors="replace")

        # With progress callback: read stderr line by line while process runs
        stdout_chunks = []
        stderr_task = asyncio.create_task(
            _read_stderr_progress(process.stderr, on_progress)
        )

        stdout_data = await asyncio.wait_for(
            process.stdout.read(),
            timeout=timeout,
        )
        stdout_chunks.append(stdout_data.decode(errors="replace"))

        # Wait for stderr reader to finish
        await stderr_task

        # Ensure process completes
        await asyncio.wait_for(process.wait(), timeout=5)

        return "".join(stdout_chunks)

    except asyncio.TimeoutError:
        process.kill()
        raise ToolTimeoutError(tool_name, timeout)


async def _read_stderr_progress(
    stderr_stream: asyncio.StreamReader,
    on_progress: Callable[[str], None],
) -> None:
    """Read stderr and forward to progress callback.

    Handles both newline-separated and carriage-return-separated output
    (nmap uses \r for progress updates).
    """
    buffer = ""
    while True:
        chunk = await stderr_stream.read(1024)
        if not chunk:
            break
        text = chunk.decode(errors="replace")
        # Split on both \n and \r
        for char in text:
            if char in ("\n", "\r"):
                if buffer.strip():
                    on_progress(buffer.strip())
                buffer = ""
            else:
                buffer += char
    # Flush remaining buffer
    if buffer.strip():
        on_progress(buffer.strip())


def parse_nmap_progress(line: str) -> Optional[Dict[str, Any]]:
    """Parse nmap stderr line for progress information.

    Nmap writes progress to stderr like:
        "SYN Stealth Scan Timing: About 15.35% done; ETC: 14:46 (0:02:51 remaining)"
        "Scanning 10.129.95.191 [1000 ports]"
        "Completed SYN Stealth Scan at 14:32, 45.23s elapsed"
        "Discovered open port 22/tcp on 10.129.95.191"
        "Increasing send delay for 10.129.95.191 from 0 to 5 due to ..."
        "Stats: 0:16:53 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan"

    Args:
        line: A single stderr line from nmap

    Returns:
        Parsed progress dict or None if not a progress line
    """
    line = line.strip()
    if not line:
        return None

    # Percentage progress: "SYN Stealth Scan Timing: About 15.35% done; ETC: 14:46 (0:02:51 remaining)"
    match = re.search(
        r"(\w[\w\s]*?)\s+Timing:\s+About\s+([\d.]+)%\s+done;"
        r"\s+ETC:\s+(\d+:\d+)\s+\(([\d:]+)\s+remaining\)",
        line,
    )
    if match:
        return {
            "type": "progress",
            "scan_phase": match.group(1).strip(),
            "percent": float(match.group(2)),
            "etc": match.group(3),
            "remaining": match.group(4),
            "raw": line,
        }

    # Stats line: "Stats: 0:16:53 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan"
    match = re.search(
        r"Stats:\s+([\d:]+)\s+elapsed;\s+(\d+)\s+hosts?\s+completed.*?(\d+)\s+undergoing\s+(.*)",
        line,
    )
    if match:
        return {
            "type": "stats",
            "elapsed": match.group(1),
            "hosts_completed": int(match.group(2)),
            "hosts_active": int(match.group(3)),
            "current_scan": match.group(4).strip(),
            "raw": line,
        }

    # Scan start: "Scanning host [X ports]"
    match = re.search(r"Scanning\s+\S+\s+\[(\d+)\s+ports?\]", line)
    if match:
        return {"type": "scanning", "ports": int(match.group(1)), "raw": line}

    # Completed scan: "Completed ... at HH:MM, Xs elapsed"
    match = re.search(r"Completed\s+.+at\s+\d+:\d+,\s+([\d.]+)s\s+elapsed", line)
    if match:
        return {"type": "completed", "elapsed": float(match.group(1)), "raw": line}

    # Port found: "Discovered open port X/tcp on host"
    match = re.search(r"Discovered open port (\d+)/(tcp|udp) on", line)
    if match:
        return {
            "type": "port_found",
            "port": int(match.group(1)),
            "protocol": match.group(2),
            "raw": line,
        }

    # Send delay increase (network issues): "Increasing send delay ..."
    match = re.search(r"Increasing send delay.*?from\s+(\d+)\s+to\s+(\d+)", line)
    if match:
        return {
            "type": "delay_increase",
            "from_ms": int(match.group(1)),
            "to_ms": int(match.group(2)),
            "raw": line,
        }

    # Generic nmap info line
    if any(kw in line.lower() for kw in ["nmap", "scan", "port", "host", "timing"]):
        return {"type": "info", "raw": line}

    return None


def parse_xml_output(xml_str: str) -> Dict[str, Any]:
    """Parse XML output from tools like nmap.

    Args:
        xml_str: Raw XML string

    Returns:
        Parsed XML as dictionary
    """
    try:
        root = ET.fromstring(xml_str)
        return _element_to_dict(root)
    except ET.ParseError:
        return {"error": "Failed to parse XML output"}


def parse_json_output(json_str: str) -> Any:
    """Parse JSON output from tools.

    Args:
        json_str: Raw JSON string

    Returns:
        Parsed JSON data
    """
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON output"}


def parse_jsonl_output(jsonl_str: str) -> list:
    """Parse JSONL (newline-delimited JSON) output from tools like nuclei.

    Args:
        jsonl_str: Raw JSONL string

    Returns:
        List of parsed JSON objects
    """
    results = []
    for line in jsonl_str.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results


def _element_to_dict(element: ET.Element) -> Dict[str, Any]:
    """Convert an XML element to a dictionary."""
    result: Dict[str, Any] = {}

    # Add attributes
    if element.attrib:
        result["@attributes"] = dict(element.attrib)

    # Add text content
    if element.text and element.text.strip():
        result["@text"] = element.text.strip()

    # Add child elements
    for child in element:
        child_dict = _element_to_dict(child)
        tag = child.tag

        if tag in result:
            # Convert to list if multiple children with same tag
            if not isinstance(result[tag], list):
                result[tag] = [result[tag]]
            result[tag].append(child_dict)
        else:
            result[tag] = child_dict

    return result
