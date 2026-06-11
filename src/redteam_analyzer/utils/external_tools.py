"""Helpers for running external tools via subprocess.

Wraps nmap, masscan, nuclei, whatweb, etc. with structured output parsing.
"""

import asyncio
import json
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional


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
) -> str:
    """Run an external tool and capture its output.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        input_data: Optional stdin input

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

        stdout, stderr = await asyncio.wait_for(
            process.communicate(input_data.encode() if input_data else None),
            timeout=timeout,
        )

        if process.returncode != 0:
            error_msg = stderr.decode(errors="replace").strip()
            # Don't raise on non-zero exit — some tools use exit codes for status
            # Return whatever stdout we got
            return stdout.decode(errors="replace")

        return stdout.decode(errors="replace")

    except asyncio.TimeoutError:
        process.kill()
        raise ToolTimeoutError(tool_name, timeout)


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
