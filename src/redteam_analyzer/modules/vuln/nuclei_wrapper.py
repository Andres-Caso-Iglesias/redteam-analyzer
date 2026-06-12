"""Nuclei subprocess wrapper for template-based vulnerability scanning.

Executes nuclei and parses JSONL output into findings.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from redteam_analyzer.core.models import Evidence, Finding, FindingType, ScanConfig, Severity
from redteam_analyzer.utils.external_tools import (
    ToolNotFoundError,
    check_tool_installed,
    parse_jsonl_output,
    run_tool,
)

logger = logging.getLogger(__name__)

# Nuclei severity mapping
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# Intrusive template tags (require auth)
INTRUSIVE_TAGS = {
    "sqli",
    "xss",
    "ssrf",
    "lfi",
    "rfi",
    "rce",
    "upload",
    "deserialization",
    "auth-bypass",
    "idor",
}


async def run_nuclei(
    target: str,
    templates: Optional[str] = None,
    tags: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    rate_limit: int = 150,
    timeout: int = 600,
) -> Dict[str, Any]:
    """Run nuclei scan and parse JSONL output.

    Args:
        target: Target URL or IP
        templates: Template path or ID (e.g., "cves/", "technologies/")
        tags: Filter by tags (e.g., ["sqli", "xss"])
        severity: Filter by severity (e.g., ["critical", "high"])
        rate_limit: Requests per second
        timeout: Timeout in seconds

    Returns:
        Parsed nuclei results dictionary

    Raises:
        ToolNotFoundError: If nuclei is not installed
    """
    if not check_tool_installed("nuclei"):
        raise ToolNotFoundError("nuclei")

    cmd = ["nuclei"]

    # Target — nuclei needs URL format, add http:// if bare IP/hostname
    nuclei_target = target
    if not target.startswith(("http://", "https://")):
        nuclei_target = f"http://{target}"
    cmd.extend(["-target", nuclei_target])

    # Output format
    cmd.extend(["-jsonl"])

    # Templates
    if templates:
        cmd.extend(["-t", templates])

    # Tags filter
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    # Severity filter
    if severity:
        cmd.extend(["-severity", ",".join(severity)])

    # Rate limiting
    cmd.extend(["-rate-limit", str(rate_limit)])

    # Silent mode (less verbose)
    cmd.append("-silent")

    logger.info(f"Running nuclei: {' '.join(cmd)}")

    output = await run_tool(cmd, timeout=timeout)

    return parse_nuclei_jsonl(output)


def parse_nuclei_jsonl(jsonl_output: str) -> Dict[str, Any]:
    """Parse nuclei JSONL output.

    Args:
        jsonl_output: Raw JSONL string from nuclei

    Returns:
        Parsed results dictionary
    """
    results = {
        "findings": [],
        "raw_output": jsonl_output,
    }

    entries = parse_jsonl_output(jsonl_output)

    for entry in entries:
        finding = _parse_nuclei_entry(entry)
        if finding:
            results["findings"].append(finding)

    return results


def _parse_nuclei_entry(entry: Dict[str, Any]) -> Optional[Finding]:
    """Parse a single nuclei JSONL entry into a Finding."""
    template_id = entry.get("template-id", "")
    info = entry.get("info", {})

    if not template_id:
        return None

    # Extract severity
    severity_str = info.get("severity", "info").lower()
    severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

    # Extract classification
    classification = info.get("classification", {})
    cvss_score = classification.get("cvss-score")
    cve_id = classification.get("cve-id")

    # Nuclei may return cve-id as list — normalize to string
    if isinstance(cve_id, list):
        cve_id = ", ".join(cve_id) if cve_id else None

    # Build location
    matched_at = entry.get("matched-at", entry.get("host", ""))
    matcher_name = entry.get("matcher-name", "")
    location = matched_at
    if matcher_name:
        location = f"{matched_at} ({matcher_name})"

    # Build description
    description = info.get("description", "")
    if not description:
        description = info.get("name", template_id)

    # Build evidence
    extracted = entry.get("extracted-results", [])
    evidence_data = {
        "template_id": template_id,
        "matcher_name": matcher_name,
        "matched_at": matched_at,
    }
    if extracted:
        evidence_data["extracted_results"] = extracted

    return Finding(
        type=FindingType.VULN_NUCLEI,
        severity=severity,
        location=location,
        title=info.get("name", template_id),
        description=description,
        evidence=Evidence(
            raw_output=entry.get("raw", ""),
            structured_data=evidence_data,
            tool_name="nuclei",
            tool_version=entry.get("nuclei-version", ""),
        ),
        cvss_score=float(cvss_score) if cvss_score else None,
        cve_id=cve_id,
        remediation=_build_remediation(info),
    )


def _build_remediation(info: Dict[str, Any]) -> str:
    """Build remediation string from nuclei info."""
    remediation = info.get("remediation", "")
    if remediation:
        return remediation

    classification = info.get("info", {}).get("classification", {})
    if classification.get("cve-id"):
        return f"Address {classification['cve-id']} — update affected software"

    return "Review and remediate the identified vulnerability"


def is_intrusive(templates: Optional[str] = None, tags: Optional[List[str]] = None) -> bool:
    """Check if the scan configuration is intrusive.

    Args:
        templates: Template path or ID
        tags: Filter tags

    Returns:
        True if scan is intrusive
    """
    if tags:
        for tag in tags:
            if tag.lower() in INTRUSIVE_TAGS:
                return True

    if templates:
        templates_lower = templates.lower()
        for tag in INTRUSIVE_TAGS:
            if tag in templates_lower:
                return True

    return False
