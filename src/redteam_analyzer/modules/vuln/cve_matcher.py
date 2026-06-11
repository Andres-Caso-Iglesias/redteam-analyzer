"""CVE matching against known vulnerability databases.

For MVP, uses an in-memory dictionary of common CVEs.
Future: local SQLite copy of NVD.
"""

import logging
from typing import Dict, List, Optional

from redteam_analyzer.core.models import Evidence, Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# MVP CVE database — in-memory dict
# Format: { "product": { "version": [ { cve, severity, cvss, description } ] } }
CVE_DB: Dict[str, Dict[str, List[Dict]]] = {
    "nginx": {
        "1.18.0": [
            {
                "cve": "CVE-2021-23017",
                "severity": Severity.HIGH,
                "cvss": 7.7,
                "description": "Nginx DNS resolver vulnerability allows arbitrary DNS requests",
            }
        ],
        "1.21.0": [
            {
                "cve": "CVE-2021-23017",
                "severity": Severity.HIGH,
                "cvss": 7.7,
                "description": "Nginx DNS resolver vulnerability allows arbitrary DNS requests",
            }
        ],
    },
    "apache": {
        "2.4.49": [
            {
                "cve": "CVE-2021-41773",
                "severity": Severity.CRITICAL,
                "cvss": 9.8,
                "description": "Apache HTTP Server path traversal vulnerability",
            }
        ],
        "2.4.50": [
            {
                "cve": "CVE-2021-42013",
                "severity": Severity.CRITICAL,
                "cvss": 9.8,
                "description": "Apache HTTP Server path traversal vulnerability (incomplete fix of CVE-2021-41773)",
            }
        ],
    },
    "OpenSSH": {
        "8.2p1": [
            {
                "cve": "CVE-2021-28041",
                "severity": Severity.MEDIUM,
                "cvss": 5.9,
                "description": "OpenSSH double-free in ssh-agent",
            }
        ],
        "7.9p1": [
            {
                "cve": "CVE-2021-41617",
                "severity": Severity.HIGH,
                "cvss": 7.0,
                "description": "OpenSSH privilege escalation via AuthorizedKeysCommand",
            }
        ],
    },
    "MySQL": {
        "5.7.33": [
            {
                "cve": "CVE-2021-2162",
                "severity": Severity.HIGH,
                "cvss": 7.5,
                "description": "MySQL Server privilege escalation vulnerability",
            }
        ],
    },
    "PostgreSQL": {
        "13.0": [
            {
                "cve": "CVE-2021-32027",
                "severity": Severity.HIGH,
                "cvss": 7.5,
                "description": "PostgreSQL memory corruption in INSERT ... ON CONFLICT",
            }
        ],
    },
}


def match_cves(
    product: str,
    version: str,
) -> List[Finding]:
    """Match a service/version against known CVEs.

    Args:
        product: Service product name (e.g., "nginx", "OpenSSH")
        version: Service version (e.g., "1.18.0", "8.2p1")

    Returns:
        List of findings for matching CVEs
    """
    findings = []

    # Normalize product name (lowercase for lookup)
    product_lower = product.lower().strip()

    # Search CVE database
    for db_product, versions in CVE_DB.items():
        if db_product.lower() == product_lower:
            # Check exact version match
            if version in versions:
                for cve_info in versions[version]:
                    findings.append(
                        Finding(
                            type=FindingType.VULN_CVE,
                            severity=cve_info["severity"],
                            location=f"{product}/{version}",
                            title=f"{cve_info['cve']}: {product} {version}",
                            description=cve_info["description"],
                            evidence=Evidence(
                                raw_output=f"{product} {version} matched {cve_info['cve']}",
                                structured_data={
                                    "product": product,
                                    "version": version,
                                    "cve": cve_info["cve"],
                                },
                                tool_name="vuln/cve_matcher",
                            ),
                            cvss_score=cve_info.get("cvss"),
                            cve_id=cve_info["cve"],
                            remediation=f"Update {product} to latest version",
                        )
                    )
            # Note: MVP only does exact version matching
            # Version range matching requires proper semver logic (future enhancement)

    if not findings:
        logger.debug(f"No CVEs found for {product} {version}")

    return findings


def _version_compare(v1: str, v2: str) -> int:
    """Simple version comparison.

    Returns:
        1 if v1 > v2, -1 if v1 < v2, 0 if equal
    """
    try:
        parts1 = [int(x) for x in v1.split(".")]
        parts2 = [int(x) for x in v2.split(".")]
    except ValueError:
        # Can't parse versions — return 0 (assume equal)
        return 0

    for a, b in zip(parts1, parts2):
        if a > b:
            return 1
        if a < b:
            return -1

    if len(parts1) > len(parts2):
        return 1
    if len(parts1) < len(parts2):
        return -1

    return 0
