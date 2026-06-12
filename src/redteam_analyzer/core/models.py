"""Core data models for redteam-analyzer.

All models use Pydantic v2 for validation and serialization.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Types of findings the scanner can produce."""

    PORT_OPEN = "port_open"
    SERVICE_DETECTED = "service_detected"
    VULN_CVE = "vuln_cve"
    VULN_NUCLEI = "vuln_nuclei"
    TECH_DETECTED = "tech_detected"
    HEADER_MISSING = "header_missing"
    SUBDOMAIN_FOUND = "subdomain_found"
    PATH_FOUND = "path_found"
    UNIDENTIFIED_SERVICE = "unidentified_service"


class OutputFormat(str, Enum):
    """Report output formats."""

    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


class Evidence(BaseModel):
    """Evidence supporting a finding."""

    raw_output: str = ""
    structured_data: Dict[str, Any] = Field(default_factory=dict)
    tool_name: str = ""
    tool_version: str = ""


class Finding(BaseModel):
    """A single security finding."""

    type: FindingType
    severity: Severity
    location: str  # e.g. "192.168.1.1:443" or "https://example.com/admin"
    title: str
    description: str = ""
    evidence: Evidence = Field(default_factory=Evidence)
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    cve_id: Optional[str] = None
    remediation: str = ""

    @field_validator("cve_id", mode="before")
    @classmethod
    def normalize_cve_id(cls, v: Any) -> Optional[str]:
        """Normalize cve_id — nuclei may return list instead of string."""
        if isinstance(v, list):
            return ", ".join(v) if v else None
        return v


class Target(BaseModel):
    """Scan target definition."""

    ip: Optional[str] = None
    hostname: Optional[str] = None
    url: Optional[str] = None
    cidr: Optional[str] = None

    @property
    def primary(self) -> str:
        """Return the primary identifier for the target."""
        return self.url or self.hostname or self.ip or self.cidr or ""

    @property
    def domain(self) -> Optional[str]:
        """Extract domain from hostname or URL."""
        if self.hostname:
            return self.hostname
        if self.url:
            # Simple domain extraction from URL
            from urllib.parse import urlparse

            parsed = urlparse(self.url)
            return parsed.hostname
        return None


class ScanMetadata(BaseModel):
    """Metadata about a plugin execution."""

    plugin_name: str
    duration_seconds: float
    tool_versions: Dict[str, str] = Field(default_factory=dict)
    timestamp: str
    dry_run: bool = False


class ScanResult(BaseModel):
    """Result from a single plugin or accumulated across plugins."""

    target: Target
    findings: List[Finding] = Field(default_factory=list)
    metadata: List[ScanMetadata] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    def merge(self, other: "ScanResult") -> "ScanResult":
        """Merge another ScanResult into this one, deduplicating findings."""
        merged_findings = list(self.findings)
        seen = {
            (f.type, f.location, f.title) for f in merged_findings
        }

        for finding in other.findings:
            key = (finding.type, finding.location, finding.title)
            if key not in seen:
                merged_findings.append(finding)
                seen.add(key)

        return ScanResult(
            target=self.target,
            findings=merged_findings,
            metadata=self.metadata + other.metadata,
            errors=self.errors + other.errors,
        )


class ScopeConfig(BaseModel):
    """Scope configuration for target validation."""

    allowed_cidrs: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)
    rate_limit_per_second: int = 10
    auth_rate_limit_per_second: int = 100
    auth_tokens: List[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Full scan configuration."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dry_run: bool = False
    auth_token: Optional[str] = None
    modules: List[str] = Field(default_factory=lambda: ["recon", "scan", "vuln", "report"])
    output_format: List[str] = Field(default_factory=lambda: ["json"])
    output_path: Optional[str] = None
    config_path: Optional[str] = None
    parallel: bool = False
    passive_only: bool = False
    scan_backend: str = "nmap"  # "nmap" or "masscan"
    scan_profile: str = "stealth"  # "stealth", "normal", "aggressive"
    nuclei_config: Dict[str, Any] = Field(default_factory=dict)  # nuclei templates/tags/severity
    report_template: str = "default"  # "default" or "executive"
    scan_results: Optional["ScanResult"] = None  # Results to export (for report plugin)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    on_progress: Optional[Any] = Field(default=None, exclude=True)


class ToolInfo(BaseModel):
    """Information about an external tool."""

    name: str
    path: Optional[str] = None
    installed: bool = False
    version: Optional[str] = None
