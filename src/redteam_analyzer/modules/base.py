"""Base plugin interface for all scan modules.

Every plugin must implement this abstract base class.
"""

from abc import ABC, abstractmethod

from redteam_analyzer.core.models import ScanConfig, ScanResult, Target


class BasePlugin(ABC):
    """Abstract base class for all scan plugins.

    Plugins must implement:
    - name: unique identifier (e.g., "recon", "scan", "vuln", "report")
    - description: human-readable description
    - requires_auth: True for intrusive plugins that need --auth-token
    - run(): execute the plugin against a target
    - validate_dependencies(): check if required tools are installed
    """

    name: str
    description: str
    requires_auth: bool = False

    @abstractmethod
    async def run(self, target: Target, config: ScanConfig) -> ScanResult:
        """Execute the plugin against the target.

        Args:
            target: The target to scan (IP, hostname, URL)
            config: Scan configuration (rate limits, auth, dry-run, etc.)

        Returns:
            ScanResult with findings and metadata

        Raises:
            ToolNotFoundError: If required external tool is not installed
            ScopeError: If target is out of scope
        """
        ...

    @abstractmethod
    def validate_dependencies(self) -> bool:
        """Check if required external tools are installed.

        Returns:
            True if all dependencies are met, False otherwise
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
