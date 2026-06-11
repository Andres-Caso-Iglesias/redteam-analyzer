"""Append-only audit logger for tracking all actions.

Every action is logged with timestamp, target, module, and user.
"""

import json
import time
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    """A single audit log entry."""

    timestamp: float
    target: str
    module: str
    action: str
    user: Optional[str] = None
    success: bool = True
    error: Optional[str] = None


class AuditLogger:
    """Append-only audit logger."""

    def __init__(self, log_path: Optional[Path] = None):
        """Initialize audit logger.

        Args:
            log_path: Path to persist audit log (JSON file)
        """
        self.log_path = log_path
        self.entries: List[AuditEntry] = []

    def log(
        self,
        target: str,
        module: str,
        action: str,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """Log an action.

        Args:
            target: The target being acted upon
            module: The module performing the action
            action: Description of the action
            success: Whether the action succeeded
            error: Error message if action failed
        """
        entry = AuditEntry(
            timestamp=time.time(),
            target=target,
            module=module,
            action=action,
            success=success,
            error=error,
        )
        self.entries.append(entry)

    def save(self) -> None:
        """Persist audit log to file."""
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "w") as f:
                json.dump(
                    [e.model_dump() for e in self.entries],
                    f,
                    indent=2,
                )

    def get_entries(
        self,
        target: Optional[str] = None,
        module: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Get filtered audit entries.

        Args:
            target: Filter by target
            module: Filter by module

        Returns:
            List of matching audit entries
        """
        entries = self.entries
        if target:
            entries = [e for e in entries if e.target == target]
        if module:
            entries = [e for e in entries if e.module == module]
        return entries

    def summary(self) -> dict:
        """Get audit log summary."""
        total = len(self.entries)
        successful = sum(1 for e in self.entries if e.success)
        failed = total - successful
        modules = list({e.module for e in self.entries})
        return {
            "total_actions": total,
            "successful": successful,
            "failed": failed,
            "modules_used": modules,
        }
