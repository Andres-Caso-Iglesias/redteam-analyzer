"""Tests for audit log utilities."""

import json
import pytest
from pathlib import Path

from redteam_analyzer.utils.audit_log import AuditEntry, AuditLogger


class TestAuditEntry:
    """Tests for AuditEntry model."""

    def test_create_entry(self):
        """AuditEntry can be created with required fields."""
        entry = AuditEntry(
            timestamp=1234567890.0,
            target="example.com",
            module="recon",
            action="scan_start",
        )
        assert entry.target == "example.com"
        assert entry.success is True

    def test_entry_defaults(self):
        """AuditEntry has correct defaults."""
        entry = AuditEntry(
            timestamp=0.0,
            target="t",
            module="m",
            action="a",
        )
        assert entry.success is True
        assert entry.error is None
        assert entry.user is None

    def test_failed_entry(self):
        """AuditEntry can represent failures."""
        entry = AuditEntry(
            timestamp=0.0,
            target="t",
            module="m",
            action="a",
            success=False,
            error="Something went wrong",
        )
        assert entry.success is False
        assert entry.error == "Something went wrong"


class TestAuditLogger:
    """Tests for AuditLogger."""

    def test_log_adds_entry(self):
        """Logging adds an entry to the list."""
        logger = AuditLogger()
        logger.log(target="example.com", module="recon", action="scan_start")

        assert len(logger.entries) == 1
        assert logger.entries[0].target == "example.com"

    def test_log_multiple_entries(self):
        """Multiple logs accumulate entries."""
        logger = AuditLogger()
        logger.log(target="a.com", module="recon", action="start")
        logger.log(target="a.com", module="scan", action="start")
        logger.log(target="b.com", module="recon", action="start")

        assert len(logger.entries) == 3

    def test_save_persists_to_file(self, tmp_path):
        """save() writes entries to JSON file."""
        log_file = tmp_path / "audit.json"
        logger = AuditLogger(log_path=log_file)

        logger.log(target="example.com", module="recon", action="scan")
        logger.save()

        assert log_file.exists()
        data = json.loads(log_file.read_text())
        assert len(data) == 1
        assert data[0]["target"] == "example.com"

    def test_save_no_path_is_noop(self):
        """save() with no log_path does nothing."""
        logger = AuditLogger(log_path=None)
        logger.log(target="x", module="m", action="a")
        logger.save()
        assert len(logger.entries) == 1

    def test_get_entries_filter_by_target(self):
        """get_entries filters by target."""
        logger = AuditLogger()
        logger.log(target="a.com", module="recon", action="start")
        logger.log(target="b.com", module="scan", action="start")

        results = logger.get_entries(target="a.com")
        assert len(results) == 1
        assert results[0].target == "a.com"

    def test_get_entries_filter_by_module(self):
        """get_entries filters by module."""
        logger = AuditLogger()
        logger.log(target="a.com", module="recon", action="start")
        logger.log(target="a.com", module="scan", action="start")

        results = logger.get_entries(module="recon")
        assert len(results) == 1
        assert results[0].module == "recon"

    def test_get_entries_no_filters(self):
        """get_entries with no filters returns all."""
        logger = AuditLogger()
        logger.log(target="a.com", module="recon", action="a")
        logger.log(target="b.com", module="scan", action="b")

        results = logger.get_entries()
        assert len(results) == 2

    def test_summary(self):
        """summary() returns correct stats."""
        logger = AuditLogger()
        logger.log(target="a.com", module="recon", action="a", success=True)
        logger.log(target="a.com", module="recon", action="b", success=True)
        logger.log(target="a.com", module="scan", action="c", success=False)

        s = logger.summary()
        assert s["total_actions"] == 3
        assert s["successful"] == 2
        assert s["failed"] == 1
        assert set(s["modules_used"]) == {"recon", "scan"}

    def test_save_and_reload(self, tmp_path):
        """Saved audit log can be reloaded."""
        log_file = tmp_path / "audit.json"

        logger = AuditLogger(log_path=log_file)
        logger.log(target="example.com", module="recon", action="scan")
        logger.save()

        data = json.loads(log_file.read_text())
        entry = AuditEntry(**data[0])
        assert entry.target == "example.com"
        assert entry.module == "recon"
