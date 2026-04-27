"""audit_log.py — hash-chained audit trail tests."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pentra.storage.audit_log import (
    GENESIS_HASH,
    AuditLog,
    _compute_entry_hash,
    make_event,
)


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture
def audit(log_path: Path) -> AuditLog:
    return AuditLog(log_path)


# =====================================================================
# Basic writing
# =====================================================================
class TestLogEvent:
    def test_fresh_log_starts_with_genesis_prev_hash(
        self, audit: AuditLog, log_path: Path,
    ) -> None:
        event = make_event("scan_requested", target_fingerprint="abc123", details={"x": 1})
        audit.log_event(event)

        with log_path.open("r", encoding="utf-8") as f:
            line = f.readline()
        entry = json.loads(line)
        assert entry["prev_hash"] == GENESIS_HASH
        assert entry["event_type"] == "scan_requested"
        assert entry["target_fp"] == "abc123"
        assert entry["details"] == {"x": 1}

    def test_consecutive_entries_link(self, audit: AuditLog, log_path: Path) -> None:
        audit.log_event(make_event("a", "fp1"))
        audit.log_event(make_event("b", "fp1"))
        audit.log_event(make_event("c", "fp1"))

        entries = [json.loads(l) for l in log_path.read_text().splitlines()]
        assert len(entries) == 3
        assert entries[0]["prev_hash"] == GENESIS_HASH
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[2]["prev_hash"] == entries[1]["entry_hash"]

    def test_log_event_returns_entry_hash(self, audit: AuditLog) -> None:
        h = audit.log_event(make_event("x", "fp"))
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_parent_directory_auto_created(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "audit.log"
        audit = AuditLog(nested)
        audit.log_event(make_event("x", "fp"))
        assert nested.exists()

    def test_utc_timestamp_in_line(self, audit: AuditLog, log_path: Path) -> None:
        ts = datetime(2026, 4, 21, 10, 0, 0, tzinfo=timezone.utc)
        audit.log_event(make_event("e", "fp", timestamp=ts))
        entry = json.loads(log_path.read_text().splitlines()[0])
        assert "2026-04-21T10:00:00" in entry["ts"]


# =====================================================================
# Persistence
# =====================================================================
class TestPersistence:
    def test_reopen_continues_chain(self, log_path: Path) -> None:
        a1 = AuditLog(log_path)
        a1.log_event(make_event("first", "fp"))

        a2 = AuditLog(log_path)  # new instance, same file
        a2.log_event(make_event("second", "fp"))

        entries = [json.loads(l) for l in log_path.read_text().splitlines()]
        assert len(entries) == 2
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]

    def test_empty_file_treated_as_fresh(self, log_path: Path) -> None:
        log_path.touch()  # create empty file
        audit = AuditLog(log_path)
        audit.log_event(make_event("x", "fp"))
        entry = json.loads(log_path.read_text().splitlines()[0])
        assert entry["prev_hash"] == GENESIS_HASH


# =====================================================================
# Integrity verification
# =====================================================================
class TestVerifyIntegrity:
    def test_clean_log_verifies(self, audit: AuditLog) -> None:
        for i in range(5):
            audit.log_event(make_event(f"evt{i}", f"fp{i}", {"n": i}))
        assert audit.verify_integrity() == []

    def test_empty_log_verifies(self, audit: AuditLog) -> None:
        assert audit.verify_integrity() == []

    def test_nonexistent_file_verifies_as_clean(self, tmp_path: Path) -> None:
        audit = AuditLog(tmp_path / "subdir" / "not-yet-existing.log")
        assert audit.verify_integrity() == []

    def test_modified_details_detected(self, audit: AuditLog, log_path: Path) -> None:
        audit.log_event(make_event("a", "fp", {"val": 1}))
        audit.log_event(make_event("b", "fp", {"val": 2}))

        lines = log_path.read_text().splitlines()
        first = json.loads(lines[0])
        first["details"] = {"val": 999}  # modify content, hash not updated
        lines[0] = json.dumps(first, sort_keys=True, ensure_ascii=False)
        log_path.write_text("\n".join(lines) + "\n")

        violations = audit.verify_integrity()
        assert len(violations) == 1
        assert violations[0].line_number == 1
        assert "entry_hash" in violations[0].reason

    def test_deleted_entry_detected(self, audit: AuditLog, log_path: Path) -> None:
        audit.log_event(make_event("a", "fp"))
        audit.log_event(make_event("b", "fp"))
        audit.log_event(make_event("c", "fp"))

        lines = log_path.read_text().splitlines()
        # Delete the middle line
        log_path.write_text(lines[0] + "\n" + lines[2] + "\n")

        violations = audit.verify_integrity()
        assert len(violations) == 1
        assert violations[0].line_number == 2
        assert "prev_hash" in violations[0].reason.lower()

    def test_corrupted_json_detected(self, audit: AuditLog, log_path: Path) -> None:
        audit.log_event(make_event("a", "fp"))
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{this is not valid json\n")

        violations = audit.verify_integrity()
        assert len(violations) == 1
        assert "JSON" in violations[0].reason

    def test_missing_fields_detected(self, audit: AuditLog, log_path: Path) -> None:
        audit.log_event(make_event("a", "fp"))
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "now"}) + "\n")

        violations = audit.verify_integrity()
        assert len(violations) == 1
        assert "missing" in violations[0].reason.lower()


# =====================================================================
# Reading
# =====================================================================
class TestReadAll:
    def test_read_all_returns_events(self, audit: AuditLog) -> None:
        audit.log_event(make_event("scan_requested", "fp1", {"ip": "10.0.0.1"}))
        audit.log_event(make_event("scan_completed", "fp1", {"findings": 3}))

        events = audit.read_all()
        assert len(events) == 2
        assert events[0].event_type == "scan_requested"
        assert events[1].details["findings"] == 3

    def test_read_all_on_empty_log(self, audit: AuditLog) -> None:
        assert audit.read_all() == []


# =====================================================================
# Helper hash function
# =====================================================================
class TestComputeEntryHash:
    def test_deterministic(self) -> None:
        args = {
            "prev_hash": "abc",
            "ts": "2026-04-21T10:00:00+00:00",
            "event_type": "x",
            "target_fp": "fp",
            "details": {"k": "v"},
        }
        assert _compute_entry_hash(**args) == _compute_entry_hash(**args)

    def test_order_independent_for_dict(self) -> None:
        base = {
            "prev_hash": "abc",
            "ts": "t",
            "event_type": "x",
            "target_fp": "fp",
        }
        h1 = _compute_entry_hash(**base, details={"a": 1, "b": 2})
        h2 = _compute_entry_hash(**base, details={"b": 2, "a": 1})
        assert h1 == h2

    def test_different_input_different_hash(self) -> None:
        base = {
            "prev_hash": "abc",
            "ts": "t",
            "event_type": "x",
            "target_fp": "fp",
            "details": {},
        }
        h1 = _compute_entry_hash(**base)
        h2 = _compute_entry_hash(**{**base, "event_type": "y"})
        assert h1 != h2


# =====================================================================
# Thread safety
# =====================================================================
class TestThreadSafety:
    def test_concurrent_logs_maintain_chain(self, audit: AuditLog) -> None:
        def worker(n: int) -> None:
            for i in range(20):
                audit.log_event(make_event(f"evt_{n}_{i}", f"fp{n}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 5 threads * 20 events = 100 entries, all must be chained
        violations = audit.verify_integrity()
        assert violations == [], f"Thread race broke the chain: {violations}"
