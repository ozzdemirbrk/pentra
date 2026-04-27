"""Hash-chained append-only audit log.

Goal: make every scan request, start, and outcome produced by Pentra auditable.
Each line contains a JSON event + the previous line's hash + its own hash. If
any line is tampered with, every following hash breaks and
`verify_integrity()` detects it.

File format (one independent JSON per line):
    {"ts":"...","event_type":"...","target_fp":"...","details":{...},
     "prev_hash":"...","entry_hash":"..."}

Threat model (v1):
    - Robust against accidental or selective edits aimed at misleading the user.
    - Out of scope: an attacker able to rewrite the full file and recompute the
      entire chain from scratch (that level of protection needs offline/WORM
      storage).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pentra.models import AuditEvent

# "Genesis hash" used as the predecessor of the very first entry
GENESIS_HASH: str = "0" * 64


@dataclasses.dataclass(frozen=True)
class IntegrityViolation:
    """An integrity violation detected in the log file."""

    line_number: int  # 1-indexed (so it's easy to read for humans)
    reason: str  # Localized description


class AuditLogError(Exception):
    """General audit-log error."""


class AuditLog:
    """Append-only, hash-chained audit log.

    Thread-safe: multiple threads may call `log_event()` concurrently.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = self._read_last_hash()

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    @property
    def path(self) -> Path:
        return self._path

    def log_event(self, event: AuditEvent) -> str:
        """Append an event to the chain. Returns the new entry's entry_hash."""
        with self._lock:
            entry = self._build_entry(event, prev_hash=self._last_hash)
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            self._last_hash = entry["entry_hash"]
            return entry["entry_hash"]

    def read_all(self) -> list[AuditEvent]:
        """Return every event in the log as AuditEvent objects.

        Does no integrity check — only parsing. Use `verify_integrity()`
        to validate the chain.
        """
        events: list[AuditEvent] = []
        for _, entry in self._iter_entries():
            events.append(
                AuditEvent(
                    event_type=entry["event_type"],
                    timestamp=datetime.fromisoformat(entry["ts"]),
                    target_fingerprint=entry["target_fp"],
                    details=entry.get("details", {}),
                ),
            )
        return events

    def verify_integrity(self) -> list[IntegrityViolation]:
        """Check the entire file; return any violations.

        Empty list = file is clean. A missing file also returns an empty list.
        """
        violations: list[IntegrityViolation] = []
        prev_hash = GENESIS_HASH

        if not self._path.exists():
            return violations

        try:
            with self._path.open("r", encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    raw = raw.rstrip("\n")
                    if not raw:
                        continue

                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError as e:
                        violations.append(
                            IntegrityViolation(line_no, f"Invalid JSON: {e}"),
                        )
                        break  # chain is broken, nothing after this matters

                    required = {"ts", "event_type", "target_fp", "prev_hash", "entry_hash"}
                    missing = required - entry.keys()
                    if missing:
                        violations.append(
                            IntegrityViolation(
                                line_no, f"missing fields: {', '.join(sorted(missing))}",
                            ),
                        )
                        break

                    if entry["prev_hash"] != prev_hash:
                        violations.append(
                            IntegrityViolation(
                                line_no,
                                f"prev_hash mismatch: expected {prev_hash[:16]}..., "
                                f"found {entry['prev_hash'][:16]}...",
                            ),
                        )
                        break

                    expected = _compute_entry_hash(
                        prev_hash=entry["prev_hash"],
                        ts=entry["ts"],
                        event_type=entry["event_type"],
                        target_fp=entry["target_fp"],
                        details=entry.get("details", {}),
                    )
                    if entry["entry_hash"] != expected:
                        violations.append(
                            IntegrityViolation(
                                line_no,
                                "entry_hash mismatch — does not match content",
                            ),
                        )
                        break

                    prev_hash = entry["entry_hash"]
        except OSError as e:
            raise AuditLogError(f"Could not read log file: {e}") from e

        return violations

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------
    def _build_entry(self, event: AuditEvent, prev_hash: str) -> dict[str, Any]:
        ts = event.timestamp.isoformat()
        details = event.details
        entry_hash = _compute_entry_hash(
            prev_hash=prev_hash,
            ts=ts,
            event_type=event.event_type,
            target_fp=event.target_fingerprint,
            details=details,
        )
        return {
            "ts": ts,
            "event_type": event.event_type,
            "target_fp": event.target_fingerprint,
            "details": details,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }

    def _read_last_hash(self) -> str:
        """Determine last_hash by parsing the final line. Genesis when file missing."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH

        # Simple approach for small files: read all lines, take the last
        last_entry: dict[str, Any] | None = None
        try:
            with self._path.open("r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        last_entry = json.loads(raw)
                    except json.JSONDecodeError:
                        # Corrupt line — keep going; verify_integrity() catches this
                        last_entry = None
        except OSError as e:
            raise AuditLogError(f"Could not read log file: {e}") from e

        if last_entry is None or "entry_hash" not in last_entry:
            return GENESIS_HASH
        return str(last_entry["entry_hash"])

    def _iter_entries(self) -> Iterator[tuple[int, dict[str, Any]]]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as f:
            for line_no, raw in enumerate(f, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield line_no, json.loads(raw)
                except json.JSONDecodeError:
                    continue


# ---------------------------------------------------------------------
# Hash calculation (usable from the outside too)
# ---------------------------------------------------------------------
def _compute_entry_hash(
    *,
    prev_hash: str,
    ts: str,
    event_type: str,
    target_fp: str,
    details: dict[str, Any],
) -> str:
    """Compute a line's entry_hash canonically.

    `details` is serialized with sort_keys=True to be deterministic.
    """
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "ts": ts,
            "event_type": event_type,
            "target_fp": target_fp,
            "details": details,
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def make_event(
    event_type: str,
    target_fingerprint: str,
    details: dict[str, Any] | None = None,
    *,
    timestamp: datetime | None = None,
) -> AuditEvent:
    """Convenience factory — uses current UTC when timestamp is omitted."""
    return AuditEvent(
        event_type=event_type,
        timestamp=timestamp if timestamp is not None else datetime.now(timezone.utc),
        target_fingerprint=target_fingerprint,
        details=details if details is not None else {},
    )
