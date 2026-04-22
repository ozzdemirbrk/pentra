"""SQLite tabanlı tarama geçmişi — "geçen taramadan beri ne değişti" için.

SQLite Python stdlib'inde (`sqlite3`) geldiği için kullanıcı hiçbir şey
kurmuyor. Dosya: `%APPDATA%/Pentra/history.db` — ilk kullanımda otomatik
oluşturulur.

Şema:
    scans: id, target_key, target_type, target_value, depth, started_at,
           ended_at, risk_score, finding_count
    findings: id, scan_id, severity, title, target
        (sadece eşleştirme için gerekli alanlar — description/remediation
        kaydedilmiyor çünkü deterministik olarak tekrar üretilebilir)
"""

from __future__ import annotations

import dataclasses
import sqlite3
from datetime import datetime
from pathlib import Path

from pentra.models import Target, TargetType
from pentra.reporting.report_builder import Report


def _target_key(target: Target) -> str:
    """Aynı hedefi (farklı scan'lerde) tanımak için stabil anahtar."""
    return f"{target.target_type.value}:{target.value}"


# ---------------------------------------------------------------------
# Snapshot tipleri (geçmişten okunan hafif veriler)
# ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class FindingSnapshot:
    """Geçmiş bir bulgu — diff için minimum alan seti."""

    severity: str  # "critical" / "high" / "medium" / "low" / "info"
    title: str
    target: str


@dataclasses.dataclass(frozen=True)
class ReportSnapshot:
    """Geçmiş bir tarama — listeler ve karşılaştırma için."""

    scan_id: int
    target_key: str
    target_value: str
    depth: str
    ended_at: datetime
    risk_score: float
    finding_count: int
    findings: tuple[FindingSnapshot, ...]


@dataclasses.dataclass(frozen=True)
class ScanSummary:
    """Geçmiş listesi için özet."""

    scan_id: int
    target_value: str
    depth: str
    ended_at: datetime
    risk_score: float
    finding_count: int


# ---------------------------------------------------------------------
# Ana sınıf
# ---------------------------------------------------------------------
class ScanHistory:
    """SQLite ile tarama geçmişi yönetimi."""

    _SCHEMA: str = """
    CREATE TABLE IF NOT EXISTS scans (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        target_key    TEXT    NOT NULL,
        target_type   TEXT    NOT NULL,
        target_value  TEXT    NOT NULL,
        depth         TEXT    NOT NULL,
        started_at    TEXT    NOT NULL,
        ended_at      TEXT    NOT NULL,
        risk_score    REAL    NOT NULL,
        finding_count INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_key, ended_at DESC);

    CREATE TABLE IF NOT EXISTS findings (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        severity  TEXT    NOT NULL,
        title     TEXT    NOT NULL,
        target    TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    # -----------------------------------------------------------------
    # Kayıt
    # -----------------------------------------------------------------
    def record(self, report: Report) -> int:
        """Bir tarama raporunu DB'ye yaz, scan_id döner."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    target_key, target_type, target_value, depth,
                    started_at, ended_at, risk_score, finding_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _target_key(report.target),
                    report.target.target_type.value,
                    report.target.value,
                    report.depth.value,
                    report.started_at.isoformat(),
                    report.ended_at.isoformat(),
                    report.risk.score,
                    report.summary.total,
                ),
            )
            scan_id = cursor.lastrowid
            if scan_id is None:
                raise RuntimeError("scan_id alınamadı")

            if report.findings:
                conn.executemany(
                    "INSERT INTO findings (scan_id, severity, title, target) VALUES (?, ?, ?, ?)",
                    [
                        (scan_id, f.severity.value, f.title, f.target)
                        for f in report.findings
                    ],
                )
            return scan_id

    # -----------------------------------------------------------------
    # Sorgu
    # -----------------------------------------------------------------
    def find_previous(self, target: Target) -> ReportSnapshot | None:
        """Aynı hedef için son tarama (varsa) döner."""
        key = _target_key(target)
        with self._connect() as conn:
            scan_row = conn.execute(
                """
                SELECT id, target_key, target_value, depth, ended_at,
                       risk_score, finding_count
                FROM scans WHERE target_key = ?
                ORDER BY ended_at DESC LIMIT 1
                """,
                (key,),
            ).fetchone()
            if scan_row is None:
                return None

            finding_rows = conn.execute(
                "SELECT severity, title, target FROM findings WHERE scan_id = ?",
                (scan_row["id"],),
            ).fetchall()

            findings = tuple(
                FindingSnapshot(
                    severity=row["severity"],
                    title=row["title"],
                    target=row["target"],
                )
                for row in finding_rows
            )

            return ReportSnapshot(
                scan_id=scan_row["id"],
                target_key=scan_row["target_key"],
                target_value=scan_row["target_value"],
                depth=scan_row["depth"],
                ended_at=datetime.fromisoformat(scan_row["ended_at"]),
                risk_score=scan_row["risk_score"],
                finding_count=scan_row["finding_count"],
                findings=findings,
            )

    def list_recent(self, limit: int = 20) -> list[ScanSummary]:
        """Son N taramanın özeti (hedef, tarih, skor)."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, target_value, depth, ended_at, risk_score, finding_count
                FROM scans ORDER BY ended_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            ScanSummary(
                scan_id=r["id"],
                target_value=r["target_value"],
                depth=r["depth"],
                ended_at=datetime.fromisoformat(r["ended_at"]),
                risk_score=r["risk_score"],
                finding_count=r["finding_count"],
            )
            for r in rows
        ]

    def delete_all(self) -> int:
        """Tüm geçmişi sil — "geçmişi temizle" butonu için. Silinen kayıt sayısı döner."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scans")
            # findings CASCADE ile otomatik silinir
            return cursor.rowcount

    # -----------------------------------------------------------------
    # İç
    # -----------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        # Yabancı anahtar desteği (CASCADE için)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(self._SCHEMA)
