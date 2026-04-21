"""Hash-zincirli append-only denetim izi.

Amaç: Pentra'nın ürettiği her tarama talebi, başlangıcı ve sonucu izlenebilir
olsun. Her satır bir JSON event + bir önceki satırın hash'i + kendi hash'i
içerir. Herhangi bir satır değiştirilirse takip eden tüm hash'ler bozulur
ve `verify_integrity()` bunu tespit eder.

Dosya formatı (her satır bağımsız JSON):
    {"ts":"...","event_type":"...","target_fp":"...","details":{...},
     "prev_hash":"...","entry_hash":"..."}

Tehdit modeli (v1):
    ✔ Kaza ile ya da kullanıcıyı yanıltmak amacıyla seçici düzenlemeye karşı dayanıklı
    ✘ Dosyayı tamamen yeniden yazıp zinciri baştan hesaplayabilen saldırgan kapsam dışı
      (bu düzeyde koruma için offline/WORM depolama gerekir)
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

# Zincirin ilk halkası için kullanılan "doğum hash'i"
GENESIS_HASH: str = "0" * 64


@dataclasses.dataclass(frozen=True)
class IntegrityViolation:
    """Log dosyasında tespit edilen bir bütünlük ihlali."""

    line_number: int  # 1-indexed (insan tarafından okunurken rahat olsun diye)
    reason: str  # Türkçe açıklama


class AuditLogError(Exception):
    """Audit log ile ilgili genel hata."""


class AuditLog:
    """Append-only, hash-zincirli denetim izi.

    Thread-safe: birden fazla thread aynı anda `log_event()` çağırabilir.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = self._read_last_hash()

    # -----------------------------------------------------------------
    # Dışa dönük API
    # -----------------------------------------------------------------
    @property
    def path(self) -> Path:
        return self._path

    def log_event(self, event: AuditEvent) -> str:
        """Olayı zincire ekle. Yeni satırın entry_hash'ini döner."""
        with self._lock:
            entry = self._build_entry(event, prev_hash=self._last_hash)
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            self._last_hash = entry["entry_hash"]
            return entry["entry_hash"]

    def read_all(self) -> list[AuditEvent]:
        """Logdaki tüm event'leri AuditEvent nesnesi olarak döndür.

        Bütünlük kontrolü yapmaz — sadece parse eder. Doğrulama için
        `verify_integrity()` kullanın.
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
        """Tüm dosyayı kontrol et; ihlalleri döndür.

        Boş liste = dosya temiz. Dosya yoksa da boş liste döner.
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
                            IntegrityViolation(line_no, f"JSON geçersiz: {e}"),
                        )
                        break  # zincir bozuldu, devamı anlamsız

                    required = {"ts", "event_type", "target_fp", "prev_hash", "entry_hash"}
                    missing = required - entry.keys()
                    if missing:
                        violations.append(
                            IntegrityViolation(
                                line_no, f"eksik alanlar: {', '.join(sorted(missing))}",
                            ),
                        )
                        break

                    if entry["prev_hash"] != prev_hash:
                        violations.append(
                            IntegrityViolation(
                                line_no,
                                f"prev_hash uyuşmuyor: bekleniyor {prev_hash[:16]}..., "
                                f"bulunan {entry['prev_hash'][:16]}...",
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
                                "entry_hash yanlış — içerik ile eşleşmiyor",
                            ),
                        )
                        break

                    prev_hash = entry["entry_hash"]
        except OSError as e:
            raise AuditLogError(f"Log dosyası okunamadı: {e}") from e

        return violations

    # -----------------------------------------------------------------
    # İç
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
        """Son satırı parse ederek last_hash'i belirler. Dosya yoksa genesis."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH

        # Basit, küçük dosyalar için: tüm satırları oku, sonuncuyu al
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
                        # Bozuk satır — devam et; bu bozukluk verify_integrity'de yakalanır
                        last_entry = None
        except OSError as e:
            raise AuditLogError(f"Log dosyası okunamadı: {e}") from e

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
# Hash hesaplama (dışarıdan da kullanılabilir)
# ---------------------------------------------------------------------
def _compute_entry_hash(
    *,
    prev_hash: str,
    ts: str,
    event_type: str,
    target_fp: str,
    details: dict[str, Any],
) -> str:
    """Bir satırın entry_hash'ini kanonik olarak hesaplar.

    Deterministik olması için details JSON'u sort_keys=True ile serileşir.
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
    """Kolaylık yapıcı — timestamp verilmezse şu anki UTC."""
    return AuditEvent(
        event_type=event_type,
        timestamp=timestamp if timestamp is not None else datetime.now(timezone.utc),
        target_fingerprint=target_fingerprint,
        details=details if details is not None else {},
    )
