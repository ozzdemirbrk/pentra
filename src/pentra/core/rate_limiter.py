"""Token bucket rate limiter — paket/saniye sınırlayıcı.

Her tarayıcı paket göndermeden önce bu sınırlayıcıdan izin alır.
Amaç: kullanıcının ağında DoS etkisi yaratmamak.

Thread-safe — birden fazla worker aynı anda acquire() çağırabilir.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Klasik token bucket algoritması.

    Kova başlangıçta dolu. Her saniyede `refill_rate_per_sec` token eklenir
    (kapasiteyi aşmaz). `acquire()` ile token tüketilir; yoksa False döner.

    Parametreler:
        capacity: Kovada en fazla tutulabilecek token sayısı (burst sınırı).
        refill_rate_per_sec: Saniyede eklenen token sayısı (sürdürülebilir hız).
    """

    def __init__(self, capacity: int, refill_rate_per_sec: float) -> None:
        if capacity <= 0:
            raise ValueError(f"capacity pozitif olmalı, verilen: {capacity}")
        if refill_rate_per_sec <= 0:
            raise ValueError(
                f"refill_rate_per_sec pozitif olmalı, verilen: {refill_rate_per_sec}",
            )

        self._capacity: int = capacity
        self._refill_rate: float = refill_rate_per_sec
        self._tokens: float = float(capacity)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Read-only özellikler
    # -----------------------------------------------------------------
    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def refill_rate_per_sec(self) -> float:
        return self._refill_rate

    @property
    def current_tokens(self) -> float:
        """O anki token sayısını döner (yaklaşık, inceleme amaçlı)."""
        with self._lock:
            self._refill_locked()
            return self._tokens

    # -----------------------------------------------------------------
    # Ana API
    # -----------------------------------------------------------------
    def acquire(self, tokens: int = 1) -> bool:
        """N token iste. Yeterli varsa çıkar ve True, yoksa False döner.

        Bloklamaz — kullanıcı kodu isterse kendi döngüsünde bekleyebilir.
        """
        if tokens <= 0:
            raise ValueError(f"tokens pozitif olmalı, verilen: {tokens}")
        if tokens > self._capacity:
            raise ValueError(
                f"istenen token sayısı ({tokens}) kapasiteden ({self._capacity}) büyük",
            )

        with self._lock:
            self._refill_locked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def wait_for(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """N token gelene kadar bekle. Acquire başarılıysa True.

        timeout None ise süresiz bekler. Aksi halde timeout süresi
        bitince False döner.
        """
        if tokens <= 0:
            raise ValueError(f"tokens pozitif olmalı, verilen: {tokens}")
        if tokens > self._capacity:
            raise ValueError(
                f"istenen token sayısı ({tokens}) kapasiteden ({self._capacity}) büyük",
            )

        deadline: float | None = None
        if timeout is not None:
            if timeout < 0:
                raise ValueError("timeout negatif olamaz")
            deadline = time.monotonic() + timeout

        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                missing = tokens - self._tokens

            # Eksik token'ın dolması için gereken tahmini süre
            wait_sec = missing / self._refill_rate

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait_sec = min(wait_sec, remaining)

            # Çok kısa sleep CPU döndürür; minimum 1 ms
            time.sleep(max(wait_sec, 0.001))

    # -----------------------------------------------------------------
    # İç
    # -----------------------------------------------------------------
    def _refill_locked(self) -> None:
        """Son refill'dan bu yana geçen süreye göre token ekle. Lock tutulmuş olmalı."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        added = elapsed * self._refill_rate
        self._tokens = min(float(self._capacity), self._tokens + added)
        self._last_refill = now
