"""rate_limiter.py — TokenBucket testleri.

Zaman-duyarlı testler deterministik olsun diye:
    - Dolgu hızı ya hızlı seçilir (ör. 1000/sn) ya da
    - `time.monotonic` monkeypatch'lenir.
"""

from __future__ import annotations

import threading
import time

import pytest

from pentra.core.rate_limiter import TokenBucket


# =====================================================================
# Kurucu doğrulaması
# =====================================================================
class TestInit:
    def test_valid_init(self) -> None:
        b = TokenBucket(capacity=10, refill_rate_per_sec=5.0)
        assert b.capacity == 10
        assert b.refill_rate_per_sec == 5.0

    @pytest.mark.parametrize("cap", [0, -1, -100])
    def test_non_positive_capacity_raises(self, cap: int) -> None:
        with pytest.raises(ValueError, match="capacity pozitif"):
            TokenBucket(capacity=cap, refill_rate_per_sec=1.0)

    @pytest.mark.parametrize("rate", [0.0, -0.5, -10.0])
    def test_non_positive_rate_raises(self, rate: float) -> None:
        with pytest.raises(ValueError, match="refill_rate"):
            TokenBucket(capacity=10, refill_rate_per_sec=rate)


# =====================================================================
# acquire()
# =====================================================================
class TestAcquire:
    def test_starts_full(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        assert b.current_tokens == pytest.approx(5.0)

    def test_acquire_one_decreases_one(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=0.001)
        assert b.acquire(1) is True
        assert b.current_tokens == pytest.approx(4.0, abs=0.01)

    def test_acquire_multiple(self) -> None:
        b = TokenBucket(capacity=10, refill_rate_per_sec=0.001)
        assert b.acquire(3) is True
        assert b.current_tokens == pytest.approx(7.0, abs=0.01)

    def test_acquire_more_than_available_returns_false(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=0.001)
        b.acquire(5)  # tamamen boşalt
        assert b.acquire(1) is False

    def test_acquire_zero_raises(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        with pytest.raises(ValueError, match="pozitif"):
            b.acquire(0)

    def test_acquire_negative_raises(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        with pytest.raises(ValueError, match="pozitif"):
            b.acquire(-1)

    def test_acquire_more_than_capacity_raises(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        with pytest.raises(ValueError, match="kapasiteden"):
            b.acquire(10)


# =====================================================================
# refill davranışı
# =====================================================================
class TestRefill:
    def test_refill_happens_over_time(self) -> None:
        # Hızlı dolgu: 100/sn
        b = TokenBucket(capacity=10, refill_rate_per_sec=100.0)
        b.acquire(10)  # boşalt
        assert b.current_tokens == pytest.approx(0.0, abs=0.5)
        time.sleep(0.05)  # ~5 token eklenmiş olmalı
        assert b.current_tokens > 3  # en azından 3 token dolmuş
        assert b.current_tokens <= 10  # kapasiteyi aşmaz

    def test_refill_caps_at_capacity(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1000.0)
        b.acquire(2)  # 3 kaldı
        time.sleep(0.1)  # 100 token üretilecekti ama 5'te kapanır
        assert b.current_tokens == pytest.approx(5.0, abs=0.01)

    def test_after_refill_acquire_succeeds(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=100.0)
        b.acquire(5)
        time.sleep(0.05)
        assert b.acquire(1) is True


# =====================================================================
# wait_for()
# =====================================================================
class TestWaitFor:
    def test_wait_for_returns_immediately_when_tokens_available(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        start = time.monotonic()
        assert b.wait_for(1) is True
        elapsed = time.monotonic() - start
        assert elapsed < 0.05  # neredeyse anında

    def test_wait_for_blocks_until_refill(self) -> None:
        b = TokenBucket(capacity=2, refill_rate_per_sec=100.0)
        b.acquire(2)  # boşalt
        start = time.monotonic()
        assert b.wait_for(1) is True
        elapsed = time.monotonic() - start
        # 1 token için ~10ms bekledi; makul aralık
        assert 0.005 < elapsed < 0.5

    def test_wait_for_timeout_returns_false(self) -> None:
        b = TokenBucket(capacity=1, refill_rate_per_sec=0.1)  # çok yavaş dolum
        b.acquire(1)  # boşalt
        start = time.monotonic()
        assert b.wait_for(1, timeout=0.1) is False
        elapsed = time.monotonic() - start
        assert 0.08 < elapsed < 0.3  # timeout'a yakın

    def test_wait_for_zero_tokens_raises(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        with pytest.raises(ValueError):
            b.wait_for(0)

    def test_wait_for_exceeds_capacity_raises(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        with pytest.raises(ValueError):
            b.wait_for(10)

    def test_wait_for_negative_timeout_raises(self) -> None:
        b = TokenBucket(capacity=5, refill_rate_per_sec=1.0)
        with pytest.raises(ValueError, match="timeout"):
            b.wait_for(1, timeout=-1.0)


# =====================================================================
# Thread safety
# =====================================================================
class TestThreadSafety:
    def test_concurrent_acquires_total_not_exceeds_available(self) -> None:
        """100 thread 1'er token istesin; toplam başarı kapasiteyi aşmamalı."""
        b = TokenBucket(capacity=50, refill_rate_per_sec=0.001)  # dolum yok denecek kadar yavaş
        successes: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            ok = b.acquire(1)
            with lock:
                successes.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # En fazla kapasite kadar başarı olmalı (race condition yok)
        assert sum(1 for ok in successes if ok) == 50
