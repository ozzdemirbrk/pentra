"""Token bucket rate limiter — packets-per-second limiter.

Every scanner asks this limiter for permission before sending a packet.
Goal: avoid causing any DoS impact on the user's network.

Thread-safe — multiple workers may call acquire() concurrently.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Classic token bucket algorithm.

    The bucket starts full. Every second `refill_rate_per_sec` tokens are
    added (without exceeding capacity). `acquire()` consumes tokens; if
    none are available it returns False.

    Parameters:
        capacity: Maximum number of tokens the bucket can hold (burst limit).
        refill_rate_per_sec: Tokens added per second (sustainable rate).
    """

    def __init__(self, capacity: int, refill_rate_per_sec: float) -> None:
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got: {capacity}")
        if refill_rate_per_sec <= 0:
            raise ValueError(
                f"refill_rate_per_sec must be positive, got: {refill_rate_per_sec}",
            )

        self._capacity: int = capacity
        self._refill_rate: float = refill_rate_per_sec
        self._tokens: float = float(capacity)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Read-only properties
    # -----------------------------------------------------------------
    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def refill_rate_per_sec(self) -> float:
        return self._refill_rate

    @property
    def current_tokens(self) -> float:
        """Return the current token count (approximate, for inspection)."""
        with self._lock:
            self._refill_locked()
            return self._tokens

    # -----------------------------------------------------------------
    # Main API
    # -----------------------------------------------------------------
    def acquire(self, tokens: int = 1) -> bool:
        """Request N tokens. If enough are available, consume them and return True; otherwise False.

        Non-blocking — user code may poll in its own loop if desired.
        """
        if tokens <= 0:
            raise ValueError(f"tokens must be positive, got: {tokens}")
        if tokens > self._capacity:
            raise ValueError(
                f"requested tokens ({tokens}) exceed capacity ({self._capacity})",
            )

        with self._lock:
            self._refill_locked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def wait_for(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """Wait until N tokens are available. True on successful acquire.

        If timeout is None this blocks indefinitely. Otherwise returns
        False when the timeout elapses.
        """
        if tokens <= 0:
            raise ValueError(f"tokens must be positive, got: {tokens}")
        if tokens > self._capacity:
            raise ValueError(
                f"requested tokens ({tokens}) exceed capacity ({self._capacity})",
            )

        deadline: float | None = None
        if timeout is not None:
            if timeout < 0:
                raise ValueError("timeout cannot be negative")
            deadline = time.monotonic() + timeout

        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                missing = tokens - self._tokens

            # Estimated time for the missing tokens to refill
            wait_sec = missing / self._refill_rate

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait_sec = min(wait_sec, remaining)

            # Very short sleeps spin the CPU; minimum 1 ms
            time.sleep(max(wait_sec, 0.001))

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------
    def _refill_locked(self) -> None:
        """Add tokens based on time elapsed since last refill. Lock must be held."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        added = elapsed * self._refill_rate
        self._tokens = min(float(self._capacity), self._tokens + added)
        self._last_refill = now
