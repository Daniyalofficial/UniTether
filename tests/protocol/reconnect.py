"""Deterministic reconnect backoff (Phase 7).

Exponential backoff with bounded jitter, capped, bounded attempt count.
Seeded RNG keeps tests reproducible; a real clock only matters for the
caller (the state machine transitions are driven by the manager).

    policy = ReconnectPolicy()            # 0.5 s base, x2, 30 s cap
    for delay in policy:                  # raises StopIteration
        sleep(delay)
        attempt()                          # on success: policy.reset()
                                           # on failure: continue
"""
import random


class ReconnectPolicy:
    def __init__(self, base_s: float = 0.5, factor: float = 2.0,
                 cap_s: float = 30.0, jitter: float = 0.2,
                 max_attempts: int = 20, seed=None):
        if not (0.0 <= jitter <= 1.0):
            raise ValueError("jitter must be in [0, 1]")
        if factor < 1.0:
            raise ValueError("factor must be >= 1.0")
        self.base_s = base_s
        self.factor = factor
        self.cap_s = cap_s
        self.jitter = jitter
        self.max_attempts = max_attempts
        self._rng = random.Random(seed)
        self._n = 0

    def next_delay(self) -> float:
        """Delay before attempt number `_n + 1` (1-indexed)."""
        if self._n >= self.max_attempts:
            raise StopIteration("reconnect attempts exhausted")
        self._n += 1
        nominal = min(self.base_s * (self.factor ** (self._n - 1)),
                      self.cap_s)
        # uniform jitter in [-jitter, +jitter] * nominal
        return nominal * (1.0 + self._rng.uniform(-self.jitter, self.jitter))

    def reset(self) -> None:
        self._n = 0

    def attempts_used(self) -> int:
        return self._n

    def __iter__(self):
        return self

    def __next__(self):
        return self.next_delay()
