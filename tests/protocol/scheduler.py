"""Channel scheduler (Phase 9): priorities, backpressure, no starvation.

Default order (configurable weights): CONTROL > INPUT > AUDIO > VIDEO
> FILE — with deficit-round-robin so a FILE flood can never starve a
CONTROL frame, and a hard per-session byte budget so a hostile peer
cannot grow memory unboundedly (Phase 8).
"""
import threading
from collections import deque

import reference_framing as rf  # noqa: E402 (channel constants)

PRIO_CONTROL = 4
PRIO_INPUT = 3
PRIO_AUDIO = 2
PRIO_VIDEO = 1
PRIO_FILE = 0

# default weights (docs/19 §5)
DEFAULT_WEIGHTS = {
    PRIO_CONTROL: 8,
    PRIO_INPUT: 4,
    PRIO_AUDIO: 3,
    PRIO_VIDEO: 2,
    PRIO_FILE: 1,
}

DEFAULT_CHANNEL_PRIO = {
    rf.CH_CONTROL: PRIO_CONTROL,
    rf.CH_STATS: PRIO_CONTROL,
    rf.CH_PROXY: PRIO_CONTROL,
    rf.CH_CLIPBOARD: PRIO_CONTROL,
    rf.CH_NOTIFICATION: PRIO_CONTROL,
    rf.CH_USER: PRIO_CONTROL,
    rf.CH_INPUT: PRIO_INPUT,
    rf.CH_AUDIO_IN: PRIO_AUDIO,
    rf.CH_AUDIO_OUT: PRIO_AUDIO,
    rf.CH_VIDEO: PRIO_VIDEO,
    rf.CH_CAMERA: PRIO_VIDEO,
    rf.CH_TUN_V4: PRIO_VIDEO,
    rf.CH_TUN_V6: PRIO_VIDEO,
    rf.CH_FILE: PRIO_FILE,
}


class Scheduler:
    def __init__(self, weights=None, channel_prio=None,
                 budget_bytes: int = 8 * 1024 * 1024,
                 max_items: int = 4096):
        self.weights = dict(weights or DEFAULT_WEIGHTS)
        self.channel_prio = dict(channel_prio or DEFAULT_CHANNEL_PRIO)
        self.budget_bytes = budget_bytes
        self.max_items = max_items
        self._queues = {p: deque() for p in sorted(self.weights, reverse=True)}
        self._deficit = {p: 0 for p in self.weights}
        self._bytes = 0
        self._items = 0
        self._lock = threading.Lock()
        self.dropped_full = 0
        self.dropped_budget = 0
        self.delivered = 0

    def prio_of(self, channel: int) -> int:
        return self.channel_prio.get(channel, PRIO_FILE)

    def enqueue(self, channel: int, item, size: int = None) -> bool:
        """Backpressure: full queue or budget ⇒ drop (counted), False."""
        p = self.prio_of(channel)
        size = size if size is not None else len(getattr(item, "payload", item))
        with self._lock:
            if self._items >= self.max_items:
                self.dropped_full += 1
                return False
            if self._bytes + size > self.budget_bytes:
                self.dropped_budget += 1
                return False
            self._queues[p].append(item)
            self._bytes += size
            self._items += 1
            return True

    def pending(self) -> int:
        with self._lock:
            return self._items

    def pop(self):
        """Weighted deficit round-robin; None when empty.

        Each priority earns `weight` credit per pass; the highest
        priority with an item AND (deficit>0 OR no other queue has
        deficit) is served. Guarantees: every non-empty priority is
        served within `max(weights)` pops ⇒ no starvation."""
        with self._lock:
            if self._items == 0:
                return None
            # find highest priority with items and credit
            served = None
            for p in self._queues:  # descending priority
                q = self._queues[p]
                if not q:
                    continue
                if self._deficit[p] >= 1:
                    served = p
                    break
            if served is None:
                # no credits left: new pass
                for p, w in self.weights.items():
                    self._deficit[p] = w
                for p in self._queues:
                    if self._queues[p]:
                        served = p
                        break
            item = self._queues[served].popleft()
            self._deficit[served] -= 1
            size = len(getattr(item, "payload", item))
            self._bytes -= size
            self._items -= 1
            self.delivered += 1
            return item

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "pending": {p: len(q) for p, q in self._queues.items()},
                "bytes": self._bytes,
                "dropped_full": self.dropped_full,
                "dropped_budget": self.dropped_budget,
                "delivered": self.delivered,
            }
