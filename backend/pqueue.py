"""Thread-safe priority queue with FIFO tie-breaking and anti-starvation aging.

Course Mapping:
- CO2 / CO3: Priority scheduling (Critical=1 > High=2 > Normal=3) so life-safety
  alerts preempt routine traffic while anti-starvation aging guarantees bounded wait.
"""

from __future__ import annotations

import heapq
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from backend import config


@dataclass
class QueueItem:
    """Item stored inside PriorityAlertQueue."""

    priority: int
    alert_id: str
    delivery_id: int
    target_role: str
    protocol: str
    payload: dict[str, Any]
    enqueued_mono: float = field(default_factory=time.monotonic)
    enqueued_wall: float = field(default_factory=time.time)
    seq: int = 0
    effective_priority: int = 0

    def __post_init__(self) -> None:
        if self.effective_priority <= 0:
            self.effective_priority = int(self.priority)


class PriorityAlertQueue:
    """Thread-safe min-heap priority queue with anti-starvation aging."""

    def __init__(self, aging_threshold_sec: float = config.AGING_THRESHOLD_SEC) -> None:
        self.aging_threshold_sec = max(0.05, float(aging_threshold_sec))
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._heap: list[tuple[int, int, QueueItem]] = []
        self._seq_counter = 0
        self._stopped = False

    def _apply_aging_locked(self, now_mono: float) -> None:
        if not self._heap:
            return
        changed = False
        updated: list[tuple[int, int, QueueItem]] = []
        for eff_prio, seq, item in self._heap:
            age_sec = max(0.0, now_mono - item.enqueued_mono)
            boost = int(age_sec // self.aging_threshold_sec)
            new_eff = max(1, int(item.priority) - boost)
            if new_eff != eff_prio:
                item.effective_priority = new_eff
                changed = True
            updated.append((new_eff, seq, item))
        if changed:
            heapq.heapify(updated)
            self._heap = updated

    def push(self, item: QueueItem) -> int:
        """Enqueue an alert delivery task; returns its assigned FIFO sequence number."""
        with self._cond:
            self._seq_counter += 1
            item.seq = self._seq_counter
            item.effective_priority = int(item.priority)
            heapq.heappush(self._heap, (item.effective_priority, item.seq, item))
            self._cond.notify()
            return item.seq

    def pop(self, timeout: float | None = None) -> QueueItem | None:
        """Pop the highest-priority (lowest numeric value) item, applying aging."""
        with self._cond:
            deadline = None if timeout is None else (time.monotonic() + timeout)
            while not self._heap and not self._stopped:
                if timeout is not None:
                    remaining = deadline - time.monotonic()  # type: ignore[operator]
                    if remaining <= 0:
                        return None
                    self._cond.wait(timeout=min(remaining, 0.5))
                else:
                    self._cond.wait(timeout=0.5)

            if self._stopped and not self._heap:
                return None

            self._apply_aging_locked(time.monotonic())
            _eff, _seq, item = heapq.heappop(self._heap)
            return item

    def pop_nowait(self) -> QueueItem | None:
        """Non-blocking pop after applying anti-starvation aging."""
        with self._cond:
            if not self._heap:
                return None
            self._apply_aging_locked(time.monotonic())
            _eff, _seq, item = heapq.heappop(self._heap)
            return item

    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a sorted non-destructive view of queued items with current effective priorities."""
        with self._lock:
            now_mono = time.monotonic()
            self._apply_aging_locked(now_mono)
            ordered = sorted(self._heap, key=lambda x: (x[0], x[1]))
            return [
                {
                    "alert_id": item.alert_id,
                    "delivery_id": item.delivery_id,
                    "target_role": item.target_role,
                    "protocol": item.protocol,
                    "base_priority": item.priority,
                    "effective_priority": eff,
                    "age_sec": round(max(0.0, now_mono - item.enqueued_mono), 2),
                    "fifo_seq": seq,
                }
                for eff, seq, item in ordered
            ]

    def clear(self) -> int:
        with self._cond:
            n = len(self._heap)
            self._heap.clear()
            return n

    def stop(self) -> None:
        with self._cond:
            self._stopped = True
            self._cond.notify_all()

