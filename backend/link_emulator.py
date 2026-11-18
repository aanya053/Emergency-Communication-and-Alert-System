"""Emulated link layer: per-hop delay, token-bucket bandwidth shaping, and finite DropTail queues.

Course Mapping:
- CO3 (Transport & Congestion): Demonstrates queuing delay, bandwidth bottlenecks,
  and real DropTail queue overflow under bursty/heavy load.

Non-Negotiable Rule #3:
Every metric, log, and result produced by this module is explicitly labeled
"emulated link" so emulated link behavior is never conflated with raw OS socket metrics.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from backend.db import Database

EMULATED_LABEL = "emulated link"


@dataclass
class LinkQueueState:
    link_id: str
    delay_ms: float
    bandwidth_kbps: float
    queue_limit: int
    is_up: bool
    in_flight: int = 0
    tokens_bytes: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)
    total_passed: int = 0
    total_dropped: int = 0
    max_depth_seen: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class EmulationResult:
    ok: bool
    emulated_delay_ms: float
    dropped_at_link: str | None = None
    reason: str | None = None
    label: str = EMULATED_LABEL


class LinkEmulator:
    """Applies emulated per-hop delay, token-bucket bandwidth, and finite DropTail queues."""

    def __init__(self, db: Database, *, metrics: Any = None, delay_scale: float = 1.0) -> None:
        self.db = db
        self.metrics = metrics
        self.delay_scale = max(0.0, float(delay_scale))
        self._lock = threading.RLock()
        self._links: dict[str, LinkQueueState] = {}
        self.refresh_from_db()

    def refresh_from_db(self) -> None:
        topo = self.db.get_topology()
        with self._lock:
            seen: set[str] = set()
            for row in topo["links"]:
                lid = row["link_id"]
                seen.add(lid)
                rate_bps = max(1.0, float(row["bandwidth_kbps"]) * 1000.0 / 8.0)
                bucket_cap = max(4096.0, rate_bps * 0.25)
                existing = self._links.get(lid)
                if existing is None:
                    self._links[lid] = LinkQueueState(
                        link_id=lid,
                        delay_ms=float(row["delay_ms"]),
                        bandwidth_kbps=float(row["bandwidth_kbps"]),
                        queue_limit=int(row["queue_limit"]),
                        is_up=bool(row["is_up"]),
                        tokens_bytes=bucket_cap,
                    )
                else:
                    with existing.lock:
                        existing.delay_ms = float(row["delay_ms"])
                        existing.bandwidth_kbps = float(row["bandwidth_kbps"])
                        existing.queue_limit = int(row["queue_limit"])
                        existing.is_up = bool(row["is_up"])
            for lid in list(self._links.keys()):
                if lid not in seen:
                    del self._links[lid]

    def set_link_params(
        self,
        link_id: str,
        *,
        delay_ms: float | None = None,
        bandwidth_kbps: float | None = None,
        queue_limit: int | None = None,
    ) -> None:
        """Override link parameters in memory and SQLite (e.g., for congestion/DropTail tests)."""
        with self._lock:
            state = self._links.get(link_id)
            if state is None:
                raise KeyError(f"Unknown link_id: {link_id}")
        with state.lock:
            if delay_ms is not None:
                state.delay_ms = float(delay_ms)
            if bandwidth_kbps is not None:
                state.bandwidth_kbps = float(bandwidth_kbps)
            if queue_limit is not None:
                state.queue_limit = max(1, int(queue_limit))
            d_val = state.delay_ms
            b_val = state.bandwidth_kbps
            q_val = state.queue_limit
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE topology_links SET delay_ms = ?, bandwidth_kbps = ?, queue_limit = ? WHERE link_id = ?",
                (d_val, b_val, q_val, link_id),
            )

    def transmit_path(self, link_ids: list[str], frame_bytes: int) -> EmulationResult:
        """Traverse each hop along `link_ids`, applying DropTail queue + token bucket + propagation delay."""
        self.refresh_from_db()
        if not link_ids:
            return EmulationResult(ok=True, emulated_delay_ms=0.0, label=EMULATED_LABEL)

        total_start = time.monotonic()
        for lid in link_ids:
            with self._lock:
                state = self._links.get(lid)
            if state is None:
                return EmulationResult(
                    ok=False,
                    emulated_delay_ms=(time.monotonic() - total_start) * 1000.0,
                    dropped_at_link=lid,
                    reason=f"{EMULATED_LABEL}: unknown link {lid}",
                    label=EMULATED_LABEL,
                )

            wait_sec = 0.0
            with state.lock:
                if not state.is_up:
                    state.total_dropped += 1
                    if self.metrics is not None:
                        self.metrics.record_emulator_drop(lid)
                    return EmulationResult(
                        ok=False,
                        emulated_delay_ms=(time.monotonic() - total_start) * 1000.0,
                        dropped_at_link=lid,
                        reason=f"{EMULATED_LABEL}: link {lid} is DOWN",
                        label=EMULATED_LABEL,
                    )

                # Finite DropTail queue check
                if state.in_flight >= state.queue_limit:
                    state.total_dropped += 1
                    if self.metrics is not None:
                        self.metrics.record_emulator_drop(lid)
                    self.db.add_log(
                        "WARN",
                        "LINK_EMULATOR",
                        "DROPTAIL_OVERFLOW",
                        {
                            "label": EMULATED_LABEL,
                            "link_id": lid,
                            "queue_depth": state.in_flight,
                            "queue_limit": state.queue_limit,
                        },
                    )
                    return EmulationResult(
                        ok=False,
                        emulated_delay_ms=(time.monotonic() - total_start) * 1000.0,
                        dropped_at_link=lid,
                        reason=f"{EMULATED_LABEL}: DropTail queue overflow on {lid} ({state.in_flight}/{state.queue_limit})",
                        label=EMULATED_LABEL,
                    )

                state.in_flight += 1
                if state.in_flight > state.max_depth_seen:
                    state.max_depth_seen = state.in_flight

                # Token-bucket rate limiter
                now = time.monotonic()
                rate_bytes_per_sec = max(1.0, (state.bandwidth_kbps * 1000.0) / 8.0)
                bucket_cap = max(float(frame_bytes), rate_bytes_per_sec * 0.25)
                elapsed = max(0.0, now - state.last_refill)
                state.tokens_bytes = min(bucket_cap, state.tokens_bytes + elapsed * rate_bytes_per_sec)
                state.last_refill = now

                state.tokens_bytes -= float(frame_bytes)
                if state.tokens_bytes < 0:
                    serialization_wait = (-state.tokens_bytes) / rate_bytes_per_sec
                else:
                    serialization_wait = 0.0

                prop_wait = (state.delay_ms / 1000.0) * self.delay_scale
                wait_sec = prop_wait + serialization_wait

            try:
                if wait_sec > 0:
                    time.sleep(wait_sec)
            finally:
                with state.lock:
                    state.in_flight = max(0, state.in_flight - 1)
                    state.total_passed += 1

        elapsed_ms = (time.monotonic() - total_start) * 1000.0
        return EmulationResult(
            ok=True,
            emulated_delay_ms=round(elapsed_ms, 3),
            label=EMULATED_LABEL,
        )

    def get_stats(self) -> list[dict[str, Any]]:
        self.refresh_from_db()
        with self._lock:
            states = list(self._links.values())
        out: list[dict[str, Any]] = []
        for s in states:
            with s.lock:
                out.append(
                    {
                        "link_id": s.link_id,
                        "label": EMULATED_LABEL,
                        "delay_ms": s.delay_ms,
                        "bandwidth_kbps": s.bandwidth_kbps,
                        "queue_limit": s.queue_limit,
                        "is_up": s.is_up,
                        "in_flight": s.in_flight,
                        "max_depth_seen": s.max_depth_seen,
                        "total_passed": s.total_passed,
                        "total_dropped": s.total_dropped,
                    }
                )
        return out
