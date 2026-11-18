"""Real-time measured network telemetry collector and 1 Hz SQLite sampler.

Course Mapping:
- CO3 (Performance Evaluation): Measures actual RTT (avg/min/max/p95), sliding-window
  throughput (bytes/sec), packet loss (ACK timeouts + UDP sequence gaps + emulated drops),
  and ACK rates across TCP, UDP, and TLS from real socket and emulator events.

Non-Negotiable Rule #1:
Zero fake or random numbers. Every statistic is computed solely from observed events.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from typing import Any, Callable

from backend.db import Database


class MetricsCollector:
    """Thread-safe collector for real socket and emulated-link performance metrics."""

    def __init__(
        self,
        db: Database,
        *,
        window_sec: float = 10.0,
        sample_interval_sec: float = 1.0,
        on_sample: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.db = db
        self.window_sec = float(window_sec)
        self.sample_interval_sec = float(sample_interval_sec)
        self.on_sample = on_sample

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._sampler_thread: threading.Thread | None = None
        self._queue_depth_fn: Callable[[], int] = lambda: 0

        self._rtts_all: deque[float] = deque(maxlen=1000)
        self._rtts_by_proto: dict[str, deque[float]] = {
            "TCP": deque(maxlen=500),
            "UDP": deque(maxlen=500),
            "TLS": deque(maxlen=500),
        }
        self._tx_bytes_window: deque[tuple[float, int]] = deque()
        self._proto_stats: dict[str, dict[str, int]] = {
            "TCP": {"tx": 0, "bytes": 0, "acked": 0, "timeouts": 0, "gap_losses": 0, "emu_drops": 0},
            "UDP": {"tx": 0, "bytes": 0, "acked": 0, "timeouts": 0, "gap_losses": 0, "emu_drops": 0},
            "TLS": {"tx": 0, "bytes": 0, "acked": 0, "timeouts": 0, "gap_losses": 0, "emu_drops": 0},
        }
        self._crc_errors = 0
        self._emulator_drops_by_link: dict[str, int] = {}

    def set_queue_depth_provider(self, fn: Callable[[], int]) -> None:
        self._queue_depth_fn = fn

    def start(self) -> None:
        if self._sampler_thread is not None and self._sampler_thread.is_alive():
            return
        self._stop_event.clear()
        self._sampler_thread = threading.Thread(
            target=self._sampler_loop,
            name="Metrics-1Hz-Sampler",
            daemon=True,
        )
        self._sampler_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._sampler_thread and self._sampler_thread.is_alive():
            self._sampler_thread.join(timeout=2.0)
            self._sampler_thread = None

    def reset(self) -> None:
        with self._lock:
            self._rtts_all.clear()
            for dq in self._rtts_by_proto.values():
                dq.clear()
            self._tx_bytes_window.clear()
            for stats in self._proto_stats.values():
                for k in stats:
                    stats[k] = 0
            self._crc_errors = 0
            self._emulator_drops_by_link.clear()

    def record_tx(self, protocol_name: str, num_bytes: int) -> None:
        proto = protocol_name.upper()
        now = time.monotonic()
        with self._lock:
            bucket = self._proto_stats.setdefault(
                proto,
                {"tx": 0, "bytes": 0, "acked": 0, "timeouts": 0, "gap_losses": 0, "emu_drops": 0},
            )
            bucket["tx"] += 1
            bucket["bytes"] += int(num_bytes)
            self._tx_bytes_window.append((now, int(num_bytes)))
            self._prune_window_locked(now)

    def record_ack(self, protocol_name: str, rtt_ms: float) -> None:
        proto = protocol_name.upper()
        with self._lock:
            bucket = self._proto_stats.setdefault(
                proto,
                {"tx": 0, "bytes": 0, "acked": 0, "timeouts": 0, "gap_losses": 0, "emu_drops": 0},
            )
            bucket["acked"] += 1
            val = round(float(rtt_ms), 3)
            self._rtts_all.append(val)
            self._rtts_by_proto.setdefault(proto, deque(maxlen=500)).append(val)

    def record_timeout(self, protocol_name: str) -> None:
        proto = protocol_name.upper()
        with self._lock:
            bucket = self._proto_stats.setdefault(
                proto,
                {"tx": 0, "bytes": 0, "acked": 0, "timeouts": 0, "gap_losses": 0, "emu_drops": 0},
            )
            bucket["timeouts"] += 1

    def record_udp_gap_loss(self, lost_count: int = 1) -> None:
        with self._lock:
            self._proto_stats["UDP"]["gap_losses"] += max(1, int(lost_count))

    def record_emulator_drop(self, link_id: str, protocol_name: str = "UDP") -> None:
        proto = protocol_name.upper()
        with self._lock:
            self._emulator_drops_by_link[link_id] = self._emulator_drops_by_link.get(link_id, 0) + 1
            if proto in self._proto_stats:
                self._proto_stats[proto]["emu_drops"] += 1

    def record_crc_error(self) -> None:
        with self._lock:
            self._crc_errors += 1

    def _prune_window_locked(self, now: float) -> None:
        cutoff = now - self.window_sec
        while self._tx_bytes_window and self._tx_bytes_window[0][0] < cutoff:
            self._tx_bytes_window.popleft()

    @staticmethod
    def _rtt_summary(samples: deque[float]) -> dict[str, float | None]:
        if not samples:
            return {"avg_rtt_ms": None, "min_rtt_ms": None, "max_rtt_ms": None, "p95_rtt_ms": None}
        ordered = sorted(samples)
        n = len(ordered)
        p95_idx = min(n - 1, max(0, math.ceil(0.95 * n) - 1))
        return {
            "avg_rtt_ms": round(sum(ordered) / n, 3),
            "min_rtt_ms": round(ordered[0], 3),
            "max_rtt_ms": round(ordered[-1], 3),
            "p95_rtt_ms": round(ordered[p95_idx], 3),
        }

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            self._prune_window_locked(now)
            window_bytes = sum(b for _t, b in self._tx_bytes_window)
            throughput_bps = round(window_bytes / self.window_sec, 2)

            rtt = self._rtt_summary(self._rtts_all)
            total_tx = sum(s["tx"] for s in self._proto_stats.values())
            total_acked = sum(s["acked"] for s in self._proto_stats.values())
            total_timeouts = sum(s["timeouts"] for s in self._proto_stats.values())
            total_gaps = sum(s["gap_losses"] for s in self._proto_stats.values())
            total_emu_drops = sum(self._emulator_drops_by_link.values())
            total_losses = total_timeouts + total_gaps + total_emu_drops

            denom_loss = max(1, total_tx + total_gaps)
            loss_rate = round(min(1.0, total_losses / denom_loss), 4) if (total_tx + total_gaps) > 0 else 0.0
            ack_rate = round(min(1.0, total_acked / total_tx), 4) if total_tx > 0 else 0.0

            by_protocol: dict[str, Any] = {}
            for proto, s in self._proto_stats.items():
                prtt = self._rtt_summary(self._rtts_by_proto.get(proto, deque()))
                p_losses = s["timeouts"] + s["gap_losses"] + s["emu_drops"]
                p_denom = max(1, s["tx"] + s["gap_losses"])
                by_protocol[proto] = {
                    "tx_packets": s["tx"],
                    "tx_bytes": s["bytes"],
                    "acked": s["acked"],
                    "timeouts": s["timeouts"],
                    "udp_gap_losses": s["gap_losses"],
                    "emulated_drops": s["emu_drops"],
                    "ack_rate": round(min(1.0, s["acked"] / s["tx"]), 4) if s["tx"] > 0 else 0.0,
                    "loss_rate": round(min(1.0, p_losses / p_denom), 4) if (s["tx"] + s["gap_losses"]) > 0 else 0.0,
                    **prtt,
                }

            return {
                "timestamp": time.time(),
                "rtt": rtt,
                "throughput_bps": throughput_bps,
                "loss_rate": loss_rate,
                "ack_rate": ack_rate,
                "totals": {
                    "tx_packets": total_tx,
                    "acked": total_acked,
                    "timeouts": total_timeouts,
                    "udp_gap_losses": total_gaps,
                    "emulated_link_drops": total_emu_drops,
                    "crc_errors": self._crc_errors,
                },
                "by_protocol": by_protocol,
                "emulated_drops_by_link": dict(self._emulator_drops_by_link),
                "queue_depth": self._queue_depth_fn(),
            }

    def _sampler_loop(self) -> None:
        while not self._stop_event.wait(self.sample_interval_sec):
            snap = self.snapshot()
            rtt = snap["rtt"]
            by_p = snap["by_protocol"]
            sample = {
                "timestamp": snap["timestamp"],
                "avg_rtt_ms": rtt["avg_rtt_ms"],
                "min_rtt_ms": rtt["min_rtt_ms"],
                "max_rtt_ms": rtt["max_rtt_ms"],
                "p95_rtt_ms": rtt["p95_rtt_ms"],
                "throughput_bps": snap["throughput_bps"],
                "loss_rate": snap["loss_rate"],
                "ack_rate": snap["ack_rate"],
                "tcp_sent": by_p["TCP"]["tx_packets"],
                "tcp_acked": by_p["TCP"]["acked"],
                "udp_sent": by_p["UDP"]["tx_packets"],
                "udp_lost": by_p["UDP"]["udp_gap_losses"] + by_p["UDP"]["emulated_drops"],
                "tls_sent": by_p["TLS"]["tx_packets"],
                "queue_depth": snap["queue_depth"],
            }
            try:
                self.db.insert_metrics_sample(sample)
            except Exception:
                pass
            if self.on_sample is not None:
                try:
                    self.on_sample(snap)
                except Exception:
                    pass

