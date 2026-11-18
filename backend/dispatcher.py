"""Priority alert dispatcher with network-down queuing, estimated delay, and redelivery.

Course Mapping:
- CO3 (Transport & Scheduling): Dispatches alerts from the PriorityAlertQueue
  over TCP, UDP, or TLS, tracks per-target delivery state, and handles offline/down
  recovery with alternate routing.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable

from backend import config, protocol
from backend.db import Database
from backend.link_emulator import LinkEmulator
from backend.pqueue import PriorityAlertQueue, QueueItem
from backend.routing import RoutingEngine


class AlertDispatcher:
    """Worker pool + redelivery loop orchestrating alert transmission and tracking."""

    def __init__(
        self,
        *,
        db: Database,
        pqueue: PriorityAlertQueue,
        routing: RoutingEngine,
        link_emulator: LinkEmulator,
        tcp_server: Any,
        udp_server: Any,
        tls_server: Any,
        metrics: Any = None,
        num_workers: int = 4,
        redelivery_interval_sec: float = config.REDELIVERY_INTERVAL_SEC,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.db = db
        self.pqueue = pqueue
        self.routing = routing
        self.link_emulator = link_emulator
        self.tcp_server = tcp_server
        self.udp_server = udp_server
        self.tls_server = tls_server
        self.metrics = metrics
        self.num_workers = max(1, int(num_workers))
        self.redelivery_interval_sec = float(redelivery_interval_sec)
        self.on_event = on_event

        self._stop_event = threading.Event()
        self._workers: list[threading.Thread] = []
        self._redelivery_thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._in_queue_deliveries: set[int] = set()
        self._dispatch_durations: deque[float] = deque(maxlen=200)

        # Hook async ACKs (e.g. UDP ACKs arriving shortly after broadcast)
        if self.udp_server is not None:
            self.udp_server.set_async_ack_callback(self._handle_async_ack)
        if self.tcp_server is not None:
            self.tcp_server.set_async_ack_callback(self._handle_async_ack)
        if self.tls_server is not None:
            self.tls_server.set_async_ack_callback(self._handle_async_ack)

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        if self.on_event is not None:
            try:
                self.on_event(event_type, data)
            except Exception:
                pass

    def _server_for_protocol(self, proto: str) -> Any:
        p = proto.upper()
        if p == "TLS":
            return self.tls_server
        if p == "UDP":
            return self.udp_server
        return self.tcp_server

    def measured_avg_dispatch_sec(self) -> float:
        with self._lock:
            if self._dispatch_durations:
                return sum(self._dispatch_durations) / len(self._dispatch_durations)
        return self.redelivery_interval_sec

    def compute_estimated_wait_sec(self, *, include_self: bool = True) -> float:
        items_ahead = self.pqueue.size()
        waiting_rows = self.db.get_deliveries(statuses=("WAITING_NETWORK",))
        pending_redeliveries = len(waiting_rows)
        if include_self and pending_redeliveries == 0 and items_ahead == 0:
            pending_redeliveries = 1
        avg_sec = self.measured_avg_dispatch_sec()
        return round((items_ahead + pending_redeliveries) * avg_sec, 2)

    def _handle_async_ack(self, alert_id: str, role: str, client_id: str, rtt_ms: float) -> None:
        delivery = self.db.get_delivery_for_alert_role(alert_id, role)
        if not delivery:
            return
        if delivery["status"] in ("DELIVERED", "REROUTED", "SENT", "WAITING_NETWORK", "QUEUED"):
            now = time.time()
            computed_rtt = rtt_ms
            if computed_rtt <= 0.0 and delivery.get("sent_at"):
                computed_rtt = max(0.1, (now - float(delivery["sent_at"])) * 1000.0)
            self.db.update_delivery(
                delivery["id"],
                status="ACKNOWLEDGED",
                client_id=client_id,
                rtt_ms=computed_rtt,
                ack_at=now,
                clear_estimated_wait=True,
            )
            new_alert_status = self.db.recompute_alert_status(alert_id)
            self._emit(
                "delivery_updated",
                {"alert_id": alert_id, "delivery_id": delivery["id"], "status": "ACKNOWLEDGED", "alert_status": new_alert_status},
            )

    def start(self) -> None:
        if self._workers:
            return
        self._stop_event.clear()
        self.recover_pending_from_db()

        for i in range(self.num_workers):
            th = threading.Thread(
                target=self._worker_loop,
                name=f"Dispatcher-Worker-{i+1}",
                daemon=True,
            )
            th.start()
            self._workers.append(th)

        self._redelivery_thread = threading.Thread(
            target=self._redelivery_loop,
            name="Dispatcher-Redelivery",
            daemon=True,
        )
        self._redelivery_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.pqueue.stop()
        for th in self._workers:
            if th.is_alive():
                th.join(timeout=2.0)
        self._workers.clear()
        if self._redelivery_thread and self._redelivery_thread.is_alive():
            self._redelivery_thread.join(timeout=2.0)
            self._redelivery_thread = None

    def enqueue_alert(self, alert_id: str) -> int:
        """Enqueue all QUEUED deliveries for a newly created alert."""
        alert = self.db.get_alert(alert_id)
        if not alert:
            return 0
        deliveries = self.db.get_deliveries(alert_id=alert_id, statuses=("QUEUED",))
        count = 0
        for d in deliveries:
            self._enqueue_delivery(alert, d)
            count += 1
        return count

    def _enqueue_delivery(self, alert: dict[str, Any], delivery: dict[str, Any]) -> None:
        did = int(delivery["id"])
        with self._lock:
            if did in self._in_queue_deliveries:
                return
            self._in_queue_deliveries.add(did)

        payload = {
            "alert_id": alert["alert_id"],
            "alert_code": alert["alert_code"],
            "title": alert["title"],
            "message": alert["message"],
            "alert_type": alert["alert_type"],
            "priority": int(alert["priority"]),
            "protocol": delivery["protocol"],
            "target_role": delivery["target_role"],
            "location": alert["location"],
            "sensitive": bool(alert["sensitive"]),
            "created_by": alert["created_by"],
            "created_at": alert["created_at"],
        }
        item = QueueItem(
            priority=int(alert["priority"]),
            alert_id=alert["alert_id"],
            delivery_id=did,
            target_role=delivery["target_role"],
            protocol=delivery["protocol"],
            payload=payload,
        )
        self.pqueue.push(item)

    def recover_pending_from_db(self) -> int:
        """Recover QUEUED and WAITING_NETWORK deliveries from SQLite on server restart."""
        pending = self.db.get_deliveries(statuses=("QUEUED", "WAITING_NETWORK"))
        recovered = 0
        for d in pending:
            alert = self.db.get_alert(d["alert_id"])
            if alert:
                self._enqueue_delivery(alert, d)
                recovered += 1
        if recovered:
            self.db.add_log("INFO", "DISPATCHER", "RECOVERED_FROM_DB", {"count": recovered})
        return recovered

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            item = self.pqueue.pop(timeout=0.5)
            if item is None:
                continue
            try:
                self._dispatch_item(item)
            except Exception as exc:
                self.db.add_log(
                    "ERROR",
                    "DISPATCHER",
                    "WORKER_EXCEPTION",
                    {"alert_id": item.alert_id, "delivery_id": item.delivery_id, "error": str(exc)},
                )
            finally:
                with self._lock:
                    self._in_queue_deliveries.discard(item.delivery_id)

    def _dispatch_item(self, item: QueueItem) -> None:
        t0 = time.monotonic()
        delivery = self.db.get_delivery(item.delivery_id)
        if delivery is None or delivery["status"] == "ACKNOWLEDGED":
            return

        proto = item.protocol.upper()
        role = item.target_role
        sensitive = bool(item.payload.get("sensitive"))

        # Enforce sensitive TLS policy
        if sensitive and (role not in config.SENSITIVE_ROLES or proto != "TLS"):
            self.db.update_delivery(
                item.delivery_id,
                status="FAILED",
                last_error="Sensitive alerts must use TLS and target Hospital or Police only",
                clear_estimated_wait=True,
            )
            self.db.recompute_alert_status(item.alert_id)
            self.db.add_log(
                "ERROR",
                "DISPATCHER",
                "SENSITIVE_POLICY_BLOCKED",
                {"alert_id": item.alert_id, "role": role, "protocol": proto},
            )
            return

        dst_node = config.ROLE_NODE_MAP.get(role, "TOWER_SOUTH")
        route = self.routing.dijkstra("ECC_HQ", dst_node)
        server = self._server_for_protocol(proto)
        client_online = server is not None and server.has_client(role)

        if not route.reachable or not client_online:
            reason = "Network route down (no path from ECC_HQ)" if not route.reachable else f"{proto} responder '{role}' offline"
            est_wait = self.compute_estimated_wait_sec(include_self=True)
            self.db.update_delivery(
                item.delivery_id,
                status="WAITING_NETWORK",
                estimated_wait_sec=est_wait,
                last_error=reason,
                route=route.path if route.reachable else [],
            )
            self.db.recompute_alert_status(item.alert_id)
            self.db.add_log(
                "WARN",
                "DISPATCHER",
                "WAITING_NETWORK",
                {
                    "alert_id": item.alert_id,
                    "role": role,
                    "protocol": proto,
                    "reason": reason,
                    "estimated_wait_sec": est_wait,
                },
            )
            self._emit(
                "delivery_updated",
                {
                    "alert_id": item.alert_id,
                    "delivery_id": item.delivery_id,
                    "status": "WAITING_NETWORK",
                    "estimated_wait_sec": est_wait,
                    "reason": reason,
                },
            )
            return

        baseline = self.routing.get_baseline_path("ECC_HQ", dst_node)
        rerouted = bool(baseline and route.path != baseline)
        flags = protocol.FLAG_ACK_REQUIRED if proto != "UDP" else 0
        if sensitive:
            flags |= protocol.FLAG_SENSITIVE
        if rerouted:
            flags |= protocol.FLAG_REROUTED

        payload = dict(item.payload)
        payload["route"] = route.path
        payload["rerouted"] = rerouted
        frame_size = len(
            protocol.pack(
                protocol.MsgType.ALERT,
                payload,
                priority=item.priority,
                flags=flags,
                seq=1,
            )
        )

        if rerouted:
            self.db.update_delivery(
                item.delivery_id,
                status="REROUTED",
                route=route.path,
                last_error="Rerouted via alternate Dijkstra path",
            )
            self.db.add_log(
                "INFO",
                "DISPATCHER",
                "REROUTED",
                {"alert_id": item.alert_id, "role": role, "route": route.path, "baseline": baseline},
            )

        prev_attempts = int(delivery.get("attempts") or 0)
        sent_wall = time.time()

        if proto == "UDP":
            emu = self.link_emulator.transmit_path(route.links, frame_size)
            res = server.send_alert(
                role,
                payload,
                priority=item.priority,
                flags=flags,
                drop_packet=(not emu.ok),
            )
            duration = time.monotonic() - t0
            with self._lock:
                self._dispatch_durations.append(duration)

            if not emu.ok or not res.ok:
                self.db.update_delivery(
                    item.delivery_id,
                    status="FAILED",
                    attempts=prev_attempts + 1,
                    route=route.path,
                    sent_at=sent_wall,
                    clear_estimated_wait=True,
                    last_error=emu.reason or res.error or "UDP drop",
                )
            else:
                self.db.update_delivery(
                    item.delivery_id,
                    status="REROUTED" if rerouted else "DELIVERED",
                    client_id=res.client_id,
                    attempts=prev_attempts + 1,
                    rtt_ms=emu.emulated_delay_ms,
                    route=route.path,
                    sent_at=sent_wall,
                    clear_estimated_wait=True,
                    last_error=f"Rerouted ({emu.label})" if rerouted else emu.label,
                )
            alert_status = self.db.recompute_alert_status(item.alert_id)
            self._emit(
                "delivery_updated",
                {"alert_id": item.alert_id, "delivery_id": item.delivery_id, "alert_status": alert_status},
            )
            return

        # TCP / TLS reliable delivery through emulated link + socket ACK/retry
        emu = self.link_emulator.transmit_path(route.links, frame_size)
        if not emu.ok:
            # Emulated link dropped the frame; mark WAITING_NETWORK for retry or backoff
            est_wait = self.compute_estimated_wait_sec(include_self=True)
            self.db.update_delivery(
                item.delivery_id,
                status="WAITING_NETWORK",
                attempts=prev_attempts + 1,
                route=route.path,
                estimated_wait_sec=est_wait,
                last_error=emu.reason,
            )
            self.db.recompute_alert_status(item.alert_id)
            self._emit(
                "delivery_updated",
                {"alert_id": item.alert_id, "delivery_id": item.delivery_id, "status": "WAITING_NETWORK"},
            )
            return

        res = server.send_alert(
            role,
            payload,
            priority=item.priority,
            flags=flags,
        )
        duration = time.monotonic() - t0
        with self._lock:
            self._dispatch_durations.append(duration)

        if res.ok:
            total_rtt_ms = (res.rtt_ms or 0.0) + emu.emulated_delay_ms
            self.db.update_delivery(
                item.delivery_id,
                status="ACKNOWLEDGED",
                client_id=res.client_id,
                attempts=prev_attempts + res.attempts,
                rtt_ms=total_rtt_ms,
                route=route.path,
                sent_at=sent_wall,
                ack_at=time.time(),
                clear_estimated_wait=True,
                last_error=f"Rerouted via {' -> '.join(route.path)} ({emu.label})" if rerouted else emu.label,
            )
            self.db.add_log(
                "INFO",
                "DISPATCHER",
                "DELIVERED_ACKED",
                {
                    "alert_id": item.alert_id,
                    "role": role,
                    "protocol": proto,
                    "rtt_ms": round(total_rtt_ms, 2),
                    "attempts": prev_attempts + res.attempts,
                    "rerouted": rerouted,
                    "route": route.path,
                },
            )
        elif res.offline:
            est_wait = self.compute_estimated_wait_sec(include_self=True)
            self.db.update_delivery(
                item.delivery_id,
                status="WAITING_NETWORK",
                attempts=prev_attempts + res.attempts,
                route=route.path,
                estimated_wait_sec=est_wait,
                last_error=res.error or "Responder disconnected",
            )
        else:
            self.db.update_delivery(
                item.delivery_id,
                status="FAILED",
                client_id=res.client_id,
                attempts=prev_attempts + res.attempts,
                route=route.path,
                sent_at=sent_wall,
                clear_estimated_wait=True,
                last_error=res.error or "ACK timeout",
            )

        alert_status = self.db.recompute_alert_status(item.alert_id)
        self._emit(
            "delivery_updated",
            {"alert_id": item.alert_id, "delivery_id": item.delivery_id, "alert_status": alert_status},
        )

    def _redelivery_loop(self) -> None:
        while not self._stop_event.wait(self.redelivery_interval_sec):
            waiting = self.db.get_deliveries(statuses=("WAITING_NETWORK",))
            if not waiting:
                continue

            est_wait = self.compute_estimated_wait_sec(include_self=False)
            for d in waiting:
                did = int(d["id"])
                with self._lock:
                    if did in self._in_queue_deliveries:
                        continue

                role = d["target_role"]
                proto = d["protocol"].upper()
                dst_node = config.ROLE_NODE_MAP.get(role, "TOWER_SOUTH")
                route = self.routing.dijkstra("ECC_HQ", dst_node)
                server = self._server_for_protocol(proto)
                client_online = server is not None and server.has_client(role)

                if route.reachable and client_online:
                    alert = self.db.get_alert(d["alert_id"])
                    if alert:
                        self.db.update_delivery(did, status="QUEUED", clear_estimated_wait=True)
                        self._enqueue_delivery(alert, d)
                        self.db.add_log(
                            "INFO",
                            "DISPATCHER",
                            "REDELIVERY_TRIGGERED",
                            {"alert_id": d["alert_id"], "role": role, "route": route.path},
                        )
                else:
                    self.db.update_delivery(did, estimated_wait_sec=est_wait)

