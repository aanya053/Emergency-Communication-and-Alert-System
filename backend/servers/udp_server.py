"""Connectionless UDP broadcast alert server with per-sender sequence numbers & measured loss.

Course Mapping:
- CO2 (Application-layer protocol): Speaks framed EMRG datagrams over UDP.
- CO3 (Transport): Fast connectionless broadcast without handshake/retransmission;
  receivers detect sequence-number gaps and report measured packet loss.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from backend import auth, config, protocol
from backend.db import Database
from backend.servers.tcp_server import DeliveryResult


@dataclass
class UdpSubscriber:
    client_id: str
    role: str
    addr: tuple[str, int]
    connected_at: float
    last_seen: float


class UdpAlertServer:
    """Connectionless UDP server for fast alert broadcasts and citizen warnings."""

    protocol_name = "UDP"

    def __init__(
        self,
        host: str = config.BIND_HOST,
        port: int = config.UDP_PORT,
        *,
        db: Database | None = None,
        metrics: Any = None,
        secret_file: Path | None = None,
        heartbeat_timeout_sec: float = config.HEARTBEAT_TIMEOUT_SEC,
    ) -> None:
        self.host = host
        self.port = port
        self.db = db
        self.metrics = metrics
        self.secret_file = secret_file
        self.heartbeat_timeout_sec = heartbeat_timeout_sec

        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._subscribers: dict[str, UdpSubscriber] = {}
        self._sender_seqs: dict[tuple[str, str], int] = {}
        self._pending_rtts: dict[tuple[str, int], tuple[float, str, str]] = {}  # (cid, seq) -> (sent_mono, alert_id, role)
        self._recv_thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._on_async_ack: Callable[[str, str, str, float], None] | None = None

    def set_async_ack_callback(self, cb: Callable[[str, str, str, float], None]) -> None:
        self._on_async_ack = cb

    def _next_sender_seq(self, sender_id: str, channel: str) -> int:
        with self._lock:
            key = (sender_id, channel)
            val = self._sender_seqs.get(key, 0) + 1
            self._sender_seqs[key] = val
            return val

    def _log(self, level: str, event: str, details: dict[str, Any] | str) -> None:
        if self.db is not None:
            try:
                self.db.add_log(level, "UDP_SERVER", event, details)
            except Exception:
                pass

    def start(self) -> None:
        if self._sock is not None:
            return
        self._stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self.port = sock.getsockname()[1]
        self._sock = sock

        self._recv_thread = threading.Thread(
            target=self._recv_loop,
            name="UDP-Recv",
            daemon=True,
        )
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="UDP-Watchdog",
            daemon=True,
        )
        self._recv_thread.start()
        self._watchdog_thread.start()
        self._log("INFO", "SERVER_STARTED", {"host": self.host, "port": self.port})

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        with self._lock:
            self._subscribers.clear()
            self._pending_rtts.clear()

        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2.0)
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=2.0)

    def _send_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._sock is not None:
            self._sock.sendto(data, addr)

    def _recv_loop(self) -> None:
        while not self._stop_event.is_set() and self._sock is not None:
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                frame = protocol.unpack(data)
            except protocol.IntegrityError as exc:
                self._log("ERROR", "UDP_CORRUPT_DATAGRAM", {"addr": f"{addr[0]}:{addr[1]}", "error": str(exc)})
                if self.metrics is not None:
                    self.metrics.record_crc_error()
                try:
                    self._send_datagram(
                        protocol.pack(protocol.MsgType.NACK, {"error": str(exc)}),
                        addr,
                    )
                except OSError:
                    pass
                continue

            if frame.msg_type == protocol.MsgType.REGISTER:
                self._handle_register(frame, addr)
            elif frame.msg_type == protocol.MsgType.HEARTBEAT:
                self._handle_heartbeat(frame, addr)
            elif frame.msg_type in (protocol.MsgType.ACK, protocol.MsgType.NACK):
                self._handle_feedback(frame, addr)

    def _handle_register(self, frame: protocol.Frame, addr: tuple[str, int]) -> None:
        token = frame.payload.get("token")
        claimed_role = frame.payload.get("role")
        client_id = str(frame.payload.get("client_id") or f"{claimed_role}-udp-{addr[0]}:{addr[1]}")
        try:
            claims = auth.verify_socket_credentials(
                token,
                claimed_role,
                secret_file=self.secret_file,
            )
        except auth.AuthError as exc:
            self._log("WARN", "UDP_AUTH_FAILED", {"addr": f"{addr[0]}:{addr[1]}", "error": str(exc)})
            try:
                self._send_datagram(
                    protocol.pack(protocol.MsgType.NACK, {"error": str(exc)}, seq=frame.seq),
                    addr,
                )
            except OSError:
                pass
            return

        now_wall = time.time()
        now_mono = time.monotonic()
        with self._lock:
            self._subscribers[client_id] = UdpSubscriber(
                client_id=client_id,
                role=claims["role"],
                addr=(addr[0], addr[1]),
                connected_at=now_wall,
                last_seen=now_mono,
            )
        try:
            self._send_datagram(
                protocol.pack(
                    protocol.MsgType.ACK,
                    {
                        "status": "registered",
                        "client_id": client_id,
                        "role": claims["role"],
                        "protocol": "UDP",
                    },
                    seq=frame.seq,
                ),
                addr,
            )
        except OSError:
            pass
        self._log(
            "INFO",
            "UDP_SUBSCRIBED",
            {"client_id": client_id, "role": claims["role"], "addr": f"{addr[0]}:{addr[1]}"},
        )

    def _handle_heartbeat(self, frame: protocol.Frame, addr: tuple[str, int]) -> None:
        now_mono = time.monotonic()
        cid = frame.payload.get("client_id")
        with self._lock:
            for sub in self._subscribers.values():
                if sub.client_id == cid or sub.addr == addr:
                    sub.last_seen = now_mono
        try:
            self._send_datagram(
                protocol.pack(
                    protocol.MsgType.ACK,
                    {"type": "heartbeat_ack", "ts": time.time()},
                    seq=frame.seq,
                ),
                addr,
            )
        except OSError:
            pass

    def _handle_feedback(self, frame: protocol.Frame, addr: tuple[str, int]) -> None:
        now_mono = time.monotonic()
        payload = frame.payload
        cid = str(payload.get("client_id") or "")
        with self._lock:
            for sub in self._subscribers.values():
                if sub.client_id == cid or sub.addr == addr:
                    sub.last_seen = now_mono
                    cid = sub.client_id
                    break

        if payload.get("report_type") == "loss_gap":
            lost_count = max(1, int(payload.get("lost_count", 1)))
            if self.metrics is not None:
                self.metrics.record_udp_gap_loss(lost_count)
            self._log(
                "WARN",
                "UDP_SEQUENCE_GAP_LOSS",
                {
                    "client_id": cid,
                    "sender_id": payload.get("sender_id"),
                    "expected_seq": payload.get("expected_seq"),
                    "received_seq": payload.get("received_seq"),
                    "lost_count": lost_count,
                },
            )
            return

        if frame.msg_type == protocol.MsgType.ACK:
            pending_entry: tuple[float, str, str] | None = None
            with self._lock:
                pending_entry = self._pending_rtts.pop((cid, frame.seq), None)
            if pending_entry is not None:
                sent_mono, alert_id, role = pending_entry
                rtt_ms = (now_mono - sent_mono) * 1000.0
                if self.metrics is not None:
                    self.metrics.record_ack("UDP", rtt_ms)
                if self._on_async_ack is not None:
                    self._on_async_ack(alert_id, role, cid, rtt_ms)

    def _watchdog_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            now_mono = time.monotonic()
            expired: list[UdpSubscriber] = []
            with self._lock:
                for cid, sub in list(self._subscribers.items()):
                    if now_mono - sub.last_seen > self.heartbeat_timeout_sec:
                        expired.append(sub)
                        del self._subscribers[cid]
                # Purge stale pending RTT entries older than 60s
                for key, (sent_mono, _, _) in list(self._pending_rtts.items()):
                    if now_mono - sent_mono > 60.0:
                        del self._pending_rtts[key]
            for sub in expired:
                self._log("WARN", "UDP_SUBSCRIBER_EXPIRED", {"client_id": sub.client_id, "role": sub.role})

    def connected_clients(self, role: str | None = None) -> list[dict[str, Any]]:
        now_mono = time.monotonic()
        with self._lock:
            subs = list(self._subscribers.values())
        return [
            {
                "client_id": s.client_id,
                "role": s.role,
                "protocol": "UDP",
                "addr": f"{s.addr[0]}:{s.addr[1]}",
                "connected_at": s.connected_at,
                "last_heartbeat_age_sec": round(now_mono - s.last_seen, 2),
            }
            for s in subs
            if role is None or s.role == role
        ]

    def has_client(self, role: str) -> bool:
        with self._lock:
            return any(s.role == role for s in self._subscribers.values())

    def send_alert(
        self,
        role: str,
        payload: dict[str, Any],
        *,
        priority: int = protocol.Priority.NORMAL,
        flags: int = 0,
        sender_id: str = "ECC_UDP",
        msg_type: protocol.MsgType = protocol.MsgType.BROADCAST,
        drop_packet: bool = False,
        on_bytes_sent: Callable[[int], None] | None = None,
    ) -> DeliveryResult:
        """Broadcast an EMRG UDP frame to subscribed clients for `role` (or all if role=='broadcast')."""
        with self._lock:
            if role in ("all", "broadcast"):
                targets = list(self._subscribers.values())
                channel = "broadcast"
            else:
                targets = [s for s in self._subscribers.values() if s.role == role]
                channel = role

        if not targets:
            return DeliveryResult(
                ok=False,
                protocol="UDP",
                attempts=0,
                offline=True,
                error=f"No UDP subscriber registered for role '{role}'",
            )

        seq = self._next_sender_seq(sender_id, channel)
        frame_payload = dict(payload)
        frame_payload["sender_id"] = sender_id
        frame_payload["sender_seq"] = seq
        frame_bytes = protocol.pack(
            msg_type,
            frame_payload,
            priority=priority,
            flags=flags,
            seq=seq,
        )

        if self.metrics is not None:
            self.metrics.record_tx("UDP", len(frame_bytes))
        if on_bytes_sent is not None:
            on_bytes_sent(len(frame_bytes))

        if drop_packet:
            # Emulated packet drop: sequence number was incremented, datagram is NOT transmitted,
            # so the next datagram will trigger real sequence-gap detection on receivers.
            self._log(
                "WARN",
                "UDP_PACKET_DROPPED",
                {"role": role, "sender_id": sender_id, "seq": seq, "alert_id": payload.get("alert_id")},
            )
            return DeliveryResult(
                ok=False,
                protocol="UDP",
                attempts=1,
                error="Dropped by emulated link queue (DropTail overflow)",
            )

        alert_id = str(payload.get("alert_id") or "")
        sent_mono = time.monotonic()
        sent_to: list[str] = []
        for sub in targets:
            with self._lock:
                self._pending_rtts[(sub.client_id, seq)] = (sent_mono, alert_id, sub.role)
            try:
                self._send_datagram(frame_bytes, sub.addr)
                sent_to.append(sub.client_id)
            except OSError:
                with self._lock:
                    self._pending_rtts.pop((sub.client_id, seq), None)

        if not sent_to:
            return DeliveryResult(ok=False, protocol="UDP", attempts=1, error="UDP sendto failed")

        return DeliveryResult(
            ok=True,
            protocol="UDP",
            attempts=1,
            rtt_ms=None,
            client_id=",".join(sent_to),
        )

