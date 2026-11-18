"""Threaded TCP alert server with authenticated REGISTER, heartbeats, ACK/RTT, and backoff retries.

Course Mapping:
- CO2 (Application-layer protocol): Speaks framed EMRG protocol over TCP streams.
- CO3 (Transport): Connection-oriented reliable delivery, server-measured RTT,
  retransmission timeout with exponential backoff, and dead-client heartbeat eviction.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from backend import auth, config, protocol
from backend.db import Database


@dataclass
class ClientSession:
    client_id: str
    role: str
    sock: socket.socket
    addr: tuple[str, int]
    protocol_name: str
    connected_at: float
    last_heartbeat: float
    write_lock: threading.Lock = field(default_factory=threading.Lock)

    def send_frame_bytes(self, data: bytes) -> None:
        with self.write_lock:
            self.sock.sendall(data)


@dataclass
class PendingAck:
    event: threading.Event
    sent_mono: float
    ack_mono: float | None = None
    error: str | None = None


@dataclass
class DeliveryResult:
    ok: bool
    protocol: str
    attempts: int
    rtt_ms: float | None = None
    client_id: str | None = None
    offline: bool = False
    error: str | None = None
    client_rtts: list[tuple[str, float]] = field(default_factory=list)


class TcpAlertServer:
    """Threaded TCP server managing authenticated responder connections."""

    protocol_name = "TCP"

    def __init__(
        self,
        host: str = config.BIND_HOST,
        port: int = config.TCP_PORT,
        *,
        db: Database | None = None,
        metrics: Any = None,
        secret_file: Path | None = None,
        ack_timeout_sec: float = config.ACK_TIMEOUT_SEC,
        max_retries: int = config.MAX_RETRIES,
        backoff_base_sec: float = config.BACKOFF_BASE_SEC,
        heartbeat_timeout_sec: float = config.HEARTBEAT_TIMEOUT_SEC,
    ) -> None:
        self.host = host
        self.port = port
        self.db = db
        self.metrics = metrics
        self.secret_file = secret_file
        self.ack_timeout_sec = ack_timeout_sec
        self.max_retries = max_retries
        self.backoff_base_sec = backoff_base_sec
        self.heartbeat_timeout_sec = heartbeat_timeout_sec

        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._clients: dict[str, ClientSession] = {}
        self._pending_by_seq: dict[tuple[str, int], PendingAck] = {}
        self._pending_by_alert: dict[tuple[str, str], PendingAck] = {}
        self._seq_counter = 0
        self._accept_thread: threading.Thread | None = None
        self._watchdog_thread: threading.Thread | None = None
        self._client_threads: list[threading.Thread] = []
        self._on_async_ack: Callable[[str, str, str, float], None] | None = None

    def set_async_ack_callback(self, cb: Callable[[str, str, str, float], None]) -> None:
        """Optional callback(alert_id, role, client_id, rtt_ms) for late/unsolicited ACKs."""
        self._on_async_ack = cb

    def _next_seq(self) -> int:
        with self._lock:
            self._seq_counter = (self._seq_counter % 0xFFFFFFFE) + 1
            return self._seq_counter

    def _log(self, level: str, event: str, details: dict[str, Any] | str) -> None:
        if self.db is not None:
            try:
                self.db.add_log(level, f"{self.protocol_name}_SERVER", event, details)
            except Exception:
                pass

    def _wrap_client_socket(self, conn: socket.socket) -> socket.socket:
        return conn

    def start(self) -> None:
        if self._sock is not None:
            return
        self._stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(128)
        sock.settimeout(0.5)
        self.port = sock.getsockname()[1]
        self._sock = sock

        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"{self.protocol_name}-Accept",
            daemon=True,
        )
        self._watchdog_thread = threading.Thread(
            target=self._heartbeat_watchdog,
            name=f"{self.protocol_name}-Watchdog",
            daemon=True,
        )
        self._accept_thread.start()
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
            sessions = list(self._clients.values())
            self._clients.clear()
            for pending in list(self._pending_by_seq.values()):
                pending.error = "Server stopped"
                pending.event.set()
            self._pending_by_seq.clear()
            self._pending_by_alert.clear()

        for session in sessions:
            try:
                session.sock.close()
            except OSError:
                pass

        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=2.0)
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set() and self._sock is not None:
            try:
                raw_conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_client,
                args=(raw_conn, addr),
                name=f"{self.protocol_name}-Client-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            with self._lock:
                self._client_threads = [th for th in self._client_threads if th.is_alive()]
                self._client_threads.append(t)
            t.start()

    def _handle_client(self, raw_conn: socket.socket, addr: tuple[str, int]) -> None:
        conn: socket.socket | None = None
        session: ClientSession | None = None
        try:
            raw_conn.settimeout(5.0)
            conn = self._wrap_client_socket(raw_conn)
            reg_frame = protocol.recv_frame(conn)
            if reg_frame.msg_type != protocol.MsgType.REGISTER:
                self._send_nack(conn, reg_frame.seq, "First frame must be REGISTER")
                return

            token = reg_frame.payload.get("token")
            claimed_role = reg_frame.payload.get("role")
            client_id = str(reg_frame.payload.get("client_id") or f"{claimed_role}-{addr[0]}:{addr[1]}")

            try:
                claims = auth.verify_socket_credentials(
                    token,
                    claimed_role,
                    secret_file=self.secret_file,
                )
            except auth.AuthError as exc:
                self._send_nack(conn, reg_frame.seq, str(exc))
                self._log("WARN", "AUTH_FAILED", {"addr": f"{addr[0]}:{addr[1]}", "error": str(exc)})
                return

            now_wall = time.time()
            now_mono = time.monotonic()
            session = ClientSession(
                client_id=client_id,
                role=claims["role"],
                sock=conn,
                addr=(addr[0], addr[1]),
                protocol_name=self.protocol_name,
                connected_at=now_wall,
                last_heartbeat=now_mono,
            )

            with self._lock:
                old = self._clients.get(client_id)
                if old is not None:
                    try:
                        old.sock.close()
                    except OSError:
                        pass
                self._clients[client_id] = session

            ack_bytes = protocol.pack(
                protocol.MsgType.ACK,
                {
                    "status": "registered",
                    "client_id": client_id,
                    "role": claims["role"],
                    "protocol": self.protocol_name,
                },
                seq=reg_frame.seq,
            )
            session.send_frame_bytes(ack_bytes)
            self._log(
                "INFO",
                "CLIENT_REGISTERED",
                {"client_id": client_id, "role": claims["role"], "addr": f"{addr[0]}:{addr[1]}"},
            )

            conn.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    frame = protocol.recv_frame(conn)
                except socket.timeout:
                    continue
                except protocol.IntegrityError as exc:
                    self._log("ERROR", "FRAME_CORRUPTION", {"client_id": client_id, "error": str(exc)})
                    if self.metrics is not None:
                        self.metrics.record_crc_error()
                    try:
                        nack_bytes = protocol.pack(
                            protocol.MsgType.NACK,
                            {"error": str(exc)},
                            seq=0,
                        )
                        session.send_frame_bytes(nack_bytes)
                    except OSError:
                        break
                    continue

                session.last_heartbeat = time.monotonic()
                if frame.msg_type == protocol.MsgType.HEARTBEAT:
                    hb_ack = protocol.pack(
                        protocol.MsgType.ACK,
                        {"type": "heartbeat_ack", "ts": time.time()},
                        seq=frame.seq,
                    )
                    session.send_frame_bytes(hb_ack)
                elif frame.msg_type == protocol.MsgType.ACK:
                    self._resolve_ack(session, frame)
                elif frame.msg_type == protocol.MsgType.NACK:
                    self._resolve_nack(session, frame)

        except (ConnectionError, OSError, protocol.IntegrityError, ValueError) as exc:
            if session is not None and not self._stop_event.is_set():
                self._log("WARN", "CLIENT_DISCONNECTED", {"client_id": session.client_id, "reason": str(exc)})
        finally:
            if session is not None:
                with self._lock:
                    if self._clients.get(session.client_id) is session:
                        del self._clients[session.client_id]
            target = conn if conn is not None else raw_conn
            try:
                target.close()
            except OSError:
                pass

    def _send_nack(self, conn: socket.socket, seq: int, error: str) -> None:
        try:
            conn.sendall(protocol.pack(protocol.MsgType.NACK, {"error": error}, seq=seq))
        except OSError:
            pass

    def _resolve_ack(self, session: ClientSession, frame: protocol.Frame) -> None:
        ack_mono = time.monotonic()
        alert_id = frame.payload.get("alert_id")
        matched = False
        with self._lock:
            pending = self._pending_by_seq.pop((session.client_id, frame.seq), None)
            if pending is None and alert_id:
                pending = self._pending_by_alert.pop((session.client_id, str(alert_id)), None)
            if pending is not None:
                if alert_id:
                    self._pending_by_alert.pop((session.client_id, str(alert_id)), None)
                self._pending_by_seq.pop((session.client_id, frame.seq), None)
                pending.ack_mono = ack_mono
                pending.event.set()
                matched = True

        if not matched and alert_id and self._on_async_ack is not None:
            self._on_async_ack(str(alert_id), session.role, session.client_id, 0.0)

    def _resolve_nack(self, session: ClientSession, frame: protocol.Frame) -> None:
        alert_id = frame.payload.get("alert_id")
        err = str(frame.payload.get("error") or "Client returned NACK")
        with self._lock:
            pending = self._pending_by_seq.pop((session.client_id, frame.seq), None)
            if pending is None and alert_id:
                pending = self._pending_by_alert.pop((session.client_id, str(alert_id)), None)
            if pending is not None:
                pending.error = err
                pending.event.set()

    def _heartbeat_watchdog(self) -> None:
        while not self._stop_event.wait(1.0):
            now_mono = time.monotonic()
            dead: list[ClientSession] = []
            with self._lock:
                for cid, session in list(self._clients.items()):
                    if now_mono - session.last_heartbeat > self.heartbeat_timeout_sec:
                        dead.append(session)
                        del self._clients[cid]
            for session in dead:
                self._log(
                    "WARN",
                    "HEARTBEAT_TIMEOUT",
                    {"client_id": session.client_id, "role": session.role},
                )
                try:
                    session.sock.close()
                except OSError:
                    pass

    def connected_clients(self, role: str | None = None) -> list[dict[str, Any]]:
        now_mono = time.monotonic()
        with self._lock:
            sessions = list(self._clients.values())
        out: list[dict[str, Any]] = []
        for s in sessions:
            if role is not None and s.role != role:
                continue
            out.append(
                {
                    "client_id": s.client_id,
                    "role": s.role,
                    "protocol": s.protocol_name,
                    "addr": f"{s.addr[0]}:{s.addr[1]}",
                    "connected_at": s.connected_at,
                    "last_heartbeat_age_sec": round(now_mono - s.last_heartbeat, 2),
                }
            )
        return out

    def has_client(self, role: str) -> bool:
        with self._lock:
            return any(s.role == role for s in self._clients.values())

    def send_alert(
        self,
        role: str,
        payload: dict[str, Any],
        *,
        priority: int = protocol.Priority.NORMAL,
        flags: int = 0,
        ack_timeout: float | None = None,
        max_retries: int | None = None,
        backoff_base: float | None = None,
        on_bytes_sent: Callable[[int], None] | None = None,
    ) -> DeliveryResult:
        """Send an alert frame to connected clients of `role` with ACK & exponential backoff."""
        with self._lock:
            targets = [s for s in self._clients.values() if s.role == role]

        if not targets:
            return DeliveryResult(
                ok=False,
                protocol=self.protocol_name,
                attempts=0,
                offline=True,
                error=f"No {self.protocol_name} client connected for role '{role}'",
            )

        timeout = ack_timeout if ack_timeout is not None else self.ack_timeout_sec
        retries = max_retries if max_retries is not None else self.max_retries
        backoff = backoff_base if backoff_base is not None else self.backoff_base_sec

        if len(targets) == 1:
            return self._send_to_session(
                targets[0],
                payload,
                priority=priority,
                flags=flags,
                ack_timeout=timeout,
                max_retries=retries,
                backoff_base=backoff,
                on_bytes_sent=on_bytes_sent,
            )

        # Multiple clients registered for the same role: send concurrently and aggregate
        results: list[DeliveryResult] = []
        res_lock = threading.Lock()

        def _worker(sess: ClientSession) -> None:
            r = self._send_to_session(
                sess,
                payload,
                priority=priority,
                flags=flags,
                ack_timeout=timeout,
                max_retries=retries,
                backoff_base=backoff,
                on_bytes_sent=on_bytes_sent,
            )
            with res_lock:
                results.append(r)

        threads = [threading.Thread(target=_worker, args=(s,), daemon=True) for s in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        acked = [r for r in results if r.ok and r.rtt_ms is not None]
        if acked:
            avg_rtt = sum(r.rtt_ms for r in acked if r.rtt_ms is not None) / len(acked)
            max_att = max(r.attempts for r in results)
            return DeliveryResult(
                ok=True,
                protocol=self.protocol_name,
                attempts=max_att,
                rtt_ms=avg_rtt,
                client_id=",".join(r.client_id or "" for r in acked),
                client_rtts=[(r.client_id or "", r.rtt_ms or 0.0) for r in acked],
            )
        first_err = results[0].error if results else "Delivery failed"
        return DeliveryResult(
            ok=False,
            protocol=self.protocol_name,
            attempts=max((r.attempts for r in results), default=1),
            error=first_err,
        )

    def _send_to_session(
        self,
        session: ClientSession,
        payload: dict[str, Any],
        *,
        priority: int,
        flags: int,
        ack_timeout: float,
        max_retries: int,
        backoff_base: float,
        on_bytes_sent: Callable[[int], None] | None,
    ) -> DeliveryResult:
        alert_id = str(payload.get("alert_id") or "")
        max_attempts = 1 + max(0, max_retries)
        last_error = "ACK timeout"

        for attempt in range(1, max_attempts + 1):
            if self._stop_event.is_set():
                return DeliveryResult(
                    ok=False,
                    protocol=self.protocol_name,
                    attempts=attempt - 1,
                    client_id=session.client_id,
                    error="Server stopping",
                )

            seq = self._next_seq()
            frame_payload = dict(payload)
            frame_payload["attempt"] = attempt
            frame_bytes = protocol.pack(
                protocol.MsgType.ALERT,
                frame_payload,
                priority=priority,
                flags=flags | protocol.FLAG_ACK_REQUIRED,
                seq=seq,
            )

            pending = PendingAck(event=threading.Event(), sent_mono=time.monotonic())
            with self._lock:
                self._pending_by_seq[(session.client_id, seq)] = pending
                if alert_id:
                    self._pending_by_alert[(session.client_id, alert_id)] = pending

            try:
                pending.sent_mono = time.monotonic()
                session.send_frame_bytes(frame_bytes)
                if on_bytes_sent is not None:
                    on_bytes_sent(len(frame_bytes))
                if self.metrics is not None:
                    self.metrics.record_tx(self.protocol_name, len(frame_bytes))
            except OSError as exc:
                with self._lock:
                    self._pending_by_seq.pop((session.client_id, seq), None)
                    if alert_id:
                        self._pending_by_alert.pop((session.client_id, alert_id), None)
                return DeliveryResult(
                    ok=False,
                    protocol=self.protocol_name,
                    attempts=attempt,
                    client_id=session.client_id,
                    offline=True,
                    error=f"Socket send failed: {exc}",
                )

            got_signal = pending.event.wait(timeout=ack_timeout)
            with self._lock:
                self._pending_by_seq.pop((session.client_id, seq), None)
                if alert_id and self._pending_by_alert.get((session.client_id, alert_id)) is pending:
                    self._pending_by_alert.pop((session.client_id, alert_id), None)

            if got_signal and pending.ack_mono is not None and pending.error is None:
                rtt_ms = (pending.ack_mono - pending.sent_mono) * 1000.0
                if self.metrics is not None:
                    self.metrics.record_ack(self.protocol_name, rtt_ms)
                return DeliveryResult(
                    ok=True,
                    protocol=self.protocol_name,
                    attempts=attempt,
                    rtt_ms=rtt_ms,
                    client_id=session.client_id,
                    client_rtts=[(session.client_id, rtt_ms)],
                )

            last_error = pending.error or f"ACK timeout after {ack_timeout:.2f}s"
            if self.metrics is not None:
                self.metrics.record_timeout(self.protocol_name)
            self._log(
                "WARN",
                "ACK_TIMEOUT_RETRY",
                {
                    "client_id": session.client_id,
                    "alert_id": alert_id,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                },
            )
            if attempt < max_attempts:
                delay = backoff_base * (2 ** (attempt - 1))
                if self._stop_event.wait(delay):
                    break

        return DeliveryResult(
            ok=False,
            protocol=self.protocol_name,
            attempts=max_attempts,
            client_id=session.client_id,
            error=last_error,
        )

