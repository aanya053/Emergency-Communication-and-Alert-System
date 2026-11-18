"""Standalone responder client process (Police, Ambulance, Fire, Hospital).

Connects over TCP (port 9001) or TLS 1.2+/1.3 (port 9003) using the EMRG binary
protocol, authenticates via REGISTER, deduplicates by alert_id, persists alerts
to a local inbox log as its real processing step, and returns ACK frames.
Can also attach a parallel UDP listener thread when --udp-port is provided.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path when invoked as `python clients/responder.py`
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend import auth, config, protocol


def fetch_token_via_api(api_url: str, username: str, password: str, retries: int = 15) -> str:
    """Authenticate against FastAPI /api/login to obtain an HMAC-signed token."""
    url = f"{api_url.rstrip('/')}/api/login"
    body = json.dumps({"username": username, "password": password}).encode("utf-8")
    last_err: Exception | None = None
    for _ in range(retries):
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return str(data["token"])
        except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
            last_err = exc
            time.sleep(0.5)
    raise RuntimeError(f"Failed to authenticate {username} at {url}: {last_err}")


class ResponderClient:
    """TCP/TLS responder process client with duplicate suppression and inbox persistence."""

    def __init__(
        self,
        *,
        role: str,
        server_host: str = "127.0.0.1",
        server_port: int | None = None,
        use_tls: bool = False,
        cafile: Path | None = None,
        token: str,
        client_id: str | None = None,
        inbox_path: Path | None = None,
        heartbeat_interval: float = config.HEARTBEAT_INTERVAL_SEC,
        udp_port: int | None = None,
        also_tcp_port: int | None = None,
    ) -> None:
        self.role = role
        self.server_host = server_host
        self.use_tls = use_tls
        self.server_port = server_port if server_port is not None else (config.TLS_PORT if use_tls else config.TCP_PORT)
        self.cafile = cafile if cafile is not None else config.TLS_CERT_FILE
        self.token = token
        self.client_id = client_id or f"{role}-{'tls' if use_tls else 'tcp'}-1"
        self.inbox_path = inbox_path or (config.DATA_DIR / f"inbox_{self.client_id}.jsonl")
        self.heartbeat_interval = heartbeat_interval
        self.udp_port = udp_port
        self.also_tcp_port = also_tcp_port

        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None
        self._write_lock = threading.Lock()
        self._seen_lock = threading.Lock()
        self._seen_alerts: set[str] = set()
        self.received_alerts: list[dict[str, Any]] = []
        self.duplicate_count = 0
        self._udp_last_seq: dict[str, int] = {}
        self.udp_loss_detected = 0

    def _connect_and_register(self) -> socket.socket:
        raw = socket.create_connection((self.server_host, self.server_port), timeout=5.0)
        if self.use_tls:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.cafile))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = True
            sock: socket.socket = ctx.wrap_socket(raw, server_hostname="localhost")
        else:
            sock = raw

        reg_bytes = protocol.pack(
            protocol.MsgType.REGISTER,
            {"token": self.token, "role": self.role, "client_id": self.client_id},
            seq=1,
        )
        sock.sendall(reg_bytes)
        resp = protocol.recv_frame(sock)
        if resp.msg_type == protocol.MsgType.NACK:
            sock.close()
            raise PermissionError(f"REGISTER rejected: {resp.payload.get('error')}")
        if resp.msg_type != protocol.MsgType.ACK:
            sock.close()
            raise RuntimeError(f"Unexpected REGISTER response: {resp.msg_type}")
        sock.settimeout(1.0)
        return sock

    def _process_alert(self, payload: dict[str, Any], channel: str) -> bool:
        """Real local processing step: validate fields, deduplicate by alert_id, persist to JSONL."""
        alert_id = str(payload.get("alert_id") or "")
        with self._seen_lock:
            is_dup = bool(alert_id and alert_id in self._seen_alerts)
            if alert_id and not is_dup:
                self._seen_alerts.add(alert_id)

        if is_dup:
            self.duplicate_count += 1
            print(f"[{self.client_id}] Duplicate alert suppressed: {alert_id}", flush=True)
            return False

        record = {
            "received_at": time.time(),
            "channel": channel,
            "role": self.role,
            "client_id": self.client_id,
            "alert": payload,
        }
        self.received_alerts.append(record)
        self.inbox_path.parent.mkdir(parents=True, exist_ok=True)
        with self.inbox_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

        print(
            f"[{self.client_id}] [{channel}] ALERT P{payload.get('priority', '?')} "
            f"{payload.get('alert_code', '')} - {payload.get('title', '')} @ {payload.get('location', '')}",
            flush=True,
        )
        return True

    def _send_frame(self, data: bytes) -> None:
        with self._write_lock:
            if self._sock is not None:
                self._sock.sendall(data)

    def _heartbeat_loop(self) -> None:
        seq = 100
        while not self._stop_event.wait(self.heartbeat_interval):
            seq += 1
            try:
                hb = protocol.pack(
                    protocol.MsgType.HEARTBEAT,
                    {"client_id": self.client_id, "role": self.role, "ts": time.time()},
                    seq=seq,
                )
                self._send_frame(hb)
            except OSError:
                break

    def _udp_listener_loop(self) -> None:
        if not self.udp_port:
            return
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(1.0)
        target = (self.server_host, self.udp_port)
        try:
            reg = protocol.pack(
                protocol.MsgType.REGISTER,
                {"token": self.token, "role": self.role, "client_id": f"{self.client_id}-udp"},
                seq=1,
            )
            udp_sock.sendto(reg, target)
            last_hb = time.monotonic()
            hb_seq = 1
            while not self._stop_event.is_set():
                if time.monotonic() - last_hb >= self.heartbeat_interval:
                    hb_seq += 1
                    try:
                        udp_sock.sendto(
                            protocol.pack(
                                protocol.MsgType.HEARTBEAT,
                                {"client_id": f"{self.client_id}-udp", "role": self.role},
                                seq=hb_seq,
                            ),
                            target,
                        )
                    except OSError:
                        pass
                    last_hb = time.monotonic()

                try:
                    data, addr = udp_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    frame = protocol.unpack(data)
                except protocol.IntegrityError:
                    continue

                if frame.msg_type in (protocol.MsgType.BROADCAST, protocol.MsgType.ALERT):
                    sender_id = str(frame.payload.get("sender_id") or "ECC_UDP")
                    prev = self._udp_last_seq.get(sender_id)
                    if prev is not None and frame.seq > prev + 1:
                        lost = frame.seq - prev - 1
                        self.udp_loss_detected += lost
                        gap_report = protocol.pack(
                            protocol.MsgType.NACK,
                            {
                                "report_type": "loss_gap",
                                "client_id": f"{self.client_id}-udp",
                                "sender_id": sender_id,
                                "expected_seq": prev + 1,
                                "received_seq": frame.seq,
                                "lost_count": lost,
                            },
                            seq=frame.seq,
                        )
                        udp_sock.sendto(gap_report, target)
                    self._udp_last_seq[sender_id] = max(prev or 0, frame.seq)
                    self._process_alert(frame.payload, "UDP")
                    ack = protocol.pack(
                        protocol.MsgType.ACK,
                        {
                            "alert_id": frame.payload.get("alert_id"),
                            "client_id": f"{self.client_id}-udp",
                            "role": self.role,
                        },
                        seq=frame.seq,
                    )
                    udp_sock.sendto(ack, target)
        finally:
            udp_sock.close()

    def run(self, *, reconnect: bool = True) -> None:
        if self.udp_port:
            udp_th = threading.Thread(target=self._udp_listener_loop, daemon=True)
            udp_th.start()
        if self.also_tcp_port and self.use_tls:
            tcp_helper = ResponderClient(
                role=self.role,
                server_host=self.server_host,
                server_port=self.also_tcp_port,
                use_tls=False,
                token=self.token,
                client_id=f"{self.role}-tcp-1",
                inbox_path=self.inbox_path,
                heartbeat_interval=self.heartbeat_interval,
            )
            tcp_helper._stop_event = self._stop_event
            tcp_helper._seen_alerts = self._seen_alerts
            tcp_helper._seen_lock = self._seen_lock
            threading.Thread(target=tcp_helper.run, kwargs={"reconnect": reconnect}, daemon=True).start()

        while not self._stop_event.is_set():
            try:
                sock = self._connect_and_register()
                self._sock = sock
                print(
                    f"[{self.client_id}] Connected ({'TLS' if self.use_tls else 'TCP'}) to "
                    f"{self.server_host}:{self.server_port} as {self.role}",
                    flush=True,
                )
                hb_th = threading.Thread(target=self._heartbeat_loop, daemon=True)
                hb_th.start()

                while not self._stop_event.is_set():
                    try:
                        frame = protocol.recv_frame(sock)
                    except socket.timeout:
                        continue
                    except protocol.IntegrityError as exc:
                        print(f"[{self.client_id}] IntegrityError: {exc}", flush=True)
                        continue

                    if frame.msg_type == protocol.MsgType.ALERT:
                        self._process_alert(frame.payload, "TLS" if self.use_tls else "TCP")
                        ack_bytes = protocol.pack(
                            protocol.MsgType.ACK,
                            {
                                "alert_id": frame.payload.get("alert_id"),
                                "client_id": self.client_id,
                                "role": self.role,
                                "ack_ts": time.time(),
                            },
                            seq=frame.seq,
                        )
                        self._send_frame(ack_bytes)
            except PermissionError as exc:
                print(f"[{self.client_id}] Auth rejected: {exc}", flush=True)
                raise
            except (OSError, ConnectionError, RuntimeError) as exc:
                if not reconnect or self._stop_event.is_set():
                    break
                print(f"[{self.client_id}] Connection lost ({exc}); reconnecting in 1.5s...", flush=True)
                self._stop_event.wait(1.5)
            finally:
                if self._sock is not None:
                    try:
                        self._sock.close()
                    except OSError:
                        pass
                    self._sock = None

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="ECAS Responder Socket Client")
    parser.add_argument("--role", required=True, choices=["police", "ambulance", "fire", "hospital"])
    parser.add_argument("--server", default="127.0.0.1", help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=None, help="Override TCP/TLS port")
    parser.add_argument("--tls", action="store_true", help="Use TLS 1.2+/1.3 channel")
    parser.add_argument("--cafile", type=Path, default=config.TLS_CERT_FILE, help="Server CA cert path")
    parser.add_argument("--udp-port", type=int, default=None, help="Optional UDP broadcast port")
    parser.add_argument("--also-tcp-port", type=int, default=None, help="Optional secondary plain TCP port when --tls is set")
    parser.add_argument("--api-url", default=f"http://127.0.0.1:{config.API_PORT}")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--client-id", default=None)
    args = parser.parse_args()

    token = args.token
    if not token:
        username = args.username or args.role
        password = args.password or auth.DEFAULT_SEED_USERS[args.role][0]
        token = fetch_token_via_api(args.api_url, username, password)

    client = ResponderClient(
        role=args.role,
        server_host=args.server,
        server_port=args.port,
        use_tls=args.tls,
        cafile=args.cafile,
        token=token,
        client_id=args.client_id,
        udp_port=args.udp_port,
        also_tcp_port=args.also_tcp_port,
    )
    try:
        client.run(reconnect=True)
    except KeyboardInterrupt:
        client.stop()


if __name__ == "__main__":
    main()
