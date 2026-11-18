"""Standalone Citizen UDP broadcast client for ECAS.

Subscribes via authenticated REGISTER datagram on UDP port 9002, detects
per-sender sequence-number gaps to measure real packet loss, suppresses
duplicates by alert_id, persists received alerts locally, and sends feedback.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend import auth, config, protocol
from clients.responder import fetch_token_via_api


class CitizenClient:
    """UDP citizen client with sequence-gap loss detection."""

    def __init__(
        self,
        *,
        server_host: str = "127.0.0.1",
        server_port: int = config.UDP_PORT,
        token: str,
        role: str = "citizen",
        client_id: str = "citizen-udp-1",
        inbox_path: Path | None = None,
        heartbeat_interval: float = config.HEARTBEAT_INTERVAL_SEC,
    ) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.token = token
        self.role = role
        self.client_id = client_id
        self.inbox_path = inbox_path or (config.DATA_DIR / f"inbox_{self.client_id}.jsonl")
        self.heartbeat_interval = heartbeat_interval

        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None
        self._seen_alerts: set[str] = set()
        self._last_seq_by_sender: dict[str, int] = {}
        self.received_alerts: list[dict[str, Any]] = []
        self.detected_losses: list[dict[str, Any]] = []
        self.total_lost_packets = 0

    def register(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        target = (self.server_host, self.server_port)
        reg = protocol.pack(
            protocol.MsgType.REGISTER,
            {"token": self.token, "role": self.role, "client_id": self.client_id},
            seq=1,
        )
        sock.sendto(reg, target)
        data, _ = sock.recvfrom(65535)
        frame = protocol.unpack(data)
        if frame.msg_type == protocol.MsgType.NACK:
            sock.close()
            raise PermissionError(f"UDP REGISTER rejected: {frame.payload.get('error')}")
        if frame.msg_type != protocol.MsgType.ACK:
            sock.close()
            raise RuntimeError(f"Unexpected UDP REGISTER response: {frame.msg_type}")
        sock.settimeout(1.0)
        self._sock = sock
        return sock

    def run(self) -> None:
        sock = self.register()
        target = (self.server_host, self.server_port)
        print(f"[{self.client_id}] Subscribed (UDP) to {self.server_host}:{self.server_port}", flush=True)
        last_hb = time.monotonic()
        hb_seq = 1

        try:
            while not self._stop_event.is_set():
                if time.monotonic() - last_hb >= self.heartbeat_interval:
                    hb_seq += 1
                    try:
                        sock.sendto(
                            protocol.pack(
                                protocol.MsgType.HEARTBEAT,
                                {"client_id": self.client_id, "role": self.role, "ts": time.time()},
                                seq=hb_seq,
                            ),
                            target,
                        )
                    except OSError:
                        pass
                    last_hb = time.monotonic()

                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    frame = protocol.unpack(data)
                except protocol.IntegrityError as exc:
                    print(f"[{self.client_id}] Corrupt UDP frame: {exc}", flush=True)
                    continue

                if frame.msg_type in (protocol.MsgType.BROADCAST, protocol.MsgType.ALERT):
                    self._handle_broadcast(sock, target, frame)
        finally:
            sock.close()
            self._sock = None

    def _handle_broadcast(
        self,
        sock: socket.socket,
        target: tuple[str, int],
        frame: protocol.Frame,
    ) -> None:
        sender_id = str(frame.payload.get("sender_id") or "ECC_UDP")
        prev_seq = self._last_seq_by_sender.get(sender_id)
        if prev_seq is not None and frame.seq > prev_seq + 1:
            lost = frame.seq - prev_seq - 1
            self.total_lost_packets += lost
            gap_info = {
                "sender_id": sender_id,
                "expected_seq": prev_seq + 1,
                "received_seq": frame.seq,
                "lost_count": lost,
            }
            self.detected_losses.append(gap_info)
            print(f"[{self.client_id}] UDP sequence gap detected: {gap_info}", flush=True)
            report = protocol.pack(
                protocol.MsgType.NACK,
                {
                    "report_type": "loss_gap",
                    "client_id": self.client_id,
                    **gap_info,
                },
                seq=frame.seq,
            )
            sock.sendto(report, target)

        self._last_seq_by_sender[sender_id] = max(prev_seq or 0, frame.seq)

        alert_id = str(frame.payload.get("alert_id") or "")
        if not alert_id or alert_id not in self._seen_alerts:
            if alert_id:
                self._seen_alerts.add(alert_id)
            record = {
                "received_at": time.time(),
                "channel": "UDP",
                "role": self.role,
                "client_id": self.client_id,
                "seq": frame.seq,
                "alert": frame.payload,
            }
            self.received_alerts.append(record)
            self.inbox_path.parent.mkdir(parents=True, exist_ok=True)
            with self.inbox_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            print(
                f"[{self.client_id}] [UDP seq={frame.seq}] {frame.payload.get('alert_code', '')} "
                f"- {frame.payload.get('title', '')} @ {frame.payload.get('location', '')}",
                flush=True,
            )

        ack = protocol.pack(
            protocol.MsgType.ACK,
            {
                "alert_id": alert_id,
                "client_id": self.client_id,
                "role": self.role,
                "ack_ts": time.time(),
            },
            seq=frame.seq,
        )
        sock.sendto(ack, target)

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="ECAS Citizen UDP Client")
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=config.UDP_PORT)
    parser.add_argument("--api-url", default=f"http://127.0.0.1:{config.API_PORT}")
    parser.add_argument("--username", default="citizen")
    parser.add_argument("--password", default=auth.DEFAULT_SEED_USERS["citizen"][0])
    parser.add_argument("--token", default=None)
    parser.add_argument("--client-id", default="citizen-udp-1")
    args = parser.parse_args()

    token = args.token or fetch_token_via_api(args.api_url, args.username, args.password)
    client = CitizenClient(
        server_host=args.server,
        server_port=args.port,
        token=token,
        client_id=args.client_id,
    )
    try:
        client.run()
    except KeyboardInterrupt:
        client.stop()


if __name__ == "__main__":
    main()

