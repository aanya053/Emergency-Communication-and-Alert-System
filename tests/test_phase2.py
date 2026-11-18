"""Phase 2 tests: TCP, TLS, UDP servers and Responder / Citizen clients."""

from __future__ import annotations

import socket
import ssl
import threading
import time

import pytest

from backend import auth, protocol
from backend.db import Database
from backend.servers.tcp_server import TcpAlertServer
from backend.servers.tls_server import TlsAlertServer
from backend.servers.udp_server import UdpAlertServer
from clients.citizen import CitizenClient
from clients.responder import ResponderClient


def test_tcp_register_auth_ack_rtt_and_dedupe(tmp_path) -> None:
    secret_file = tmp_path / ".secret"
    db = Database(tmp_path / "tcp.db")
    srv = TcpAlertServer(
        "127.0.0.1",
        0,
        db=db,
        secret_file=secret_file,
        ack_timeout_sec=0.5,
        max_retries=2,
        backoff_base_sec=0.1,
    )
    srv.start()
    try:
        # 1) Wrong role vs token must be rejected
        bad_token = auth.create_token("fire", "fire", secret_file=secret_file)
        with socket.create_connection(("127.0.0.1", srv.port), timeout=2.0) as bad_sock:
            bad_sock.sendall(
                protocol.pack(
                    protocol.MsgType.REGISTER,
                    {"token": bad_token, "role": "police", "client_id": "fake-pol"},
                    seq=1,
                )
            )
            resp = protocol.recv_frame(bad_sock)
            assert resp.msg_type == protocol.MsgType.NACK

        # 2) Valid ResponderClient connects and processes alerts + deduplicates
        pol_token = auth.create_token("police", "police", secret_file=secret_file)
        client = ResponderClient(
            role="police",
            server_host="127.0.0.1",
            server_port=srv.port,
            use_tls=False,
            token=pol_token,
            client_id="police-test-1",
            inbox_path=tmp_path / "inbox_police.jsonl",
            heartbeat_interval=1.0,
        )
        th = threading.Thread(target=client.run, kwargs={"reconnect": False}, daemon=True)
        th.start()

        deadline = time.monotonic() + 3.0
        while not srv.has_client("police") and time.monotonic() < deadline:
            time.sleep(0.05)
        assert srv.has_client("police")

        payload = {"alert_id": "AL-100", "alert_code": "POL-100", "title": "Intrusion", "priority": 1}
        res1 = srv.send_alert("police", payload, priority=protocol.Priority.CRITICAL)
        assert res1.ok is True
        assert res1.attempts == 1
        assert res1.rtt_ms is not None and res1.rtt_ms >= 0.0

        # Send same alert_id again -> client deduplicates, still ACKs
        res2 = srv.send_alert("police", payload, priority=protocol.Priority.CRITICAL)
        assert res2.ok is True
        assert len(client.received_alerts) == 1
        assert client.duplicate_count == 1

        client.stop()
        th.join(timeout=2.0)
    finally:
        srv.stop()
        db.close_all()


def test_tcp_retransmission_backoff_when_first_ack_missing(tmp_path) -> None:
    secret_file = tmp_path / ".secret"
    srv = TcpAlertServer(
        "127.0.0.1",
        0,
        secret_file=secret_file,
        ack_timeout_sec=0.15,
        max_retries=2,
        backoff_base_sec=0.05,
    )
    srv.start()
    try:
        tok = auth.create_token("fire", "fire", secret_file=secret_file)
        sock = socket.create_connection(("127.0.0.1", srv.port), timeout=2.0)
        sock.sendall(
            protocol.pack(
                protocol.MsgType.REGISTER,
                {"token": tok, "role": "fire", "client_id": "fire-raw"},
                seq=1,
            )
        )
        reg_ack = protocol.recv_frame(sock)
        assert reg_ack.msg_type == protocol.MsgType.ACK

        def _client_behavior() -> None:
            # Receive attempt 1 and intentionally do NOT ACK it
            f1 = protocol.recv_frame(sock)
            assert f1.payload["attempt"] == 1
            # Receive attempt 2 and ACK it
            f2 = protocol.recv_frame(sock)
            assert f2.payload["attempt"] == 2
            sock.sendall(
                protocol.pack(
                    protocol.MsgType.ACK,
                    {"alert_id": f2.payload["alert_id"], "client_id": "fire-raw"},
                    seq=f2.seq,
                )
            )

        ct = threading.Thread(target=_client_behavior, daemon=True)
        ct.start()
        res = srv.send_alert("fire", {"alert_id": "AL-RETRY", "title": "Fire"})
        ct.join(timeout=3.0)
        sock.close()

        assert res.ok is True
        assert res.attempts == 2
        assert res.rtt_ms is not None
    finally:
        srv.stop()


def test_tls_cert_verification_and_alert(tmp_path) -> None:
    secret_file = tmp_path / ".secret"
    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"
    srv = TlsAlertServer(
        "127.0.0.1",
        0,
        cert_file=cert_file,
        key_file=key_file,
        secret_file=secret_file,
    )
    srv.start()
    try:
        assert cert_file.exists() and key_file.exists()

        # Connecting without trusting cafile must fail cert verification
        raw = socket.create_connection(("127.0.0.1", srv.port), timeout=2.0)
        untrusted_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        with pytest.raises(ssl.SSLError):
            untrusted_ctx.wrap_socket(raw, server_hostname="localhost")
        raw.close()

        # Connecting with cafile succeeds over TLS 1.2+
        hosp_tok = auth.create_token("hospital", "hospital", secret_file=secret_file)
        client = ResponderClient(
            role="hospital",
            server_host="127.0.0.1",
            server_port=srv.port,
            use_tls=True,
            cafile=cert_file,
            token=hosp_tok,
            client_id="hospital-tls-1",
            inbox_path=tmp_path / "inbox_hosp.jsonl",
        )
        th = threading.Thread(target=client.run, kwargs={"reconnect": False}, daemon=True)
        th.start()

        deadline = time.monotonic() + 3.0
        while not srv.has_client("hospital") and time.monotonic() < deadline:
            time.sleep(0.05)
        assert srv.has_client("hospital")

        res = srv.send_alert(
            "hospital",
            {"alert_id": "AL-TLS-1", "title": "Patient Trauma", "sensitive": True},
            flags=protocol.FLAG_SENSITIVE,
        )
        assert res.ok is True
        assert res.protocol == "TLS"
        assert len(client.received_alerts) == 1

        client.stop()
        th.join(timeout=2.0)
    finally:
        srv.stop()


def test_udp_sequence_gap_loss_detection(tmp_path) -> None:
    secret_file = tmp_path / ".secret"
    db = Database(tmp_path / "udp.db")
    srv = UdpAlertServer("127.0.0.1", 0, db=db, secret_file=secret_file)
    srv.start()
    try:
        tok = auth.create_token("citizen", "citizen", secret_file=secret_file)
        cit = CitizenClient(
            server_host="127.0.0.1",
            server_port=srv.port,
            token=tok,
            client_id="cit-test-1",
            inbox_path=tmp_path / "inbox_cit.jsonl",
        )
        th = threading.Thread(target=cit.run, daemon=True)
        th.start()

        deadline = time.monotonic() + 3.0
        while not srv.has_client("citizen") and time.monotonic() < deadline:
            time.sleep(0.05)
        assert srv.has_client("citizen")

        # Packet 1 delivered
        r1 = srv.send_alert("citizen", {"alert_id": "U-1", "title": "Flood Warning"})
        assert r1.ok is True
        # Packet 2 dropped in transit (seq advances, datagram not sent)
        r2 = srv.send_alert("citizen", {"alert_id": "U-2", "title": "Flood Update"}, drop_packet=True)
        assert r2.ok is False
        # Packet 3 delivered -> receiver detects gap (expected 2, got 3)
        r3 = srv.send_alert("citizen", {"alert_id": "U-3", "title": "Evacuate"})
        assert r3.ok is True

        deadline = time.monotonic() + 2.0
        while cit.total_lost_packets == 0 and time.monotonic() < deadline:
            time.sleep(0.05)

        assert cit.total_lost_packets == 1
        assert len(cit.received_alerts) == 2

        cit.stop()
        th.join(timeout=2.0)
    finally:
        srv.stop()
        db.close_all()

