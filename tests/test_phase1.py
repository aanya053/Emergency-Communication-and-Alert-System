"""Phase 1 tests: EMRG binary protocol + CRC32, SQLite WAL DB, PBKDF2/HMAC Auth."""

from __future__ import annotations

import socket
import struct
import time

import pytest

from backend import auth, protocol
from backend.db import Database


def test_protocol_pack_unpack_roundtrip() -> None:
    payload = {"alert_id": "a-1", "title": "Fire", "location": "Sector 62"}
    raw = protocol.pack(
        protocol.MsgType.ALERT,
        payload,
        priority=protocol.Priority.CRITICAL,
        flags=protocol.FLAG_SENSITIVE | protocol.FLAG_ACK_REQUIRED,
        seq=42,
    )
    frame = protocol.unpack(raw)
    assert frame.version == protocol.PROTOCOL_VERSION
    assert frame.msg_type == protocol.MsgType.ALERT
    assert frame.priority == protocol.Priority.CRITICAL
    assert frame.flags == (protocol.FLAG_SENSITIVE | protocol.FLAG_ACK_REQUIRED)
    assert frame.seq == 42
    assert frame.payload == payload


def test_protocol_crc_corruption_raises_integrity_error() -> None:
    raw = bytearray(protocol.pack(protocol.MsgType.HEARTBEAT, {"ts": 1234.5}, seq=7))
    # Flip a byte in the payload
    raw[-1] ^= 0xFF
    with pytest.raises(protocol.IntegrityError):
        protocol.unpack(bytes(raw))

    # Flip a byte in the header (flags byte at index 7)
    raw2 = bytearray(protocol.pack(protocol.MsgType.ACK, {"alert_id": "x"}, seq=8))
    raw2[7] ^= 0x01
    with pytest.raises(protocol.IntegrityError):
        protocol.unpack(bytes(raw2))


def test_protocol_bad_magic_and_oversized_payload() -> None:
    raw = bytearray(protocol.pack(protocol.MsgType.REGISTER, {"role": "police"}))
    raw[0:4] = b"BAD!"
    with pytest.raises(protocol.IntegrityError):
        protocol.unpack(bytes(raw))

    huge = {"data": "A" * (protocol.MAX_PAYLOAD_SIZE + 100)}
    with pytest.raises(ValueError):
        protocol.pack(protocol.MsgType.ALERT, huge)


def test_recv_exact_with_socketpair() -> None:
    s1, s2 = socket.socketpair()
    try:
        frame_bytes = protocol.pack(protocol.MsgType.BROADCAST, {"msg": "hello"}, seq=99)
        s1.sendall(frame_bytes[:10])
        s1.sendall(frame_bytes[10:])
        received = protocol.recv_frame(s2)
        assert received.msg_type == protocol.MsgType.BROADCAST
        assert received.seq == 99
        assert received.payload == {"msg": "hello"}
    finally:
        s1.close()
        s2.close()


def test_db_wal_and_seed_topology(tmp_path) -> None:
    db_file = tmp_path / "test.db"
    db = Database(db_file)
    try:
        mode = db.query_one("PRAGMA journal_mode;")
        assert mode is not None
        assert list(mode.values())[0].lower() == "wal"

        topo = db.get_topology()
        node_ids = {n["node_id"] for n in topo["nodes"]}
        assert {
            "ECC_HQ",
            "TOWER_NORTH",
            "TOWER_SOUTH",
            "SUBSTATION_A",
            "POLICE",
            "FIRE",
            "AMBULANCE",
            "HOSPITAL",
        } == node_ids
        assert len(topo["links"]) == 12
    finally:
        db.close_all()


def test_auth_pbkdf2_token_and_seed_users(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("EAS_SECRET_KEY", raising=False)
    secret_file = tmp_path / ".secret"
    db = Database(tmp_path / "auth.db")
    try:
        auth.seed_default_users(db)
        for uname, (pwd, role) in auth.DEFAULT_SEED_USERS.items():
            user = auth.authenticate_user(db, uname, pwd)
            assert user is not None
            assert user["role"] == role
            assert user["password_hash"].startswith("pbkdf2_sha256$200000$")
            assert auth.authenticate_user(db, uname, "wrongpass") is None

        token = auth.create_token("police", "police", ttl_sec=60, secret_file=secret_file)
        claims = auth.verify_token(token, secret_file=secret_file)
        assert claims["sub"] == "police"
        assert claims["role"] == "police"
        assert secret_file.exists()

        # Tamper token
        bad_token = token[:-4] + "AAAA"
        with pytest.raises(auth.AuthError):
            auth.verify_token(bad_token, secret_file=secret_file)

        # Expired token
        expired = auth.create_token("police", "police", ttl_sec=-5, secret_file=secret_file)
        with pytest.raises(auth.AuthError):
            auth.verify_token(expired, secret_file=secret_file)
    finally:
        db.close_all()

