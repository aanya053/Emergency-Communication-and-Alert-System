"""Binary framed application-layer protocol (EMRG) for ECAS.

Course Mapping:
- CO2 (Application-layer protocol design): Custom binary-framed protocol over
  TCP, UDP, and TLS sockets with explicit message types, priorities, flags, and
  sequence numbers.
- CO5 (CRC error detection): 32-bit CRC-32 checksum computed over the 20-byte
  header (with the CRC field zeroed) concatenated with the UTF-8 JSON payload.

Wire Format (20-byte big-endian header + variable JSON payload):
    0..3   magic       (4B)  "EMRG"
    4      version     (1B)  Protocol version (1)
    5      msg_type    (1B)  ALERT=1, ACK=2, HEARTBEAT=3, REGISTER=4, BROADCAST=5, NACK=6
    6      priority    (1B)  CRITICAL=1, HIGH=2, NORMAL=3 (0 if unused)
    7      flags       (1B)  Bitmask (SENSITIVE=0x01, REROUTED=0x02, ACK_REQUIRED=0x04, EMULATED=0x08)
    8..11  seq         (4B)  uint32 sequence number
    12..15 payload_len (4B)  uint32 payload length in bytes (<= 16384)
    16..19 crc32       (4B)  uint32 CRC-32 over header(crc=0) + payload
    20..   payload     (NB)  UTF-8 JSON object
"""

from __future__ import annotations

import json
import socket
import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

MAGIC = b"EMRG"
PROTOCOL_VERSION = 1
HEADER_FORMAT = "!4sBBBBIII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 20 bytes
MAX_PAYLOAD_SIZE = 16 * 1024  # 16 KB


class IntegrityError(Exception):
    """Raised when an EMRG frame fails structural, length, JSON, or CRC validation."""


class MsgType(IntEnum):
    ALERT = 1
    ACK = 2
    HEARTBEAT = 3
    REGISTER = 4
    BROADCAST = 5
    NACK = 6


class Priority(IntEnum):
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3


FLAG_SENSITIVE = 0x01
FLAG_REROUTED = 0x02
FLAG_ACK_REQUIRED = 0x04
FLAG_EMULATED = 0x08


@dataclass(frozen=True, slots=True)
class Frame:
    """Decoded EMRG protocol frame."""

    version: int
    msg_type: MsgType
    priority: int
    flags: int
    seq: int
    payload_len: int
    crc32: int
    payload: dict[str, Any]


def compute_crc32(header_zero_crc: bytes, payload_bytes: bytes) -> int:
    """Compute unsigned 32-bit CRC over header (with CRC field zeroed) + payload."""
    return zlib.crc32(header_zero_crc + payload_bytes) & 0xFFFFFFFF


def pack(
    msg_type: int | MsgType,
    payload: dict[str, Any] | None = None,
    *,
    priority: int = Priority.NORMAL,
    flags: int = 0,
    seq: int = 0,
    version: int = PROTOCOL_VERSION,
) -> bytes:
    """Serialize a message type and JSON payload into a CRC-protected EMRG frame."""
    try:
        mtype = MsgType(int(msg_type))
    except ValueError as exc:
        raise ValueError(f"Unsupported msg_type: {msg_type}") from exc

    if version != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    if not (0 <= priority <= 255):
        raise ValueError(f"Invalid priority byte: {priority}")
    if not (0 <= flags <= 255):
        raise ValueError(f"Invalid flags byte: {flags}")
    if not (0 <= seq <= 0xFFFFFFFF):
        raise ValueError(f"Sequence number out of uint32 range: {seq}")

    body = {} if payload is None else payload
    if not isinstance(body, dict):
        raise TypeError("EMRG payload must be a dict serializable to JSON")

    payload_bytes = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_len = len(payload_bytes)
    if payload_len > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload length {payload_len} exceeds max {MAX_PAYLOAD_SIZE} bytes")

    header_zero_crc = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        version,
        int(mtype),
        int(priority),
        int(flags),
        int(seq),
        payload_len,
        0,
    )
    crc = compute_crc32(header_zero_crc, payload_bytes)
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        version,
        int(mtype),
        int(priority),
        int(flags),
        int(seq),
        payload_len,
        crc,
    )
    return header + payload_bytes


def unpack(data: bytes) -> Frame:
    """Validate and decode a complete EMRG frame from bytes. Raises IntegrityError on corruption."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise IntegrityError("Frame data must be bytes-like")

    raw = bytes(data)
    if len(raw) < HEADER_SIZE:
        raise IntegrityError(f"Frame shorter than {HEADER_SIZE}-byte header (got {len(raw)} bytes)")

    magic, version, msg_type_raw, priority, flags, seq, payload_len, frame_crc = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )

    if magic != MAGIC:
        raise IntegrityError(f"Invalid magic bytes: {magic!r}")
    if version != PROTOCOL_VERSION:
        raise IntegrityError(f"Unsupported version: {version}")
    try:
        msg_type = MsgType(msg_type_raw)
    except ValueError as exc:
        raise IntegrityError(f"Unknown message type: {msg_type_raw}") from exc

    if payload_len > MAX_PAYLOAD_SIZE:
        raise IntegrityError(f"Payload length {payload_len} exceeds max {MAX_PAYLOAD_SIZE}")

    expected_total = HEADER_SIZE + payload_len
    if len(raw) != expected_total:
        raise IntegrityError(
            f"Frame length mismatch: header declares {expected_total} bytes, got {len(raw)}"
        )

    payload_bytes = raw[HEADER_SIZE:]
    header_zero_crc = struct.pack(
        HEADER_FORMAT,
        magic,
        version,
        msg_type_raw,
        priority,
        flags,
        seq,
        payload_len,
        0,
    )
    computed_crc = compute_crc32(header_zero_crc, payload_bytes)
    if computed_crc != frame_crc:
        raise IntegrityError(
            f"CRC32 mismatch: expected 0x{computed_crc:08X}, got 0x{frame_crc:08X}"
        )

    try:
        decoded = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Invalid UTF-8/JSON payload: {exc}") from exc

    if not isinstance(decoded, dict):
        raise IntegrityError("JSON payload must decode to an object")

    return Frame(
        version=version,
        msg_type=msg_type,
        priority=priority,
        flags=flags,
        seq=seq,
        payload_len=payload_len,
        crc32=frame_crc,
        payload=decoded,
    )


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a stream socket or raise ConnectionError on premature EOF."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return b""

    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(f"Socket closed with {remaining} of {n} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> Frame:
    """Read a full EMRG frame from a stream socket, validating header bounds before body read."""
    header = recv_exact(sock, HEADER_SIZE)
    magic, version, msg_type_raw, _priority, _flags, _seq, payload_len, _crc = struct.unpack(
        HEADER_FORMAT, header
    )
    if magic != MAGIC:
        raise IntegrityError(f"Invalid magic bytes in stream: {magic!r}")
    if version != PROTOCOL_VERSION:
        raise IntegrityError(f"Unsupported protocol version in stream: {version}")
    try:
        MsgType(msg_type_raw)
    except ValueError as exc:
        raise IntegrityError(f"Unknown message type in stream: {msg_type_raw}") from exc
    if payload_len > MAX_PAYLOAD_SIZE:
        raise IntegrityError(f"Payload length {payload_len} exceeds max {MAX_PAYLOAD_SIZE}")

    payload_bytes = recv_exact(sock, payload_len)
    return unpack(header + payload_bytes)

