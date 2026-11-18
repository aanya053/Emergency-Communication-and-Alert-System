"""Pure-Python .pcap and .pcapng reader with EMRG protocol dissector.

Course Mapping:
- CO2 / CO5: Inspects real Wireshark/Npcap captures across Ethernet (DLT 1),
  Npcap Loopback/NULL (DLT 0 / 108), and RAW IP (DLT 101), supporting both
  classic .pcap and .pcapng Enhanced Packet Blocks (EPB), and decodes EMRG
  frames with CRC-32 verification.
"""

from __future__ import annotations

import ipaddress
import json
import struct
import zlib
from typing import Any

from backend import protocol

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228

MSG_TYPE_NAMES = {
    1: "ALERT",
    2: "ACK",
    3: "HEARTBEAT",
    4: "REGISTER",
    5: "BROADCAST",
    6: "NACK",
}

PRIORITY_NAMES = {
    1: "CRITICAL",
    2: "HIGH",
    3: "NORMAL",
}


def _format_hex_dump(data: bytes, max_bytes: int = 512) -> str:
    clipped = data[:max_bytes]
    lines: list[str] = []
    for offset in range(0, len(clipped), 16):
        chunk = clipped[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


def _decode_emrg_payload(app_bytes: bytes) -> dict[str, Any] | None:
    if len(app_bytes) < protocol.HEADER_SIZE or app_bytes[:4] != protocol.MAGIC:
        return None
    magic, version, msg_type_raw, priority, flags, seq, payload_len, frame_crc = struct.unpack(
        protocol.HEADER_FORMAT, app_bytes[: protocol.HEADER_SIZE]
    )
    body = app_bytes[protocol.HEADER_SIZE : protocol.HEADER_SIZE + payload_len]
    truncated = len(body) < payload_len

    header_zero = struct.pack(
        protocol.HEADER_FORMAT, magic, version, msg_type_raw, priority, flags, seq, payload_len, 0
    )
    computed_crc = zlib.crc32(header_zero + body) & 0xFFFFFFFF
    crc_valid = (not truncated) and (computed_crc == frame_crc)

    decoded_json: dict[str, Any] = {}
    if body:
        try:
            obj = json.loads(body.decode("utf-8"))
            if isinstance(obj, dict):
                decoded_json = obj
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

    return {
        "version": version,
        "msg_type": MSG_TYPE_NAMES.get(msg_type_raw, f"UNKNOWN({msg_type_raw})"),
        "msg_type_code": msg_type_raw,
        "priority": PRIORITY_NAMES.get(priority, str(priority)),
        "priority_code": priority,
        "flags": flags,
        "seq": seq,
        "payload_len": payload_len,
        "crc32": f"0x{frame_crc:08X}",
        "crc_valid": crc_valid,
        "truncated": truncated,
        "alert_code": decoded_json.get("alert_code"),
        "alert_id": decoded_json.get("alert_id"),
        "title": decoded_json.get("title"),
        "target_role": decoded_json.get("target_role") or decoded_json.get("role"),
        "payload": decoded_json,
    }


def _dissect_packet(index: int, ts: float, link_type: int, raw: bytes) -> dict[str, Any]:
    ip_offset: int | None = None
    ip_version: int | None = None

    if link_type == LINKTYPE_ETHERNET:
        if len(raw) >= 14:
            eth_type = struct.unpack("!H", raw[12:14])[0]
            offset = 14
            if eth_type == 0x8100 and len(raw) >= 18:
                eth_type = struct.unpack("!H", raw[16:18])[0]
                offset = 18
            if eth_type == 0x0800:
                ip_version = 4
                ip_offset = offset
            elif eth_type == 0x86DD:
                ip_version = 6
                ip_offset = offset
    elif link_type in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(raw) >= 4:
            fam_le = struct.unpack("<I", raw[:4])[0]
            fam_be = struct.unpack(">I", raw[:4])[0]
            fam = fam_be if link_type == LINKTYPE_LOOP else fam_le
            if fam == 2:
                ip_version = 4
                ip_offset = 4
            elif fam in (10, 24, 28, 30):
                ip_version = 6
                ip_offset = 4
    elif link_type in (LINKTYPE_RAW, LINKTYPE_IPV4):
        if len(raw) >= 1:
            ver = (raw[0] >> 4) & 0x0F
            if ver in (4, 6):
                ip_version = ver
                ip_offset = 0

    src_ip = "-"
    dst_ip = "-"
    transport = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    app_bytes = b""

    if ip_offset is not None and ip_version == 4 and len(raw) >= ip_offset + 20:
        ip_hdr = raw[ip_offset:]
        ihl = (ip_hdr[0] & 0x0F) * 4
        total_len = struct.unpack("!H", ip_hdr[2:4])[0]
        proto = ip_hdr[9]
        src_ip = str(ipaddress.IPv4Address(ip_hdr[12:16]))
        dst_ip = str(ipaddress.IPv4Address(ip_hdr[16:20]))
        l4_end = min(len(ip_hdr), total_len) if total_len >= ihl else len(ip_hdr)
        l4 = ip_hdr[ihl:l4_end]
        if proto == 6 and len(l4) >= 20:
            transport = "TCP"
            src_port, dst_port = struct.unpack("!HH", l4[:4])
            doff = ((l4[12] >> 4) & 0x0F) * 4
            flag_byte = l4[13]
            flag_names = [
                name
                for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"))
                if flag_byte & bit
            ]
            tcp_flags = ",".join(flag_names) or "NONE"
            app_bytes = l4[doff:] if doff >= 20 else b""
        elif proto == 17 and len(l4) >= 8:
            transport = "UDP"
            src_port, dst_port, udp_len = struct.unpack("!HHH", l4[:6])
            app_bytes = l4[8:udp_len] if udp_len >= 8 else l4[8:]
    elif ip_offset is not None and ip_version == 6 and len(raw) >= ip_offset + 40:
        ip_hdr = raw[ip_offset:]
        next_hdr = ip_hdr[6]
        src_ip = str(ipaddress.IPv6Address(ip_hdr[8:24]))
        dst_ip = str(ipaddress.IPv6Address(ip_hdr[24:40]))
        l4 = ip_hdr[40:]
        if next_hdr == 6 and len(l4) >= 20:
            transport = "TCP"
            src_port, dst_port = struct.unpack("!HH", l4[:4])
            doff = ((l4[12] >> 4) & 0x0F) * 4
            app_bytes = l4[doff:] if doff >= 20 else b""
        elif next_hdr == 17 and len(l4) >= 8:
            transport = "UDP"
            src_port, dst_port, udp_len = struct.unpack("!HHH", l4[:6])
            app_bytes = l4[8:udp_len] if udp_len >= 8 else l4[8:]

    emrg = _decode_emrg_payload(app_bytes)
    is_tls_port = 9003 in (src_port, dst_port)
    if transport == "TCP" and is_tls_port and emrg is None and len(app_bytes) > 0:
        transport = "TLS"

    return {
        "index": index,
        "timestamp": round(ts, 6),
        "length": len(raw),
        "link_type": link_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "transport": transport,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": tcp_flags,
        "is_emrg": emrg is not None,
        "emrg": emrg,
        "app_payload_len": len(app_bytes),
        "hex_dump": _format_hex_dump(raw),
    }


def _parse_pcap(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 24:
        raise ValueError("File too short to be a valid .pcap capture")

    magic_le = struct.unpack("<I", data[:4])[0]
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_le in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
        ts_div = 1_000_000_000.0 if magic_le == 0xA1B23C4D else 1_000_000.0
    elif magic_be in (0xA1B2C3D4, 0xA1B23C4D):
        endian = ">"
        ts_div = 1_000_000_000.0 if magic_be == 0xA1B23C4D else 1_000_000.0
    else:
        raise ValueError("Invalid .pcap global magic header")

    _magic, _maj, _min, _tz, _sigfigs, _snaplen, network = struct.unpack(f"{endian}IHHIIII", data[:24])
    offset = 24
    packets: list[dict[str, Any]] = []
    idx = 0
    while offset + 16 <= len(data):
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        if offset + incl_len > len(data):
            break
        pkt_bytes = data[offset : offset + incl_len]
        offset += incl_len
        idx += 1
        ts = float(ts_sec) + float(ts_sub) / ts_div
        packets.append(_dissect_packet(idx, ts, network, pkt_bytes))
    return packets


def _parse_pcapng(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 12 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Invalid .pcapng section header block")

    endian = "<"
    # Check Byte-Order Magic at offset 8..12
    bom_le = struct.unpack("<I", data[8:12])[0]
    bom_be = struct.unpack(">I", data[8:12])[0]
    if bom_le == 0x1A2B3C4D:
        endian = "<"
    elif bom_be == 0x1A2B3C4D:
        endian = ">"
    else:
        raise ValueError("Invalid .pcapng byte-order magic")

    interfaces: list[tuple[int, float]] = []  # (link_type, ts_resol)
    packets: list[dict[str, Any]] = []
    offset = 0
    idx = 0

    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack(f"{endian}II", data[offset : offset + 8])
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8 : offset + block_len - 4]

        if block_type == 0x0A0D0D0A:
            interfaces.clear()
        elif block_type == 0x00000001 and len(body) >= 8:
            # Interface Description Block (IDB)
            link_type, _reserved, _snaplen = struct.unpack(f"{endian}HHI", body[:8])
            ts_resol = 1e-6
            # Scan options for if_tsresol (option code 9)
            opt_off = 8
            while opt_off + 4 <= len(body):
                opt_code, opt_len = struct.unpack(f"{endian}HH", body[opt_off : opt_off + 4])
                opt_off += 4
                if opt_code == 0:
                    break
                opt_val = body[opt_off : opt_off + opt_len]
                if opt_code == 9 and len(opt_val) >= 1:
                    val = opt_val[0]
                    if val & 0x80:
                        ts_resol = 2.0 ** (-(val & 0x7F))
                    else:
                        ts_resol = 10.0 ** (-val)
                padded_len = (opt_len + 3) & ~3
                opt_off += padded_len
            interfaces.append((link_type, ts_resol))
        elif block_type == 0x00000006 and len(body) >= 20:
            # Enhanced Packet Block (EPB)
            iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack(f"{endian}IIIII", body[:20])
            pkt_bytes = body[20 : 20 + cap_len]
            link_type, ts_resol = interfaces[iface_id] if iface_id < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            ts = ((ts_high << 32) | ts_low) * ts_resol
            idx += 1
            packets.append(_dissect_packet(idx, ts, link_type, pkt_bytes))

        offset += block_len

    return packets


def parse_capture(data: bytes, filename: str = "") -> dict[str, Any]:
    """Parse raw .pcap or .pcapng bytes and return structured packet + EMRG summary."""
    if len(data) < 12:
        raise ValueError("Empty or truncated capture file")

    if data[:4] == b"\x0a\x0d\x0d\x0a":
        fmt = "pcapng"
        packets = _parse_pcapng(data)
    else:
        fmt = "pcap"
        packets = _parse_pcap(data)

    emrg_packets = [p for p in packets if p["is_emrg"]]
    crc_valid = sum(1 for p in emrg_packets if p["emrg"]["crc_valid"])
    crc_invalid = sum(1 for p in emrg_packets if not p["emrg"]["crc_valid"])

    return {
        "filename": filename,
        "format": fmt,
        "total_packets": len(packets),
        "emrg_packets": len(emrg_packets),
        "tcp_packets": sum(1 for p in packets if p["transport"] == "TCP"),
        "udp_packets": sum(1 for p in packets if p["transport"] == "UDP"),
        "tls_packets": sum(1 for p in packets if p["transport"] == "TLS"),
        "crc_valid_count": crc_valid,
        "crc_invalid_count": crc_invalid,
        "packets": packets[:1000],
    }

