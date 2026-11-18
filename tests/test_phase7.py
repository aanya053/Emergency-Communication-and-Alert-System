"""Phase 6 & 7 tests: Pure-Python .pcap/.pcapng reader, NS-2 trace parser, and frontend security."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from fastapi.testclient import TestClient

from backend import pcap_reader, protocol
from backend.api import create_app
from ns2.parse_trace import parse_trace_text


def _ipv4_udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", sport, dport, udp_len, 0)
    total_len = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        17,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    return ip_hdr + udp_hdr + payload


def _ipv4_tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, (5 << 4), 0x18, 8192, 0, 0)
    total_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        2,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    return ip_hdr + tcp_hdr + payload


def _build_pcap_bytes(link_type: int, packets: list[bytes]) -> bytes:
    ghdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    chunks = [ghdr]
    for i, pkt in enumerate(packets):
        phdr = struct.pack("<IIII", 1700000000 + i, 500, len(pkt), len(pkt))
        chunks.append(phdr + pkt)
    return b"".join(chunks)


def _build_pcapng_bytes(link_type: int, packets: list[bytes]) -> bytes:
    # Section Header Block (SHB)
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 12 + len(shb_body)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)

    # Interface Description Block (IDB)
    idb_body = struct.pack("<HHI", link_type, 0, 65535)
    idb_len = 12 + len(idb_body)
    idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)

    blocks = [shb, idb]
    for i, pkt in enumerate(packets):
        pad = (-len(pkt)) % 4
        epb_body = struct.pack("<IIIII", 0, 0, (i + 1) * 1000, len(pkt), len(pkt)) + pkt + (b"\x00" * pad)
        epb_len = 12 + len(epb_body)
        blocks.append(struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len))
    return b"".join(blocks)


def test_pcap_and_pcapng_reader_and_crc_check() -> None:
    emrg_ok = protocol.pack(
        protocol.MsgType.ALERT,
        {"alert_code": "FIR-101", "alert_id": "AL-1", "title": "Fire"},
        priority=protocol.Priority.CRITICAL,
        seq=5,
    )
    emrg_bad = bytearray(emrg_ok)
    emrg_bad[-1] ^= 0x55

    # Test classic .pcap with Npcap Loopback (LINKTYPE_NULL = 0)
    pkt1 = struct.pack("<I", 2) + _ipv4_tcp_packet("127.0.0.1", "127.0.0.1", 50000, 9001, emrg_ok)
    pkt2 = struct.pack("<I", 2) + _ipv4_udp_packet("127.0.0.1", "127.0.0.1", 9002, 51000, bytes(emrg_bad))
    pcap_data = _build_pcap_bytes(pcap_reader.LINKTYPE_NULL, [pkt1, pkt2])
    parsed = pcap_reader.parse_capture(pcap_data, filename="loopback.pcap")
    assert parsed["format"] == "pcap"
    assert parsed["total_packets"] == 2
    assert parsed["emrg_packets"] == 2
    assert parsed["crc_valid_count"] == 1
    assert parsed["crc_invalid_count"] == 1
    assert parsed["packets"][0]["emrg"]["alert_code"] == "FIR-101"

    # Test .pcapng with Ethernet (LINKTYPE_ETHERNET = 1)
    eth_hdr = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    eth_pkt = eth_hdr + _ipv4_tcp_packet("10.0.0.1", "10.0.0.2", 52000, 9001, emrg_ok)
    pcapng_data = _build_pcapng_bytes(pcap_reader.LINKTYPE_ETHERNET, [eth_pkt])
    parsed_ng = pcap_reader.parse_capture(pcapng_data, filename="eth.pcapng")
    assert parsed_ng["format"] == "pcapng"
    assert parsed_ng["total_packets"] == 1
    assert parsed_ng["emrg_packets"] == 1
    assert parsed_ng["crc_valid_count"] == 1


def test_parse_ns2_trace_on_handwritten_trace() -> None:
    sample_tr = "\n".join(
        [
            "+ 0.100 0 1 rtProtoDV 50 ------- 0 0.0 1.0 0 1",
            "r 0.112 0 1 rtProtoDV 50 ------- 0 0.0 1.0 0 1",
            "+ 1.000 0 1 tcp 1000 ------- 1 0.0 4.0 1 10",
            "- 1.000 0 1 tcp 1000 ------- 1 0.0 4.0 1 10",
            "r 1.016 0 1 tcp 1000 ------- 1 0.0 4.0 1 10",
            "+ 1.016 1 4 tcp 1000 ------- 1 0.0 4.0 1 10",
            "r 1.028 1 4 tcp 1000 ------- 1 0.0 4.0 1 10",
            "r 1.040 4 1 ack 40 ------- 1 4.0 0.0 1 11",
            "+ 1.500 0 2 cbr 512 ------- 2 0.1 6.0 1 20",
            "r 1.535 2 6 cbr 512 ------- 2 0.1 6.0 1 20",
            "+ 1.600 0 2 cbr 512 ------- 2 0.1 6.0 2 21",
            "d 1.605 0 2 cbr 512 ------- 2 0.1 6.0 2 21",
            "# CWND 1.0 4.0",
            "# CWND 1.5 8.0",
        ]
    )
    res = parse_trace_text(sample_tr, load_name="normal")
    assert res["packet_classes"]["DATA"] == 9
    assert res["packet_classes"]["ACK"] == 1
    assert res["packet_classes"]["CONTROL"] == 2
    assert res["summary"]["sent"] == 3
    assert res["summary"]["received"] == 2
    assert res["summary"]["dropped"] == 1
    assert res["summary"]["loss_pct"] == 33.33
    assert res["tcp"]["sent"] == 1 and res["tcp"]["received"] == 1
    assert res["tcp"]["avg_delay_ms"] == 28.0
    assert res["udp"]["sent"] == 2 and res["udp"]["dropped"] == 1
    assert res["drops_per_link"] == {"ECC_HQ->TOWER_SOUTH": 1}
    assert len(res["cwnd_series"]) == 2
    assert len(res["replay_events"]) > 0


def test_frontend_no_innerhtml_and_upload_endpoints(tmp_path) -> None:
    js_text = (Path(__file__).resolve().parent.parent / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert ".innerHTML" not in js_text

    app = create_app(
        db_path=tmp_path / "p7.db",
        secret_file=tmp_path / ".secret",
        cert_file=tmp_path / "c.crt",
        key_file=tmp_path / "c.key",
        tcp_port=0,
        udp_port=0,
        tls_port=0,
        start_servers=False,
    )
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        tok = client.post("/api/login", json={"username": "admin", "password": "admin123"}).json()["token"]
        headers = {"Authorization": f"Bearer {tok}"}

        emrg_ok = protocol.pack(protocol.MsgType.ALERT, {"alert_code": "TST-1", "title": "Test"}, seq=1)
        pkt = struct.pack("<I", 2) + _ipv4_tcp_packet("127.0.0.1", "127.0.0.1", 40000, 9001, emrg_ok)
        pcap_data = _build_pcap_bytes(pcap_reader.LINKTYPE_NULL, [pkt])

        up_pcap = client.post(
            "/api/wireshark/upload",
            headers=headers,
            files={"file": ("test.pcap", pcap_data, "application/octet-stream")},
        )
        assert up_pcap.status_code == 200
        assert up_pcap.json()["emrg_packets"] == 1

        tr_bytes = b"+ 0.5 0 1 tcp 1000 ------- 1 0.0 4.0 1 1\nr 0.52 1 4 tcp 1000 ------- 1 0.0 4.0 1 1\n"
        up_ns2 = client.post(
            "/api/ns2/upload",
            headers=headers,
            data={"load": "low"},
            files={"file": ("real_trace_low.tr", tr_bytes, "text/plain")},
        )
        assert up_ns2.status_code == 200
        assert up_ns2.json()["summary"]["received"] == 1
