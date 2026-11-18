"""Parser for NS-2 trace files (.tr) and optional TCP cwnd trace lines.

Course Mapping:
- CO3 / CO4 / CO5: Extracts real simulation metrics from NS-2 traces:
  DATA (tcp, cbr) vs ACK vs CONTROL (rtProtoDV) classification, per-flow
  sent/received/dropped counts, packet loss %, end-to-end delay matched by
  pktid, throughput per second, per-link drops, TCP cwnd series, and replay events.

Non-Negotiable Rule #1:
Never generates synthetic traces or fabricated metrics.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

NODE_ID_TO_NAME = {
    0: "ECC_HQ",
    1: "TOWER_NORTH",
    2: "TOWER_SOUTH",
    3: "SUBSTATION_A",
    4: "POLICE",
    5: "FIRE",
    6: "AMBULANCE",
    7: "HOSPITAL",
}


def classify_packet_type(pkt_type: str) -> str:
    p = pkt_type.lower()
    if p in ("tcp", "cbr"):
        return "DATA"
    if p == "ack":
        return "ACK"
    if p in ("rtprotodv", "message", "arp"):
        return "CONTROL"
    return "OTHER"


def parse_trace_text(text: str, *, load_name: str = "unknown") -> dict[str, Any]:
    """Parse NS-2 trace file text and return comprehensive flow, link, cwnd, and replay metrics."""
    lines = text.splitlines()
    category_counts = {"DATA": 0, "ACK": 0, "CONTROL": 0, "OTHER": 0}

    # Per-pktid tracking for DATA flows
    pkt_first_tx: dict[int, tuple[float, int, str, int]] = {}  # pkt_id -> (time, fid, pkt_type, size)
    pkt_rx: dict[int, tuple[float, int, str, int]] = {}  # pkt_id -> (time, fid, pkt_type, size)
    pkt_dropped: dict[int, tuple[int, str, str]] = {}  # pkt_id -> (fid, pkt_type, link_key)

    drops_per_link: dict[str, int] = defaultdict(int)
    flow_types: dict[int, set[str]] = defaultdict(set)
    flow_sent: dict[int, set[int]] = defaultdict(set)
    flow_rx: dict[int, set[int]] = defaultdict(set)
    flow_dropped: dict[int, set[int]] = defaultdict(set)
    flow_delays_ms: dict[int, list[float]] = defaultdict(list)
    flow_rx_bytes: dict[int, int] = defaultdict(int)

    # Throughput per 1-second bucket: sec -> {total_bytes, tcp_bytes, udp_bytes}
    sec_bytes: dict[int, dict[str, int]] = defaultdict(lambda: {"total": 0, "tcp": 0, "udp": 0})
    cwnd_series: list[dict[str, float]] = []
    replay_events: list[dict[str, Any]] = []

    valid_lines = 0
    min_time = math.inf
    max_time = 0.0

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        # Embedded genuine NS-2 cwnd record appended by run_ns2.sh / emergency.tcl
        if line.startswith("# CWND "):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    cwnd_series.append({"time": round(float(parts[2]), 4), "cwnd": round(float(parts[3]), 4)})
                except ValueError:
                    pass
            continue
        if line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 12:
            continue

        event = parts[0]
        if event not in ("+", "-", "r", "d"):
            continue

        try:
            ts = float(parts[1])
            from_node = int(parts[2])
            to_node = int(parts[3])
            pkt_type = parts[4]
            pkt_size = int(parts[5])
            fid = int(parts[7])
            src_addr = parts[8]
            dst_addr = parts[9]
            pkt_id = int(parts[11])
            src_node = int(float(src_addr.split(".")[0]))
            dst_node = int(float(dst_addr.split(".")[0]))
        except (ValueError, IndexError):
            continue

        valid_lines += 1
        min_time = min(min_time, ts)
        max_time = max(max_time, ts)

        cat = classify_packet_type(pkt_type)
        category_counts[cat] += 1

        if len(replay_events) < 2000 and (cat == "DATA" or event == "d" or cat == "CONTROL"):
            replay_events.append(
                {
                    "t": round(ts, 4),
                    "ev": event,
                    "u": from_node,
                    "v": to_node,
                    "u_name": NODE_ID_TO_NAME.get(from_node, f"N{from_node}"),
                    "v_name": NODE_ID_TO_NAME.get(to_node, f"N{to_node}"),
                    "type": pkt_type,
                    "cat": cat,
                    "fid": fid,
                    "pkt_id": pkt_id,
                }
            )

        if event == "d":
            link_key = f"{NODE_ID_TO_NAME.get(from_node, from_node)}->{NODE_ID_TO_NAME.get(to_node, to_node)}"
            drops_per_link[link_key] += 1
            if cat == "DATA":
                pkt_dropped[pkt_id] = (fid, pkt_type, link_key)
                flow_dropped[fid].add(pkt_id)
            continue

        if cat != "DATA":
            continue

        flow_types[fid].add(pkt_type.lower())

        if event == "+" and (from_node == src_node or pkt_id not in pkt_first_tx):
            if pkt_id not in pkt_first_tx:
                pkt_first_tx[pkt_id] = (ts, fid, pkt_type.lower(), pkt_size)
                flow_sent[fid].add(pkt_id)
        elif event == "-" and pkt_id not in pkt_first_tx:
            pkt_first_tx[pkt_id] = (ts, fid, pkt_type.lower(), pkt_size)
            flow_sent[fid].add(pkt_id)

        if event == "r" and to_node == dst_node:
            if pkt_id not in pkt_rx:
                pkt_rx[pkt_id] = (ts, fid, pkt_type.lower(), pkt_size)
                flow_rx[fid].add(pkt_id)
                flow_rx_bytes[fid] += pkt_size
                sec = int(math.floor(ts))
                sec_bytes[sec]["total"] += pkt_size
                if pkt_type.lower() == "tcp":
                    sec_bytes[sec]["tcp"] += pkt_size
                elif pkt_type.lower() == "cbr":
                    sec_bytes[sec]["udp"] += pkt_size
                if pkt_id in pkt_first_tx:
                    tx_ts = pkt_first_tx[pkt_id][0]
                    delay_ms = max(0.0, (ts - tx_ts) * 1000.0)
                    flow_delays_ms[fid].append(delay_ms)

    if valid_lines == 0:
        raise ValueError("No valid NS-2 trace events found in file")

    duration = max(0.001, max_time - (min_time if not math.isinf(min_time) else 0.0))

    # Build per-flow stats
    all_fids = sorted(set(flow_sent.keys()) | set(flow_rx.keys()) | set(flow_dropped.keys()))
    flows: list[dict[str, Any]] = []
    tcp_summary = {"sent": 0, "received": 0, "dropped": 0, "delays": [], "bytes": 0}
    udp_summary = {"sent": 0, "received": 0, "dropped": 0, "delays": [], "bytes": 0}

    for fid in all_fids:
        sent_cnt = len(flow_sent[fid])
        rx_cnt = len(flow_rx[fid])
        drop_cnt = len(flow_dropped[fid])
        denom = max(1, sent_cnt)
        loss_pct = round((drop_cnt / denom) * 100.0, 2) if sent_cnt > 0 else 0.0
        delays = flow_delays_ms[fid]
        avg_delay = round(sum(delays) / len(delays), 3) if delays else None
        tput_kbps = round((flow_rx_bytes[fid] * 8.0) / duration / 1000.0, 2)
        ptype_label = "/".join(sorted(flow_types[fid])) if flow_types[fid] else "data"

        flows.append(
            {
                "fid": fid,
                "protocol": "TCP" if "tcp" in flow_types[fid] else ("UDP" if "cbr" in flow_types[fid] else ptype_label.upper()),
                "pkt_type": ptype_label,
                "sent": sent_cnt,
                "received": rx_cnt,
                "dropped": drop_cnt,
                "loss_pct": loss_pct,
                "avg_delay_ms": avg_delay,
                "throughput_kbps": tput_kbps,
            }
        )
        if "tcp" in flow_types[fid]:
            tcp_summary["sent"] += sent_cnt
            tcp_summary["received"] += rx_cnt
            tcp_summary["dropped"] += drop_cnt
            tcp_summary["delays"].extend(delays)
            tcp_summary["bytes"] += flow_rx_bytes[fid]
        if "cbr" in flow_types[fid]:
            udp_summary["sent"] += sent_cnt
            udp_summary["received"] += rx_cnt
            udp_summary["dropped"] += drop_cnt
            udp_summary["delays"].extend(delays)
            udp_summary["bytes"] += flow_rx_bytes[fid]

    total_sent = len(pkt_first_tx)
    total_rx = len(pkt_rx)
    total_dropped = len(pkt_dropped)
    overall_loss_pct = round((total_dropped / max(1, total_sent)) * 100.0, 2) if total_sent > 0 else 0.0
    all_delays = [d for ds in flow_delays_ms.values() for d in ds]
    overall_avg_delay = round(sum(all_delays) / len(all_delays), 3) if all_delays else None
    overall_tput_kbps = round((sum(flow_rx_bytes.values()) * 8.0) / duration / 1000.0, 2)

    max_sec = max(sec_bytes.keys(), default=0)
    throughput_per_sec = [
        {
            "sec": s,
            "total_kbps": round((sec_bytes[s]["total"] * 8.0) / 1000.0, 2),
            "tcp_kbps": round((sec_bytes[s]["tcp"] * 8.0) / 1000.0, 2),
            "udp_kbps": round((sec_bytes[s]["udp"] * 8.0) / 1000.0, 2),
        }
        for s in range(0, max_sec + 1)
    ]

    def _proto_block(s: dict[str, Any]) -> dict[str, Any]:
        return {
            "sent": s["sent"],
            "received": s["received"],
            "dropped": s["dropped"],
            "loss_pct": round((s["dropped"] / max(1, s["sent"])) * 100.0, 2) if s["sent"] > 0 else 0.0,
            "avg_delay_ms": round(sum(s["delays"]) / len(s["delays"]), 3) if s["delays"] else None,
            "throughput_kbps": round((s["bytes"] * 8.0) / duration / 1000.0, 2),
        }

    return {
        "load": load_name,
        "valid_lines": valid_lines,
        "duration_sec": round(duration, 3),
        "packet_classes": category_counts,
        "summary": {
            "sent": total_sent,
            "received": total_rx,
            "dropped": total_dropped,
            "loss_pct": overall_loss_pct,
            "avg_delay_ms": overall_avg_delay,
            "throughput_kbps": overall_tput_kbps,
        },
        "tcp": _proto_block(tcp_summary),
        "udp": _proto_block(udp_summary),
        "flows": flows,
        "drops_per_link": dict(sorted(drops_per_link.items())),
        "throughput_per_sec": throughput_per_sec,
        "cwnd_series": cwnd_series,
        "replay_events": replay_events,
    }


def parse_trace_file(path: str | Path, *, load_name: str = "unknown") -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_trace_text(text, load_name=load_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse an NS-2 trace file (.tr)")
    parser.add_argument("trace_file", type=Path, help="Path to NS-2 .tr file")
    parser.add_argument("--load", default="unknown", help="Load scenario label (low/normal/heavy)")
    parser.add_argument("--cwnd-file", type=Path, default=None, help="Optional separate cwnd trace file")
    args = parser.parse_args()

    result = parse_trace_file(args.trace_file, load_name=args.load)
    if args.cwnd_file and args.cwnd_file.exists():
        cwnd_rows: list[dict[str, float]] = []
        for line in args.cwnd_file.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    cwnd_rows.append({"time": round(float(parts[0]), 4), "cwnd": round(float(parts[1]), 4)})
                except ValueError:
                    pass
        result["cwnd_series"] = cwnd_rows

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

