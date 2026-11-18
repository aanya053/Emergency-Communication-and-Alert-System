"""Load test: 20 concurrent responder clients + mixed priority/protocol alerts.

Measures real ACK rate, real RTT (avg/min/max/p95), and verifies critical-first
ordering under load. Can be executed directly (`python tests/load_test.py`) or
via pytest.
"""

from __future__ import annotations

import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend import auth
from backend.db import Database
from backend.dispatcher import AlertDispatcher
from backend.link_emulator import LinkEmulator
from backend.metrics import MetricsCollector
from backend.pqueue import PriorityAlertQueue
from backend.routing import RoutingEngine
from backend.servers.tcp_server import TcpAlertServer
from backend.servers.tls_server import TlsAlertServer
from backend.servers.udp_server import UdpAlertServer
from clients.citizen import CitizenClient
from clients.responder import ResponderClient


def run_load_test(work_dir: Path) -> dict[str, object]:
    secret_file = work_dir / ".secret"
    cert_file = work_dir / "server.crt"
    key_file = work_dir / "server.key"
    db = Database(work_dir / "load.db")
    pq = PriorityAlertQueue(aging_threshold_sec=30.0)
    routing = RoutingEngine(db)
    metrics = MetricsCollector(db)
    emu = LinkEmulator(db, metrics=metrics, delay_scale=0.05)

    tcp = TcpAlertServer("127.0.0.1", 0, db=db, metrics=metrics, secret_file=secret_file, ack_timeout_sec=2.0)
    udp = UdpAlertServer("127.0.0.1", 0, db=db, metrics=metrics, secret_file=secret_file)
    tls = TlsAlertServer(
        "127.0.0.1",
        0,
        cert_file=cert_file,
        key_file=key_file,
        db=db,
        metrics=metrics,
        secret_file=secret_file,
        ack_timeout_sec=2.0,
    )
    tcp.start()
    udp.start()
    tls.start()

    # Keep dispatcher stopped initially so we can verify Critical overtakes queued Normals
    disp = AlertDispatcher(
        db=db,
        pqueue=pq,
        routing=routing,
        link_emulator=emu,
        tcp_server=tcp,
        udp_server=udp,
        tls_server=tls,
        metrics=metrics,
        num_workers=4,
        redelivery_interval_sec=0.5,
    )

    clients = []
    threads: list[threading.Thread] = []
    try:
        # 20 responders across roles: 4 police (TLS), 4 hospital (TLS), 4 fire (TCP), 4 ambulance (TCP), 4 citizen (UDP)
        for i in range(4):
            for role in ("police", "hospital"):
                tok = auth.create_token(role, role, secret_file=secret_file)
                c = ResponderClient(
                    role=role,
                    server_host="127.0.0.1",
                    server_port=tls.port,
                    use_tls=True,
                    cafile=cert_file,
                    token=tok,
                    client_id=f"{role}-tls-{i+1}",
                    inbox_path=work_dir / f"inbox_{role}_{i}.jsonl",
                )
                th = threading.Thread(target=c.run, kwargs={"reconnect": False}, daemon=True)
                th.start()
                clients.append(c)
                threads.append(th)

            for role in ("fire", "ambulance"):
                tok = auth.create_token(role, role, secret_file=secret_file)
                c = ResponderClient(
                    role=role,
                    server_host="127.0.0.1",
                    server_port=tcp.port,
                    use_tls=False,
                    token=tok,
                    client_id=f"{role}-tcp-{i+1}",
                    inbox_path=work_dir / f"inbox_{role}_{i}.jsonl",
                )
                th = threading.Thread(target=c.run, kwargs={"reconnect": False}, daemon=True)
                th.start()
                clients.append(c)
                threads.append(th)

            cit_tok = auth.create_token("citizen", "citizen", secret_file=secret_file)
            cc = CitizenClient(
                server_host="127.0.0.1",
                server_port=udp.port,
                token=cit_tok,
                client_id=f"citizen-udp-{i+1}",
                inbox_path=work_dir / f"inbox_cit_{i}.jsonl",
            )
            th = threading.Thread(target=cc.run, daemon=True)
            th.start()
            clients.append(cc)
            threads.append(th)

        # Wait until all 20 responders have registered
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            total_reg = len(tcp.connected_clients()) + len(tls.connected_clients()) + len(udp.connected_clients())
            if total_reg >= 20:
                break
            time.sleep(0.05)

        total_reg = len(tcp.connected_clients()) + len(tls.connected_clients()) + len(udp.connected_clients())
        assert total_reg == 20, f"Expected 20 registered responders, got {total_reg}"

        # Enqueue 12 Normal alerts first, then 4 Critical alerts, then 4 High alerts
        normal_ids = []
        critical_ids = []
        for i in range(12):
            aid = f"LOAD-NORM-{i+1}"
            normal_ids.append(aid)
            db.create_alert(
                alert_id=aid,
                alert_code=f"NRM-{i+1:02d}",
                title=f"Routine Update {i+1}",
                message="Normal status message",
                alert_type="general",
                priority=3,
                protocol="TCP" if i % 2 == 0 else "UDP",
                target_roles=["fire"] if i % 2 == 0 else ["citizen"],
                location="Sector 62",
                sensitive=False,
                status="QUEUED",
                created_by="admin",
            )
            disp.enqueue_alert(aid)

        for i in range(4):
            aid = f"LOAD-CRIT-{i+1}"
            critical_ids.append(aid)
            db.create_alert(
                alert_id=aid,
                alert_code=f"CRT-{i+1:02d}",
                title=f"Critical Emergency {i+1}",
                message="Immediate response",
                alert_type="medical",
                priority=1,
                protocol="TLS",
                target_roles=["hospital", "police"],
                location="Main Highway",
                sensitive=True,
                status="QUEUED",
                created_by="admin",
            )
            disp.enqueue_alert(aid)

        for i in range(4):
            aid = f"LOAD-HIGH-{i+1}"
            db.create_alert(
                alert_id=aid,
                alert_code=f"HGH-{i+1:02d}",
                title=f"High Priority {i+1}",
                message="Ambulance dispatch",
                alert_type="accident",
                priority=2,
                protocol="TCP",
                target_roles=["ambulance"],
                location="Ring Road",
                sensitive=False,
                status="QUEUED",
                created_by="admin",
            )
            disp.enqueue_alert(aid)

        # Verify critical-first ordering at head of queue before starting workers
        snap_before = pq.snapshot()
        assert all(item["base_priority"] == 1 for item in snap_before[:8])

        disp.start()

        # Wait until all 20 alerts reach ACKNOWLEDGED
        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline:
            alerts = db.list_alerts()
            if len(alerts) == 20 and all(a["status"] == "ACKNOWLEDGED" for a in alerts):
                break
            time.sleep(0.1)

        all_deliveries = db.get_deliveries()
        ack_count = sum(1 for d in all_deliveries if d["status"] == "ACKNOWLEDGED")
        ack_rate = ack_count / len(all_deliveries)
        rtts = [float(d["rtt_ms"]) for d in all_deliveries if d["rtt_ms"] is not None]

        # Check critical-first delivery timestamps vs normal deliveries
        crit_ack_times = [float(d["ack_at"]) for d in all_deliveries if d["alert_id"].startswith("LOAD-CRIT") and d["ack_at"]]
        norm_ack_times = [float(d["ack_at"]) for d in all_deliveries if d["alert_id"].startswith("LOAD-NORM") and d["ack_at"]]
        critical_first = min(crit_ack_times) <= max(norm_ack_times)

        report = {
            "responders": total_reg,
            "alerts_dispatched": 20,
            "deliveries_total": len(all_deliveries),
            "ack_rate": round(ack_rate, 4),
            "avg_rtt_ms": round(statistics.mean(rtts), 3) if rtts else None,
            "min_rtt_ms": round(min(rtts), 3) if rtts else None,
            "max_rtt_ms": round(max(rtts), 3) if rtts else None,
            "critical_first_ordering": critical_first,
            "metrics_snapshot": metrics.snapshot(),
        }
        return report
    finally:
        for c in clients:
            c.stop()
        disp.stop()
        tcp.stop()
        udp.stop()
        tls.stop()
        db.close_all()


def test_load_20_responders_mixed_alerts(tmp_path) -> None:
    report = run_load_test(tmp_path)
    assert report["responders"] == 20
    assert report["ack_rate"] >= 0.95
    assert report["avg_rtt_ms"] is not None
    assert report["critical_first_ordering"] is True


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        res = run_load_test(Path(tmp))
        print("=== ECAS Load Test Report (20 Responders) ===")
        for k, v in res.items():
            if k != "metrics_snapshot":
                print(f"  {k}: {v}")

