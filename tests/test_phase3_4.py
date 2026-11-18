"""Phase 3 & 4 tests: PriorityQueue + aging, Dijkstra == DV routing, LinkEmulator DropTail, Dispatcher."""

from __future__ import annotations

import threading
import time

from backend import auth, protocol
from backend.db import Database
from backend.dispatcher import AlertDispatcher
from backend.link_emulator import EMULATED_LABEL, LinkEmulator
from backend.pqueue import PriorityAlertQueue, QueueItem
from backend.routing import RoutingEngine
from backend.servers.tcp_server import TcpAlertServer
from backend.servers.tls_server import TlsAlertServer
from backend.servers.udp_server import UdpAlertServer
from clients.responder import ResponderClient


def test_pqueue_order_fifo_and_aging() -> None:
    pq = PriorityAlertQueue(aging_threshold_sec=0.1)
    pq.push(QueueItem(priority=3, alert_id="n1", delivery_id=1, target_role="fire", protocol="TCP", payload={}))
    pq.push(QueueItem(priority=3, alert_id="n2", delivery_id=2, target_role="fire", protocol="TCP", payload={}))
    pq.push(QueueItem(priority=1, alert_id="c1", delivery_id=3, target_role="police", protocol="TCP", payload={}))
    pq.push(QueueItem(priority=2, alert_id="h1", delivery_id=4, target_role="ambulance", protocol="TCP", payload={}))

    popped = [pq.pop_nowait().alert_id for _ in range(4)]
    assert popped == ["c1", "h1", "n1", "n2"]

    # Anti-starvation aging: wait 0.25s on a Normal(3) item so it ages to eff_priority 1
    old_normal = QueueItem(priority=3, alert_id="old_n", delivery_id=5, target_role="fire", protocol="TCP", payload={})
    pq.push(old_normal)
    time.sleep(0.25)
    pq.push(QueueItem(priority=2, alert_id="fresh_h", delivery_id=6, target_role="fire", protocol="TCP", payload={}))
    first = pq.pop_nowait()
    assert first is not None and first.alert_id == "old_n"


def test_routing_dijkstra_equals_distance_vector_and_failures(tmp_path) -> None:
    db = Database(tmp_path / "route.db")
    try:
        routing = RoutingEngine(db)
        table = routing.all_routing_tables_from("ECC_HQ")
        assert len(table["routes"]) == 7
        for row in table["routes"]:
            assert row["reachable"] is True
            assert row["costs_match"] is True
            assert row["dijkstra_delay_ms"] == row["dv_delay_ms"]

        # Fail primary link to North -> POLICE must reroute via SOUTH -> SUBSTATION_A -> POLICE
        db.set_link_state("L_ECC_NORTH", False)
        cmp_res = routing.compare_routes("ECC_HQ", "POLICE")
        assert cmp_res["costs_match"] is True
        assert cmp_res["rerouted_from_baseline"] is True
        assert cmp_res["dijkstra"]["reachable"] is True
        assert cmp_res["dijkstra"]["path"] == ["ECC_HQ", "TOWER_SOUTH", "SUBSTATION_A", "POLICE"]

        # Fail node SUBSTATION_A too
        db.set_node_state("SUBSTATION_A", False)
        cmp_res2 = routing.compare_routes("ECC_HQ", "POLICE")
        assert cmp_res2["costs_match"] is True
        assert cmp_res2["dijkstra"]["reachable"] is False

        # Restore
        db.set_node_state("SUBSTATION_A", True)
        db.set_link_state("L_ECC_NORTH", True)
        cmp_res3 = routing.compare_routes("ECC_HQ", "POLICE")
        assert cmp_res3["rerouted_from_baseline"] is False
    finally:
        db.close_all()


def test_link_emulator_droptail_overflow_under_load(tmp_path) -> None:
    db = Database(tmp_path / "emu.db")
    try:
        emu = LinkEmulator(db, delay_scale=1.0)
        emu.set_link_params("L_ECC_NORTH", delay_ms=40.0, bandwidth_kbps=500.0, queue_limit=2)

        results = []
        lock = threading.Lock()

        def _send_one() -> None:
            r = emu.transmit_path(["L_ECC_NORTH"], 1024)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=_send_one) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        dropped = [r for r in results if not r.ok]
        passed = [r for r in results if r.ok]
        assert len(passed) >= 2
        assert len(dropped) >= 1
        assert all(r.label == EMULATED_LABEL for r in results)
        assert any("DropTail" in (r.reason or "") for r in dropped)
    finally:
        db.close_all()


def test_dispatcher_waiting_network_redelivery_and_partial_ack(tmp_path) -> None:
    secret_file = tmp_path / ".secret"
    db = Database(tmp_path / "disp.db")
    pq = PriorityAlertQueue(aging_threshold_sec=10.0)
    routing = RoutingEngine(db)
    emu = LinkEmulator(db, delay_scale=0.1)
    tcp = TcpAlertServer("127.0.0.1", 0, db=db, secret_file=secret_file, ack_timeout_sec=1.0)
    udp = UdpAlertServer("127.0.0.1", 0, db=db, secret_file=secret_file)
    tls = TlsAlertServer(
        "127.0.0.1",
        0,
        cert_file=tmp_path / "c.crt",
        key_file=tmp_path / "c.key",
        db=db,
        secret_file=secret_file,
    )
    tcp.start()
    udp.start()
    tls.start()

    disp = AlertDispatcher(
        db=db,
        pqueue=pq,
        routing=routing,
        link_emulator=emu,
        tcp_server=tcp,
        udp_server=udp,
        tls_server=tls,
        num_workers=2,
        redelivery_interval_sec=0.25,
    )
    disp.start()

    fire_tok = auth.create_token("fire", "fire", secret_file=secret_file)
    fire_client = ResponderClient(
        role="fire",
        server_host="127.0.0.1",
        server_port=tcp.port,
        token=fire_tok,
        client_id="fire-disp-1",
        inbox_path=tmp_path / "fire.jsonl",
    )
    fth = threading.Thread(target=fire_client.run, kwargs={"reconnect": False}, daemon=True)
    fth.start()

    try:
        deadline = time.monotonic() + 3.0
        while not tcp.has_client("fire") and time.monotonic() < deadline:
            time.sleep(0.05)

        # Take BOTH ECC links down -> WAITING_NETWORK with estimated_wait_sec
        db.set_link_state("L_ECC_NORTH", False)
        db.set_link_state("L_ECC_SOUTH", False)

        db.create_alert(
            alert_id="A-NET-1",
            alert_code="FIRE-01",
            title="Factory Fire",
            message="Smoke at Sector 18",
            alert_type="fire",
            priority=1,
            protocol="TCP",
            target_roles=["fire", "ambulance"],
            location="Sector 18",
            sensitive=False,
            status="QUEUED",
            created_by="admin",
        )
        disp.enqueue_alert("A-NET-1")

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            a = db.get_alert("A-NET-1")
            if a and a["status"] == "WAITING_NETWORK":
                break
            time.sleep(0.05)

        a = db.get_alert("A-NET-1")
        assert a is not None and a["status"] == "WAITING_NETWORK"
        d_rows = db.get_deliveries(alert_id="A-NET-1")
        assert all(d["estimated_wait_sec"] is not None and d["estimated_wait_sec"] > 0 for d in d_rows)

        # Restore ONLY L_ECC_SOUTH -> fire gets delivered via alternate route, ambulance still offline -> PARTIALLY_DELIVERED
        db.set_link_state("L_ECC_SOUTH", True)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            a = db.get_alert("A-NET-1")
            if a and a["status"] == "PARTIALLY_DELIVERED":
                break
            time.sleep(0.05)

        a = db.get_alert("A-NET-1")
        assert a is not None and a["status"] == "PARTIALLY_DELIVERED"
        fire_del = db.get_delivery_for_alert_role("A-NET-1", "fire")
        assert fire_del is not None and fire_del["status"] == "ACKNOWLEDGED"

        # Now connect ambulance -> redelivery delivers -> alert becomes ACKNOWLEDGED
        amb_tok = auth.create_token("ambulance", "ambulance", secret_file=secret_file)
        amb_client = ResponderClient(
            role="ambulance",
            server_host="127.0.0.1",
            server_port=tcp.port,
            token=amb_tok,
            client_id="amb-disp-1",
            inbox_path=tmp_path / "amb.jsonl",
        )
        ath = threading.Thread(target=amb_client.run, kwargs={"reconnect": False}, daemon=True)
        ath.start()

        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            a = db.get_alert("A-NET-1")
            if a and a["status"] == "ACKNOWLEDGED":
                break
            time.sleep(0.05)

        a = db.get_alert("A-NET-1")
        assert a is not None and a["status"] == "ACKNOWLEDGED"
        amb_client.stop()
        ath.join(timeout=2.0)
    finally:
        fire_client.stop()
        fth.join(timeout=2.0)
        disp.stop()
        tcp.stop()
        udp.stop()
        tls.stop()
        db.close_all()

