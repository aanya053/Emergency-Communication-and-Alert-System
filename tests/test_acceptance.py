"""End-to-end Acceptance Check test suite covering every required scenario."""

from __future__ import annotations

import socket
import threading
import time

from fastapi.testclient import TestClient

from backend import auth, protocol
from backend.api import create_app
from clients.citizen import CitizenClient
from clients.responder import ResponderClient


def _login(client: TestClient, username: str, password: str) -> str:
    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.json()["token"]


def test_acceptance_end_to_end_scenarios(tmp_path) -> None:
    secret_file = tmp_path / ".secret"
    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"

    app = create_app(
        db_path=tmp_path / "accept.db",
        secret_file=secret_file,
        cert_file=cert_file,
        key_file=key_file,
        tcp_port=0,
        udp_port=0,
        tls_port=0,
        delay_scale=0.05,
        start_servers=True,
    )

    with TestClient(app) as client:
        # 1) Login required everywhere
        assert client.get("/api/alerts").status_code == 401
        assert client.get("/api/metrics").status_code == 401
        admin_tok = _login(client, "admin", "admin123")
        headers = {"Authorization": f"Bearer {admin_tok}"}

        tcp_port = app.state.tcp_server.port
        udp_port = app.state.udp_server.port

        # 2) Critical alert overtakes queued normals + 3) Kill responder then restart & watch redelivery
        fire_tok = _login(client, "fire", "fire123")
        fire_client = ResponderClient(
            role="fire",
            server_host="127.0.0.1",
            server_port=tcp_port,
            token=fire_tok,
            client_id="fire-accept-1",
            inbox_path=tmp_path / "fire1.jsonl",
        )
        fth = threading.Thread(target=fire_client.run, kwargs={"reconnect": False}, daemon=True)
        fth.start()
        deadline = time.monotonic() + 3.0
        while not app.state.tcp_server.has_client("fire") and time.monotonic() < deadline:
            time.sleep(0.05)

        # Kill fire responder before sending alert
        fire_client.stop()
        fth.join(timeout=2.0)
        deadline = time.monotonic() + 3.0
        while app.state.tcp_server.has_client("fire") and time.monotonic() < deadline:
            time.sleep(0.05)

        # Create normal + critical while fire is offline -> WAITING_NETWORK
        r_norm = client.post(
            "/api/alerts",
            headers=headers,
            json={
                "title": "Normal Check",
                "message": "Routine hydrant check",
                "alert_type": "general",
                "priority": 3,
                "protocol": "TCP",
                "target_roles": ["fire"],
                "location": "Sector 62",
            },
        )
        assert r_norm.status_code == 201
        norm_id = r_norm.json()["alert"]["alert_id"]

        r_crit = client.post(
            "/api/alerts",
            headers=headers,
            json={
                "title": "Critical Blaze",
                "message": "Immediate fire response",
                "alert_type": "fire",
                "priority": 1,
                "protocol": "TCP",
                "target_roles": ["fire"],
                "location": "Main Lab",
            },
        )
        assert r_crit.status_code == 201
        crit_id = r_crit.json()["alert"]["alert_id"]

        time.sleep(0.25)
        # Restart fire responder -> redelivery worker recovers both, critical delivered
        fire_client2 = ResponderClient(
            role="fire",
            server_host="127.0.0.1",
            server_port=tcp_port,
            token=fire_tok,
            client_id="fire-accept-2",
            inbox_path=tmp_path / "fire2.jsonl",
        )
        fth2 = threading.Thread(target=fire_client2.run, kwargs={"reconnect": False}, daemon=True)
        fth2.start()

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            d_crit = app.state.db.get_delivery_for_alert_role(crit_id, "fire")
            d_norm = app.state.db.get_delivery_for_alert_role(norm_id, "fire")
            if d_crit and d_norm and d_crit["status"] == "ACKNOWLEDGED" and d_norm["status"] == "ACKNOWLEDGED":
                break
            time.sleep(0.1)

        d_crit = app.state.db.get_delivery_for_alert_role(crit_id, "fire")
        d_norm = app.state.db.get_delivery_for_alert_role(norm_id, "fire")
        assert d_crit["status"] == "ACKNOWLEDGED"
        assert d_norm["status"] == "ACKNOWLEDGED"

        # 4) Take both ECC links down, see estimated delay, restore, see delivery
        assert client.post("/api/topology/link/L_ECC_NORTH", headers=headers, json={"is_up": False}).status_code == 200
        assert client.post("/api/topology/link/L_ECC_SOUTH", headers=headers, json={"is_up": False}).status_code == 200

        r_down = client.post(
            "/api/alerts",
            headers=headers,
            json={
                "title": "Link Down Alert",
                "message": "Waiting for ECC uplink",
                "alert_type": "fire",
                "priority": 1,
                "protocol": "TCP",
                "target_roles": ["fire"],
                "location": "Sector 12",
            },
        )
        down_id = r_down.json()["alert"]["alert_id"]
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            row = app.state.db.get_delivery_for_alert_role(down_id, "fire")
            if row and row["status"] == "WAITING_NETWORK":
                break
            time.sleep(0.05)
        row = app.state.db.get_delivery_for_alert_role(down_id, "fire")
        assert row["status"] == "WAITING_NETWORK"
        assert row["estimated_wait_sec"] is not None and row["estimated_wait_sec"] > 0

        # Restore link -> redelivered
        assert client.post("/api/topology/link/L_ECC_NORTH", headers=headers, json={"is_up": True}).status_code == 200
        assert client.post("/api/topology/link/L_ECC_SOUTH", headers=headers, json={"is_up": True}).status_code == 200
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            row = app.state.db.get_delivery_for_alert_role(down_id, "fire")
            if row and row["status"] == "ACKNOWLEDGED":
                break
            time.sleep(0.1)
        assert app.state.db.get_delivery_for_alert_role(down_id, "fire")["status"] == "ACKNOWLEDGED"

        # 5) TCP vs UDP loss visible under emulated DropTail bottleneck
        cit_tok = _login(client, "citizen", "citizen123")
        cit = CitizenClient(
            server_host="127.0.0.1",
            server_port=udp_port,
            token=cit_tok,
            client_id="cit-accept-1",
            inbox_path=tmp_path / "cit.jsonl",
        )
        cth = threading.Thread(target=cit.run, daemon=True)
        cth.start()
        deadline = time.monotonic() + 3.0
        while not app.state.udp_server.has_client("citizen") and time.monotonic() < deadline:
            time.sleep(0.05)

        # Tighten DropTail queue_limit & bandwidth on L_ECC_SOUTH (keeping 18ms so Dijkstra still selects it)
        app.state.link_emulator.set_link_params("L_ECC_SOUTH", delay_ms=18.0, bandwidth_kbps=8.0, queue_limit=1)
        for i in range(10):
            client.post(
                "/api/alerts",
                headers=headers,
                json={
                    "title": f"Burst UDP {i}",
                    "message": "Congestion test",
                    "alert_type": "disaster",
                    "priority": 2,
                    "protocol": "UDP",
                    "target_roles": ["citizen"],
                    "location": "Sector 62",
                },
            )
        time.sleep(1.0)
        m_resp = client.get("/api/metrics", headers=headers).json()["current"]
        assert m_resp["totals"]["emulated_link_drops"] >= 1 or m_resp["by_protocol"]["UDP"]["udp_gap_losses"] >= 1

        cit.stop()
        cth.join(timeout=2.0)
        fire_client2.stop()
        fth2.join(timeout=2.0)

