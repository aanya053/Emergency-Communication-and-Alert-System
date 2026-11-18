"""Phase 5 tests: MetricsCollector and FastAPI REST + WebSocket auth/RBAC/validation."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.api import create_app
from backend.db import Database
from backend.metrics import MetricsCollector


def test_metrics_collector_real_calculations(tmp_path) -> None:
    db = Database(tmp_path / "metrics.db")
    mc = MetricsCollector(db, window_sec=5.0, sample_interval_sec=0.2)
    try:
        assert mc.snapshot()["rtt"]["avg_rtt_ms"] is None
        mc.record_tx("TCP", 500)
        mc.record_tx("TCP", 500)
        mc.record_ack("TCP", 10.0)
        mc.record_ack("TCP", 20.0)
        mc.record_tx("UDP", 300)
        mc.record_udp_gap_loss(1)
        mc.record_emulator_drop("L_ECC_NORTH", "UDP")

        snap = mc.snapshot()
        assert snap["rtt"]["min_rtt_ms"] == 10.0
        assert snap["rtt"]["max_rtt_ms"] == 20.0
        assert snap["rtt"]["avg_rtt_ms"] == 15.0
        assert snap["rtt"]["p95_rtt_ms"] == 20.0
        assert snap["throughput_bps"] == round(1300 / 5.0, 2)
        assert snap["by_protocol"]["TCP"]["ack_rate"] == 1.0
        assert snap["by_protocol"]["UDP"]["udp_gap_losses"] == 1
        assert snap["by_protocol"]["UDP"]["emulated_drops"] == 1

        mc.start()
        time.sleep(0.35)
        mc.stop()
        samples = db.get_metrics_samples()
        assert len(samples) >= 1
    finally:
        mc.stop()
        db.close_all()


def _login(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/api/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["token"]


def test_api_auth_rbac_validation_and_manual_ack(tmp_path) -> None:
    app = create_app(
        db_path=tmp_path / "api.db",
        secret_file=tmp_path / ".secret",
        cert_file=tmp_path / "s.crt",
        key_file=tmp_path / "s.key",
        tcp_port=0,
        udp_port=0,
        tls_port=0,
        delay_scale=0.05,
        start_servers=True,
    )
    with TestClient(app) as client:
        # Every GET endpoint requires a token -> 401
        for path in ("/api/alerts", "/api/deliveries", "/api/topology", "/api/routes", "/api/metrics", "/api/logs"):
            assert client.get(path).status_code == 401

        admin_tok = _login(client, "admin", "admin123")
        pol_tok = _login(client, "police", "police123")
        fire_tok = _login(client, "fire", "fire123")
        cit_tok = _login(client, "citizen", "citizen123")

        # 422 validation: sensitive alert over TCP or targeting fire must fail
        r422 = client.post(
            "/api/alerts",
            headers={"Authorization": f"Bearer {admin_tok}"},
            json={
                "title": "Trauma Patient",
                "message": "Patient ID 99",
                "alert_type": "medical",
                "priority": 1,
                "protocol": "TCP",
                "target_roles": ["hospital"],
                "location": "Sector 62",
                "sensitive": True,
            },
        )
        assert r422.status_code == 422

        r422_role = client.post(
            "/api/alerts",
            headers={"Authorization": f"Bearer {admin_tok}"},
            json={
                "title": "Trauma Patient",
                "message": "Patient ID 99",
                "alert_type": "medical",
                "priority": 1,
                "protocol": "TLS",
                "target_roles": ["fire"],
                "location": "Sector 62",
                "sensitive": True,
            },
        )
        assert r422_role.status_code == 422

        # Citizen: non-SOS forbidden (403), SOS allowed (201)
        r_cit_bad = client.post(
            "/api/alerts",
            headers={"Authorization": f"Bearer {cit_tok}"},
            json={
                "title": "General",
                "message": "Not SOS",
                "alert_type": "general",
                "priority": 3,
                "protocol": "UDP",
                "target_roles": ["police"],
                "location": "Gate 1",
                "sensitive": False,
            },
        )
        assert r_cit_bad.status_code == 403

        r_cit_sos = client.post(
            "/api/alerts",
            headers={"Authorization": f"Bearer {cit_tok}"},
            json={
                "title": "Citizen SOS",
                "message": "Need help immediately",
                "alert_type": "sos",
                "priority": 1,
                "protocol": "TCP",
                "target_roles": ["police"],
                "location": "Hostel Block",
                "sensitive": False,
            },
        )
        assert r_cit_sos.status_code == 201
        sos_id = r_cit_sos.json()["alert"]["alert_id"]

        # Responder cannot create alerts or clear or toggle links -> 403
        assert (
            client.post(
                "/api/alerts",
                headers={"Authorization": f"Bearer {pol_tok}"},
                json={
                    "title": "Test",
                    "message": "Test msg",
                    "alert_type": "crime",
                    "priority": 2,
                    "protocol": "TCP",
                    "target_roles": ["police"],
                    "location": "Gate 2",
                },
            ).status_code
            == 403
        )
        assert client.post("/api/admin/clear", headers={"Authorization": f"Bearer {pol_tok}"}).status_code == 403
        assert (
            client.post(
                "/api/topology/link/L_ECC_NORTH",
                headers={"Authorization": f"Bearer {pol_tok}"},
                json={"is_up": False},
            ).status_code
            == 403
        )

        # Manual ACK: fire has no delivery for sos_id -> 404; police has delivery -> 200 with computed RTT
        assert client.post(f"/api/deliveries/{sos_id}/ack", headers={"Authorization": f"Bearer {fire_tok}"}).status_code == 404
        r_ack = client.post(f"/api/deliveries/{sos_id}/ack", headers={"Authorization": f"Bearer {pol_tok}"})
        assert r_ack.status_code == 200
        assert r_ack.json()["delivery"]["status"] == "ACKNOWLEDGED"
        assert r_ack.json()["delivery"]["rtt_ms"] > 0.0
        assert r_ack.json()["alert_status"] == "ACKNOWLEDGED"

        # Routes comparison endpoint + hop-by-hop CO5 IPv4 addressing
        r_routes = client.get("/api/routes?src=ECC_HQ&dst=POLICE", headers={"Authorization": f"Bearer {admin_tok}"})
        assert r_routes.status_code == 200
        rdata = r_routes.json()
        assert rdata["costs_match"] is True
        assert rdata["dijkstra"]["ip_path"] == ["10.0.0.10", "10.0.1.11", "10.0.2.21"]
        assert rdata["distance_vector"]["ip_path"] == ["10.0.0.10", "10.0.1.11", "10.0.2.21"]
        assert rdata["dijkstra"]["hop_ips"][0]["gateway"] == "10.0.0.1"
        assert rdata["dijkstra"]["hop_ips"][-1]["subnet_mask"] == "255.255.255.0"

        # Topology nodes include CO5 IPv4/mask/gateway
        topo = client.get("/api/topology", headers={"Authorization": f"Bearer {admin_tok}"}).json()
        node_ips = {n["node_id"]: n["ip_address"] for n in topo["nodes"]}
        assert node_ips["ECC_HQ"] == "10.0.0.10"
        assert node_ips["TOWER_NORTH"] == "10.0.1.11"
        assert node_ips["HOSPITAL"] == "10.0.2.24"

        # POST /api/auth/register: citizen self-registration + admin-only responder creation
        assert client.post("/api/auth/register", json={"username": "ab", "password": "password123"}).status_code == 422
        assert client.post("/api/auth/register", json={"username": "bad-name!", "password": "password123"}).status_code == 422
        assert client.post("/api/auth/register", json={"username": "valid_user", "password": "short"}).status_code == 422

        # Unauthenticated self-register succeeds as citizen
        r_self = client.post(
            "/api/auth/register",
            json={"username": "cit_new_1", "password": "password123"},
        )
        assert r_self.status_code == 201
        assert r_self.json()["role"] == "citizen"
        _login(client, "cit_new_1", "password123")

        # Duplicate username rejected (409)
        assert (
            client.post(
                "/api/auth/register",
                json={"username": "cit_new_1", "password": "password123"},
            ).status_code
            == 409
        )

        # Unauthenticated / non-admin cannot create responder accounts
        assert (
            client.post(
                "/api/auth/register",
                json={"username": "pol_rogue", "password": "password123", "role": "police"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/register",
                headers={"Authorization": f"Bearer {cit_tok}"},
                json={"username": "pol_rogue", "password": "password123", "role": "police"},
            ).status_code
            == 403
        )

        # Admin creates responder account
        r_adm_reg = client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_tok}"},
            json={"username": "police_unit2", "password": "password123", "role": "police"},
        )
        assert r_adm_reg.status_code == 201
        assert r_adm_reg.json()["role"] == "police"
        _login(client, "police_unit2", "password123")

        # WebSocket auth enforcement
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/telemetry"):
                pass

        with client.websocket_connect(f"/ws/telemetry?token={admin_tok}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "snapshot"

