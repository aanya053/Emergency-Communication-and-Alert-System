"""FastAPI REST & WebSocket server for ECAS.

Course Mapping:
- CO2 / CO3 / CO4 / CO5: Exposes authenticated REST endpoints and real-time
  WebSocket telemetry for emergency alert creation, role-based inboxes, manual ACK,
  topology failure control, Dijkstra vs Distance Vector route comparison,
  emulated-link metrics, Wireshark .pcap/.pcapng analysis, and NS-2 .tr analysis.

Non-Negotiable Rules:
- Authentication and role checks enforced on every REST endpoint and WebSocket.
- All user input strictly validated via Pydantic v2 models.
- Zero fake/random numbers; all metrics and RTTs are measured.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend import auth, config, pcap_reader
from backend.db import Database
from backend.dispatcher import AlertDispatcher
from backend.link_emulator import EMULATED_LABEL, LinkEmulator
from backend.metrics import MetricsCollector
from backend.pqueue import PriorityAlertQueue
from backend.routing import RoutingEngine
from backend.servers.tcp_server import TcpAlertServer
from backend.servers.tls_server import TlsAlertServer
from backend.servers.udp_server import UdpAlertServer
from ns2.parse_trace import parse_trace_text

AlertTypeLiteral = Literal["accident", "fire", "medical", "crime", "disaster", "sos", "tactical", "general"]
ProtocolLiteral = Literal["TCP", "UDP", "TLS"]
TargetRoleLiteral = Literal["police", "ambulance", "fire", "hospital", "citizen"]
Ns2LoadLiteral = Literal["low", "normal", "heavy"]


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]{3,30}$")
    password: str = Field(..., min_length=8, max_length=128)
    role: TargetRoleLiteral = "citizen"


_optional_bearer = HTTPBearer(auto_error=False)


class CreateAlertRequest(BaseModel):
    title: str = Field(..., min_length=2, max_length=120)
    message: str = Field(..., min_length=2, max_length=2000)
    alert_type: AlertTypeLiteral = "general"
    priority: Literal[1, 2, 3] = 2
    protocol: ProtocolLiteral = "TCP"
    target_roles: list[TargetRoleLiteral] = Field(..., min_length=1)
    location: str = Field(..., min_length=2, max_length=200)
    sensitive: bool = False

    @model_validator(mode="after")
    def validate_sensitive_and_targets(self) -> "CreateAlertRequest":
        # Deduplicate target_roles while preserving order
        seen: set[str] = set()
        deduped: list[TargetRoleLiteral] = []
        for r in self.target_roles:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        self.target_roles = deduped

        if self.sensitive:
            if self.protocol != "TLS":
                raise ValueError("Sensitive alerts (patient/tactical data) MUST use TLS protocol")
            disallowed = [r for r in self.target_roles if r not in config.SENSITIVE_ROLES]
            if disallowed:
                raise ValueError(
                    f"Sensitive alerts may only target Hospital or Police (invalid: {', '.join(disallowed)})"
                )
        return self


class LinkUpdateRequest(BaseModel):
    is_up: bool | None = None
    delay_ms: float | None = Field(default=None, gt=0, le=5000)
    bandwidth_kbps: float | None = Field(default=None, gt=0, le=1_000_000)
    queue_limit: int | None = Field(default=None, ge=1, le=10000)


class NodeUpdateRequest(BaseModel):
    is_up: bool


class TelemetryHub:
    """Manages authenticated WebSocket subscribers and broadcasts JSON updates."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self._connections:
            return
        dead: list[WebSocket] = []
        text = json.dumps(message)
        for ws in list(self._connections):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    def broadcast_threadsafe(self, message: dict[str, Any]) -> None:
        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)


def create_app(
    *,
    db_path: Path | None = None,
    secret_file: Path | None = None,
    cert_file: Path | None = None,
    key_file: Path | None = None,
    tcp_port: int = config.TCP_PORT,
    udp_port: int = config.UDP_PORT,
    tls_port: int = config.TLS_PORT,
    delay_scale: float = 1.0,
    start_servers: bool = True,
) -> FastAPI:
    """Application factory enabling isolated test instances and production deployment."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config.ensure_directories()
        db = Database(db_path)
        auth.seed_default_users(db)

        hub = TelemetryHub()
        hub.set_loop(asyncio.get_running_loop())

        pqueue = PriorityAlertQueue()
        routing = RoutingEngine(db)
        metrics = MetricsCollector(
            db,
            on_sample=lambda snap: hub.broadcast_threadsafe({"type": "metrics", "data": snap}),
        )
        metrics.set_queue_depth_provider(pqueue.size)
        link_emulator = LinkEmulator(db, metrics=metrics, delay_scale=delay_scale)

        tcp_srv = TcpAlertServer(
            config.BIND_HOST,
            tcp_port,
            db=db,
            metrics=metrics,
            secret_file=secret_file,
        )
        udp_srv = UdpAlertServer(
            config.BIND_HOST,
            udp_port,
            db=db,
            metrics=metrics,
            secret_file=secret_file,
        )
        tls_srv = TlsAlertServer(
            config.BIND_HOST,
            tls_port,
            cert_file=cert_file,
            key_file=key_file,
            db=db,
            metrics=metrics,
            secret_file=secret_file,
        )
        dispatcher = AlertDispatcher(
            db=db,
            pqueue=pqueue,
            routing=routing,
            link_emulator=link_emulator,
            tcp_server=tcp_srv,
            udp_server=udp_srv,
            tls_server=tls_srv,
            metrics=metrics,
            on_event=lambda ev, data: hub.broadcast_threadsafe({"type": ev, "data": data}),
        )

        app.state.db = db
        app.state.secret_file = secret_file
        app.state.hub = hub
        app.state.pqueue = pqueue
        app.state.routing = routing
        app.state.metrics = metrics
        app.state.link_emulator = link_emulator
        app.state.tcp_server = tcp_srv
        app.state.udp_server = udp_srv
        app.state.tls_server = tls_srv
        app.state.dispatcher = dispatcher
        app.state.latest_capture = None
        app.state.ns2_results = {}

        if start_servers:
            tcp_srv.start()
            udp_srv.start()
            tls_srv.start()
            metrics.start()
            dispatcher.start()

        try:
            yield
        finally:
            dispatcher.stop()
            metrics.stop()
            tcp_srv.stop()
            udp_srv.stop()
            tls_srv.stop()
            db.close_all()

    app = FastAPI(
        title="Emergency Communication and Alert System (ECAS)",
        version="2.0.0",
        lifespan=lifespan,
    )

    def _get_connected_clients(request: Request) -> list[dict[str, Any]]:
        clients: list[dict[str, Any]] = []
        for srv in (
            request.app.state.tcp_server,
            request.app.state.tls_server,
            request.app.state.udp_server,
        ):
            clients.extend(srv.connected_clients())
        return clients

    @app.post("/api/login")
    async def login(body: LoginRequest, request: Request) -> dict[str, Any]:
        db: Database = request.app.state.db
        user = auth.authenticate_user(db, body.username.strip(), body.password)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
        token = auth.create_token(
            user["username"],
            user["role"],
            secret_file=request.app.state.secret_file,
        )
        db.add_log("INFO", "AUTH", "USER_LOGIN", {"username": user["username"], "role": user["role"]})
        return {
            "token": token,
            "username": user["username"],
            "role": user["role"],
            "expires_in_sec": config.TOKEN_TTL_SEC,
        }

    @app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
    async def register_account(
        body: RegisterRequest,
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_optional_bearer),
    ) -> dict[str, Any]:
        db: Database = request.app.state.db
        secret_file = getattr(request.app.state, "secret_file", None)

        caller_claims: dict[str, Any] | None = None
        if credentials is not None:
            if credentials.scheme.lower() != "bearer":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication scheme",
                )
            try:
                caller_claims = auth.verify_token(credentials.credentials, secret_file=secret_file)
            except auth.AuthError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                ) from exc

        if body.role != "citizen":
            if caller_claims is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Admin authentication required to create responder accounts",
                )
            if caller_claims["role"] != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only admin can create responder accounts",
                )
            assigned_role = body.role
        else:
            # Self-registration is always forced to citizen role
            assigned_role = "citizen"

        if db.get_user(body.username) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{body.username}' already exists",
            )

        pw_hash = auth.hash_password(body.password)
        db.ensure_user(body.username, pw_hash, assigned_role)
        db.add_log(
            "INFO",
            "AUTH",
            "USER_REGISTERED",
            {
                "username": body.username,
                "role": assigned_role,
                "created_by": caller_claims["sub"] if caller_claims else "self",
            },
        )
        return {
            "username": body.username,
            "role": assigned_role,
            "message": f"Account '{body.username}' created with role '{assigned_role}'",
        }

    @app.get("/api/me")
    async def me(user: dict[str, Any] = Depends(auth.require_role())) -> dict[str, Any]:
        return {"username": user["sub"], "role": user["role"], "exp": user["exp"]}

    @app.post("/api/alerts", status_code=status.HTTP_201_CREATED)
    async def create_alert(
        body: CreateAlertRequest,
        request: Request,
        user: dict[str, Any] = Depends(auth.require_role("admin", "citizen")),
    ) -> dict[str, Any]:
        role = user["role"]
        if role == "citizen":
            if body.alert_type != "sos" or body.sensitive:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Citizen accounts may only create non-sensitive SOS alerts",
                )

        db: Database = request.app.state.db
        dispatcher: AlertDispatcher = request.app.state.dispatcher

        alert_id = f"AL-{uuid.uuid4().hex[:10].upper()}"
        alert_code = f"{body.alert_type[:3].upper()}-{int(time.time()) % 10000:04d}"
        db.create_alert(
            alert_id=alert_id,
            alert_code=alert_code,
            title=body.title.strip(),
            message=body.message.strip(),
            alert_type=body.alert_type,
            priority=body.priority,
            protocol=body.protocol,
            target_roles=list(body.target_roles),
            location=body.location.strip(),
            sensitive=body.sensitive,
            status="QUEUED",
            created_by=user["sub"],
        )
        db.add_log(
            "INFO",
            "API",
            "ALERT_CREATED",
            {
                "alert_id": alert_id,
                "priority": body.priority,
                "protocol": body.protocol,
                "targets": body.target_roles,
                "sensitive": body.sensitive,
                "created_by": user["sub"],
            },
        )
        dispatcher.enqueue_alert(alert_id)
        request.app.state.hub.broadcast_threadsafe(
            {"type": "alert_created", "data": {"alert_id": alert_id, "priority": body.priority}}
        )
        alert = db.get_alert(alert_id)
        deliveries = db.get_deliveries(alert_id=alert_id)
        return {"alert": alert, "deliveries": deliveries}

    @app.get("/api/alerts")
    async def list_alerts(
        request: Request,
        user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        db: Database = request.app.state.db
        role_filter = None if user["role"] == "admin" else user["role"]
        alerts = db.list_alerts(role_filter=role_filter)
        if user["role"] == "citizen":
            # Also include SOS alerts created by this citizen
            all_alerts = db.list_alerts(role_filter=None)
            seen = {a["alert_id"] for a in alerts}
            for a in all_alerts:
                if a["created_by"] == user["sub"] and a["alert_id"] not in seen:
                    alerts.append(a)
        return {"alerts": alerts}

    @app.get("/api/deliveries")
    async def list_deliveries(
        request: Request,
        alert_id: str | None = Query(default=None),
        role: str | None = Query(default=None),
        user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        db: Database = request.app.state.db
        routing: RoutingEngine = request.app.state.routing
        caller_role = user["role"]

        effective_role = role if caller_role == "admin" else caller_role
        rows = db.get_deliveries(alert_id=alert_id, target_role=effective_role)
        for row in rows:
            dst_node = config.ROLE_NODE_MAP.get(row["target_role"], "TOWER_SOUTH")
            baseline = routing.get_baseline_path("ECC_HQ", dst_node)
            rlist = row.get("route_list") or []
            row["rerouted"] = bool(rlist and baseline and rlist != baseline)
        return {"deliveries": rows}

    @app.post("/api/deliveries/{alert_id}/ack")
    @app.post("/api/alerts/{alert_id}/ack")
    async def manual_ack(
        alert_id: str,
        request: Request,
        user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        db: Database = request.app.state.db
        metrics: MetricsCollector = request.app.state.metrics
        caller_role = user["role"]

        delivery = db.get_delivery_for_alert_role(alert_id, caller_role)
        if delivery is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No delivery found for alert '{alert_id}' and role '{caller_role}'",
            )

        if delivery["status"] == "ACKNOWLEDGED":
            return {
                "delivery": db.get_delivery(delivery["id"]),
                "alert_status": db.recompute_alert_status(alert_id),
            }

        now = time.time()
        ref_time = delivery["sent_at"] if delivery["sent_at"] is not None else delivery["created_at"]
        rtt_ms = max(0.01, (now - float(ref_time)) * 1000.0)
        db.update_delivery(
            delivery["id"],
            status="ACKNOWLEDGED",
            client_id=delivery.get("client_id") or f"{caller_role}-web-console",
            rtt_ms=rtt_ms,
            ack_at=now,
            clear_estimated_wait=True,
        )
        metrics.record_ack(delivery["protocol"], rtt_ms)
        new_status = db.recompute_alert_status(alert_id)
        db.add_log(
            "INFO",
            "API",
            "MANUAL_ACK",
            {"alert_id": alert_id, "role": caller_role, "rtt_ms": round(rtt_ms, 2)},
        )
        request.app.state.hub.broadcast_threadsafe(
            {"type": "delivery_updated", "data": {"alert_id": alert_id, "alert_status": new_status}}
        )
        return {
            "delivery": db.get_delivery(delivery["id"]),
            "alert_status": new_status,
        }

    @app.post("/api/admin/clear")
    async def admin_clear(
        request: Request,
        user: dict[str, Any] = Depends(auth.require_role("admin")),
    ) -> dict[str, Any]:
        request.app.state.pqueue.clear()
        request.app.state.db.clear_operational_data()
        request.app.state.metrics.reset()
        request.app.state.latest_capture = None
        request.app.state.ns2_results.clear()
        request.app.state.db.add_log("INFO", "API", "ADMIN_CLEAR", {"by": user["sub"]})
        return {"status": "cleared"}

    @app.get("/api/topology")
    async def get_topology(
        request: Request,
        _user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        topo = request.app.state.db.get_topology()
        for link in topo["links"]:
            link["label"] = EMULATED_LABEL
        return {
            **topo,
            "emulated_stats": request.app.state.link_emulator.get_stats(),
            "connected_clients": _get_connected_clients(request),
        }

    @app.post("/api/topology/link/{link_id}")
    async def update_link(
        link_id: str,
        body: LinkUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(auth.require_role("admin")),
    ) -> dict[str, Any]:
        db: Database = request.app.state.db
        emu: LinkEmulator = request.app.state.link_emulator

        existing = db.query_one("SELECT * FROM topology_links WHERE link_id = ?", (link_id,))
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown link '{link_id}'")

        if body.is_up is not None:
            db.set_link_state(link_id, body.is_up)
        if body.delay_ms is not None or body.bandwidth_kbps is not None or body.queue_limit is not None:
            emu.set_link_params(
                link_id,
                delay_ms=body.delay_ms,
                bandwidth_kbps=body.bandwidth_kbps,
                queue_limit=body.queue_limit,
            )
        emu.refresh_from_db()
        db.add_log(
            "INFO",
            "TOPOLOGY",
            "LINK_UPDATED",
            {"link_id": link_id, "changes": body.model_dump(exclude_none=True), "by": user["sub"]},
        )
        request.app.state.hub.broadcast_threadsafe(
            {"type": "topology_updated", "data": {"link_id": link_id}}
        )
        updated = db.query_one("SELECT * FROM topology_links WHERE link_id = ?", (link_id,))
        if updated:
            updated["is_up"] = bool(updated["is_up"])
            updated["label"] = EMULATED_LABEL
        return {"link": updated}

    @app.post("/api/topology/node/{node_id}")
    async def update_node(
        node_id: str,
        body: NodeUpdateRequest,
        request: Request,
        user: dict[str, Any] = Depends(auth.require_role("admin")),
    ) -> dict[str, Any]:
        db: Database = request.app.state.db
        if not db.set_node_state(node_id, body.is_up):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown node '{node_id}'")
        db.add_log("INFO", "TOPOLOGY", "NODE_UPDATED", {"node_id": node_id, "is_up": body.is_up, "by": user["sub"]})
        request.app.state.hub.broadcast_threadsafe({"type": "topology_updated", "data": {"node_id": node_id}})
        node = db.query_one("SELECT * FROM topology_nodes WHERE node_id = ?", (node_id,))
        if node:
            node["is_up"] = bool(node["is_up"])
        return {"node": node}

    @app.get("/api/routes")
    async def query_routes(
        request: Request,
        src: str = Query(default="ECC_HQ"),
        dst: str | None = Query(default=None),
        _user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        routing: RoutingEngine = request.app.state.routing
        if dst:
            return routing.compare_routes(src, dst)
        return routing.all_routing_tables_from(src)

    @app.get("/api/metrics")
    async def get_metrics(
        request: Request,
        limit: int = Query(default=120, ge=1, le=1000),
        _user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        metrics: MetricsCollector = request.app.state.metrics
        db: Database = request.app.state.db
        return {
            "current": metrics.snapshot(),
            "history": db.get_metrics_samples(limit=limit),
            "queue": request.app.state.pqueue.snapshot(),
            "emulated_links": request.app.state.link_emulator.get_stats(),
            "connected_clients": _get_connected_clients(request),
        }

    @app.get("/api/logs")
    async def get_logs(
        request: Request,
        limit: int = Query(default=150, ge=1, le=1000),
        _user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        return {"logs": request.app.state.db.get_logs(limit=limit)}

    @app.post("/api/wireshark/upload")
    async def upload_pcap(
        request: Request,
        file: UploadFile = File(...),
        user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        raw = await file.read()
        if len(raw) > 25 * 1024 * 1024:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Capture exceeds 25 MB limit")
        try:
            parsed = pcap_reader.parse_capture(raw, filename=file.filename or "capture.pcap")
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        request.app.state.latest_capture = parsed
        request.app.state.db.add_log(
            "INFO",
            "WIRESHARK",
            "CAPTURE_UPLOADED",
            {
                "filename": parsed["filename"],
                "total_packets": parsed["total_packets"],
                "emrg_packets": parsed["emrg_packets"],
                "by": user["sub"],
            },
        )
        return parsed

    @app.get("/api/wireshark/captures")
    async def get_latest_capture(
        request: Request,
        _user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        cap = request.app.state.latest_capture
        if cap is None:
            return {"capture": None}
        return {"capture": cap}

    @app.post("/api/ns2/upload")
    async def upload_ns2_trace(
        request: Request,
        load: Ns2LoadLiteral = Form(...),
        file: UploadFile = File(...),
        user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        raw = await file.read()
        if len(raw) > 50 * 1024 * 1024:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Trace exceeds 50 MB limit")
        text = raw.decode("utf-8", errors="replace")
        try:
            parsed = parse_trace_text(text, load_name=load)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        parsed["filename"] = file.filename or f"real_trace_{load}.tr"
        request.app.state.ns2_results[load] = parsed
        request.app.state.db.add_log(
            "INFO",
            "NS2",
            "TRACE_UPLOADED",
            {"load": load, "filename": parsed["filename"], "valid_lines": parsed["valid_lines"], "by": user["sub"]},
        )
        return parsed

    @app.get("/api/ns2/results")
    async def get_ns2_results(
        request: Request,
        _user: dict[str, Any] = Depends(auth.require_role()),
    ) -> dict[str, Any]:
        return {"loads": request.app.state.ns2_results}

    @app.websocket("/ws/telemetry")
    async def ws_telemetry(ws: WebSocket, token: str | None = Query(default=None)) -> None:
        secret_file = getattr(ws.app.state, "secret_file", None)
        try:
            if not token:
                raise auth.AuthError("Missing token")
            auth.verify_token(token, secret_file=secret_file)
        except auth.AuthError:
            await ws.close(code=1008, reason="Authentication required")
            return

        hub: TelemetryHub = ws.app.state.hub
        await hub.connect(ws)
        try:
            await ws.send_text(
                json.dumps(
                    {
                        "type": "snapshot",
                        "data": {
                            "metrics": ws.app.state.metrics.snapshot(),
                            "queue": ws.app.state.pqueue.snapshot(),
                        },
                    }
                )
            )
            while True:
                # Keep socket open; echo/ignore pings
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            hub.disconnect(ws)

    # Static frontend serving
    if config.FRONTEND_DIR.exists():
        css_dir = config.FRONTEND_DIR / "css"
        js_dir = config.FRONTEND_DIR / "js"
        if css_dir.exists():
            app.mount("/css", StaticFiles(directory=str(css_dir)), name="css")
        if js_dir.exists():
            app.mount("/js", StaticFiles(directory=str(js_dir)), name="js")

        @app.get("/")
        async def index_page() -> FileResponse:
            return FileResponse(
                str(config.FRONTEND_DIR / "index.html"),
                headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
            )

    return app


app = create_app()

