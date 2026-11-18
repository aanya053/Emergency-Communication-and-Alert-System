"""SQLite persistence layer (WAL mode) for ECAS.

Manages users, alerts, per-target deliveries, network event logs,
network topology nodes/links, and 1 Hz metrics time-series samples.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from backend import config

DEFAULT_TOPOLOGY_NODES = [
    ("ECC_HQ", "ECC Headquarters", "core", "admin", 120.0, 220.0, 1, "10.0.0.10", "255.255.255.0", "10.0.0.1"),
    ("TOWER_NORTH", "Relay Tower North", "relay", None, 330.0, 110.0, 1, "10.0.1.11", "255.255.255.0", "10.0.1.1"),
    ("TOWER_SOUTH", "Relay Tower South (Citizen Sector)", "relay", "citizen", 330.0, 330.0, 1, "10.0.1.12", "255.255.255.0", "10.0.1.1"),
    ("SUBSTATION_A", "Substation A", "relay", None, 540.0, 220.0, 1, "10.0.1.13", "255.255.255.0", "10.0.1.1"),
    ("POLICE", "Police Dispatch", "responder", "police", 760.0, 70.0, 1, "10.0.2.21", "255.255.255.0", "10.0.2.1"),
    ("FIRE", "Fire Department", "responder", "fire", 760.0, 170.0, 1, "10.0.2.22", "255.255.255.0", "10.0.2.1"),
    ("AMBULANCE", "Ambulance Fleet", "responder", "ambulance", 760.0, 270.0, 1, "10.0.2.23", "255.255.255.0", "10.0.2.1"),
    ("HOSPITAL", "Central Hospital", "responder", "hospital", 760.0, 370.0, 1, "10.0.2.24", "255.255.255.0", "10.0.2.1"),
]

DEFAULT_TOPOLOGY_LINKS = [
    ("L_ECC_NORTH", "ECC_HQ", "TOWER_NORTH", 12.0, 2000.0, 20, 1),
    ("L_ECC_SOUTH", "ECC_HQ", "TOWER_SOUTH", 18.0, 1500.0, 15, 1),
    ("L_NORTH_SUB", "TOWER_NORTH", "SUBSTATION_A", 10.0, 1500.0, 15, 1),
    ("L_SOUTH_SUB", "TOWER_SOUTH", "SUBSTATION_A", 14.0, 1200.0, 15, 1),
    ("L_NORTH_POL", "TOWER_NORTH", "POLICE", 8.0, 2000.0, 20, 1),
    ("L_SUB_POL", "SUBSTATION_A", "POLICE", 15.0, 1200.0, 15, 1),
    ("L_NORTH_FIRE", "TOWER_NORTH", "FIRE", 15.0, 1500.0, 15, 1),
    ("L_SUB_FIRE", "SUBSTATION_A", "FIRE", 10.0, 1500.0, 15, 1),
    ("L_SOUTH_AMB", "TOWER_SOUTH", "AMBULANCE", 12.0, 1200.0, 15, 1),
    ("L_SUB_AMB", "SUBSTATION_A", "AMBULANCE", 14.0, 1200.0, 15, 1),
    ("L_SOUTH_HOSP", "TOWER_SOUTH", "HOSPITAL", 16.0, 1500.0, 15, 1),
    ("L_SUB_HOSP", "SUBSTATION_A", "HOSPITAL", 11.0, 2000.0, 20, 1),
]


class Database:
    """Thread-safe SQLite database wrapper configured with WAL mode."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else config.DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        self.init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn = conn
            with self._lock:
                self._connections.append(conn)
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize write transactions across threads."""
        with self._lock:
            conn = self._get_conn()
            conn.execute("BEGIN IMMEDIATE;")
            try:
                yield conn
                if conn.in_transaction:
                    conn.execute("COMMIT;")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
                raise

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._get_conn().execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._get_conn().execute(sql, params).fetchone()
            return dict(row) if row is not None else None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self.transaction() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid or 0

    def close_all(self) -> None:
        with self._lock:
            for conn in self._connections:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._connections.clear()
            if hasattr(self._local, "conn"):
                delattr(self._local, "conn")

    def init_schema(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    alert_code TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    target_roles TEXT NOT NULL,
                    location TEXT NOT NULL,
                    sensitive INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    target_role TEXT NOT NULL,
                    client_id TEXT,
                    protocol TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    rtt_ms REAL,
                    route TEXT,
                    estimated_wait_sec REAL,
                    last_error TEXT,
                    sent_at REAL,
                    ack_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_deliveries_alert ON deliveries(alert_id);
                CREATE INDEX IF NOT EXISTS idx_deliveries_role ON deliveries(target_role);
                CREATE INDEX IF NOT EXISTS idx_deliveries_status ON deliveries(status);

                CREATE TABLE IF NOT EXISTS network_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    event TEXT NOT NULL,
                    details TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS topology_nodes (
                    node_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    role TEXT,
                    x REAL NOT NULL,
                    y REAL NOT NULL,
                    is_up INTEGER NOT NULL DEFAULT 1,
                    ip_address TEXT NOT NULL DEFAULT '',
                    subnet_mask TEXT NOT NULL DEFAULT '',
                    gateway TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS topology_links (
                    link_id TEXT PRIMARY KEY,
                    src TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    delay_ms REAL NOT NULL,
                    bandwidth_kbps REAL NOT NULL,
                    queue_limit INTEGER NOT NULL,
                    is_up INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS metrics_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    avg_rtt_ms REAL,
                    min_rtt_ms REAL,
                    max_rtt_ms REAL,
                    p95_rtt_ms REAL,
                    throughput_bps REAL NOT NULL,
                    loss_rate REAL NOT NULL,
                    ack_rate REAL NOT NULL,
                    tcp_sent INTEGER NOT NULL,
                    tcp_acked INTEGER NOT NULL,
                    udp_sent INTEGER NOT NULL,
                    udp_lost INTEGER NOT NULL,
                    tls_sent INTEGER NOT NULL,
                    queue_depth INTEGER NOT NULL
                );
                """
            )

        self._migrate_topology_columns()
        self.seed_topology()

    def _migrate_topology_columns(self) -> None:
        cols = {row["name"] for row in self.query_all("PRAGMA table_info(topology_nodes)")}
        with self._lock:
            conn = self._get_conn()
            for col in ("ip_address", "subnet_mask", "gateway"):
                if col not in cols:
                    conn.execute(f"ALTER TABLE topology_nodes ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")

    def seed_topology(self) -> None:
        existing_nodes = self.query_one("SELECT COUNT(*) AS cnt FROM topology_nodes")
        if existing_nodes and existing_nodes["cnt"] == 0:
            with self.transaction() as conn:
                conn.executemany(
                    "INSERT INTO topology_nodes(node_id, label, node_type, role, x, y, is_up, ip_address, subnet_mask, gateway) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    DEFAULT_TOPOLOGY_NODES,
                )
        else:
            # Backfill IP/mask/gateway on existing DB rows if blank
            with self.transaction() as conn:
                for node in DEFAULT_TOPOLOGY_NODES:
                    conn.execute(
                        "UPDATE topology_nodes SET ip_address = ?, subnet_mask = ?, gateway = ? WHERE node_id = ? AND ip_address = ''",
                        (node[7], node[8], node[9], node[0]),
                    )
        existing_links = self.query_one("SELECT COUNT(*) AS cnt FROM topology_links")
        if existing_links and existing_links["cnt"] == 0:
            with self.transaction() as conn:
                conn.executemany(
                    "INSERT INTO topology_links(link_id, src, dst, delay_ms, bandwidth_kbps, queue_limit, is_up) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    DEFAULT_TOPOLOGY_LINKS,
                )

    # --- User operations ---
    def get_user(self, username: str) -> dict[str, Any] | None:
        return self.query_one("SELECT * FROM users WHERE username = ?", (username,))

    def upsert_user(self, username: str, password_hash: str, role: str) -> None:
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO users(username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role
                """,
                (username, password_hash, role, now),
            )

    def ensure_user(self, username: str, password_hash: str, role: str) -> None:
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO users(username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, password_hash, role, now),
            )

    # --- Alert & Delivery operations ---
    def create_alert(
        self,
        *,
        alert_id: str,
        alert_code: str,
        title: str,
        message: str,
        alert_type: str,
        priority: int,
        protocol: str,
        target_roles: list[str],
        location: str,
        sensitive: bool,
        status: str,
        created_by: str,
        created_at: float | None = None,
    ) -> None:
        now = created_at if created_at is not None else time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO alerts(
                    alert_id, alert_code, title, message, alert_type, priority,
                    protocol, target_roles, location, sensitive, status,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert_code,
                    title,
                    message,
                    alert_type,
                    int(priority),
                    protocol,
                    json.dumps(target_roles),
                    location,
                    1 if sensitive else 0,
                    status,
                    created_by,
                    now,
                    now,
                ),
            )
            for role in target_roles:
                conn.execute(
                    """
                    INSERT INTO deliveries(
                        alert_id, target_role, protocol, status, attempts,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 0, ?, ?)
                    """,
                    (alert_id, role, protocol, "QUEUED", now, now),
                )

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        row = self.query_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        if row:
            row["target_roles"] = json.loads(row["target_roles"])
            row["sensitive"] = bool(row["sensitive"])
        return row

    def list_alerts(self, role_filter: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.query_all(
            "SELECT * FROM alerts ORDER BY priority ASC, created_at DESC LIMIT ?",
            (limit,),
        )
        results: list[dict[str, Any]] = []
        for row in rows:
            roles = json.loads(row["target_roles"])
            row["target_roles"] = roles
            row["sensitive"] = bool(row["sensitive"])
            if role_filter and role_filter not in roles and row["created_by"] != role_filter:
                continue
            results.append(row)
        return results

    def update_alert_status(self, alert_id: str, status: str) -> None:
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
                (status, now, alert_id),
            )

    def recompute_alert_status(self, alert_id: str) -> str:
        rows = self.query_all("SELECT status FROM deliveries WHERE alert_id = ?", (alert_id,))
        if not rows:
            return "QUEUED"
        statuses = [r["status"] for r in rows]
        if all(s == "ACKNOWLEDGED" for s in statuses):
            new_status = "ACKNOWLEDGED"
        elif any(s in ("ACKNOWLEDGED", "SENT", "DELIVERED", "REROUTED") for s in statuses):
            new_status = "PARTIALLY_DELIVERED"
        elif any(s == "WAITING_NETWORK" for s in statuses):
            new_status = "WAITING_NETWORK"
        elif all(s == "FAILED" for s in statuses):
            new_status = "FAILED"
        else:
            new_status = "QUEUED"
        self.update_alert_status(alert_id, new_status)
        return new_status

    def get_deliveries(
        self,
        *,
        alert_id: str | None = None,
        target_role: str | None = None,
        statuses: tuple[str, ...] | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if alert_id is not None:
            clauses.append("d.alert_id = ?")
            params.append(alert_id)
        if target_role is not None:
            clauses.append("d.target_role = ?")
            params.append(target_role)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"d.status IN ({placeholders})")
            params.extend(statuses)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT d.*, a.alert_code, a.title, a.message, a.alert_type, a.priority,
                   a.location, a.sensitive, a.created_by
            FROM deliveries d
            JOIN alerts a ON d.alert_id = a.alert_id
            {where}
            ORDER BY a.priority ASC, d.created_at DESC, d.id ASC
            LIMIT ?
        """
        params.append(limit)
        rows = self.query_all(sql, tuple(params))
        for r in rows:
            r["sensitive"] = bool(r["sensitive"])
            if r["route"]:
                try:
                    r["route_list"] = json.loads(r["route"])
                except json.JSONDecodeError:
                    r["route_list"] = []
            else:
                r["route_list"] = []
        return rows

    def get_delivery(self, delivery_id: int) -> dict[str, Any] | None:
        return self.query_one("SELECT * FROM deliveries WHERE id = ?", (delivery_id,))

    def get_delivery_for_alert_role(self, alert_id: str, target_role: str) -> dict[str, Any] | None:
        return self.query_one(
            "SELECT * FROM deliveries WHERE alert_id = ? AND target_role = ?",
            (alert_id, target_role),
        )

    def update_delivery(
        self,
        delivery_id: int,
        *,
        status: str | None = None,
        client_id: str | None = None,
        attempts: int | None = None,
        rtt_ms: float | None = None,
        route: list[str] | str | None = None,
        estimated_wait_sec: float | None = None,
        clear_estimated_wait: bool = False,
        last_error: str | None = None,
        sent_at: float | None = None,
        ack_at: float | None = None,
    ) -> None:
        fields: list[str] = []
        params: list[Any] = []
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        if client_id is not None:
            fields.append("client_id = ?")
            params.append(client_id)
        if attempts is not None:
            fields.append("attempts = ?")
            params.append(attempts)
        if rtt_ms is not None:
            fields.append("rtt_ms = ?")
            params.append(round(float(rtt_ms), 3))
        if route is not None:
            route_val = json.dumps(route) if isinstance(route, list) else route
            fields.append("route = ?")
            params.append(route_val)
        if clear_estimated_wait:
            fields.append("estimated_wait_sec = NULL")
        elif estimated_wait_sec is not None:
            fields.append("estimated_wait_sec = ?")
            params.append(round(float(estimated_wait_sec), 2))
        if last_error is not None:
            fields.append("last_error = ?")
            params.append(last_error)
        if sent_at is not None:
            fields.append("sent_at = ?")
            params.append(sent_at)
        if ack_at is not None:
            fields.append("ack_at = ?")
            params.append(ack_at)

        fields.append("updated_at = ?")
        params.append(time.time())
        params.append(delivery_id)
        sql = f"UPDATE deliveries SET {', '.join(fields)} WHERE id = ?"
        with self.transaction() as conn:
            conn.execute(sql, tuple(params))

    def clear_operational_data(self) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM deliveries")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM network_logs")
            conn.execute("DELETE FROM metrics_samples")

    # --- Logs ---
    def add_log(self, level: str, component: str, event: str, details: dict[str, Any] | str = "") -> None:
        details_str = json.dumps(details) if isinstance(details, dict) else str(details)
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO network_logs(timestamp, level, component, event, details) VALUES (?, ?, ?, ?, ?)",
                (time.time(), level.upper(), component, event, details_str),
            )

    def get_logs(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.query_all(
            "SELECT * FROM network_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )

    # --- Topology ---
    def get_topology(self) -> dict[str, list[dict[str, Any]]]:
        nodes = self.query_all("SELECT * FROM topology_nodes ORDER BY node_id")
        links = self.query_all("SELECT * FROM topology_links ORDER BY link_id")
        for n in nodes:
            n["is_up"] = bool(n["is_up"])
        for l in links:
            l["is_up"] = bool(l["is_up"])
        return {"nodes": nodes, "links": links}

    def set_link_state(self, link_id: str, is_up: bool) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE topology_links SET is_up = ? WHERE link_id = ?",
                (1 if is_up else 0, link_id),
            )
            return cur.rowcount > 0

    def set_node_state(self, node_id: str, is_up: bool) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE topology_nodes SET is_up = ? WHERE node_id = ?",
                (1 if is_up else 0, node_id),
            )
            return cur.rowcount > 0

    # --- Metrics samples ---
    def insert_metrics_sample(self, sample: dict[str, Any]) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO metrics_samples(
                    timestamp, avg_rtt_ms, min_rtt_ms, max_rtt_ms, p95_rtt_ms,
                    throughput_bps, loss_rate, ack_rate,
                    tcp_sent, tcp_acked, udp_sent, udp_lost, tls_sent, queue_depth
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample["timestamp"],
                    sample.get("avg_rtt_ms"),
                    sample.get("min_rtt_ms"),
                    sample.get("max_rtt_ms"),
                    sample.get("p95_rtt_ms"),
                    sample["throughput_bps"],
                    sample["loss_rate"],
                    sample["ack_rate"],
                    sample["tcp_sent"],
                    sample["tcp_acked"],
                    sample["udp_sent"],
                    sample["udp_lost"],
                    sample["tls_sent"],
                    sample["queue_depth"],
                ),
            )

    def get_metrics_samples(self, limit: int = 120) -> list[dict[str, Any]]:
        rows = self.query_all(
            "SELECT * FROM metrics_samples ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows.reverse()
        return rows
