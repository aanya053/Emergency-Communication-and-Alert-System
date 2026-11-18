"""Centralized configuration for the Emergency Communication and Alert System.

Course Mapping:
- CO5 (IP addressing & ports): Explicit port bindings for TCP (9001), UDP (9002),
  TLS (9003), and FastAPI HTTP/WebSocket (8000).
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("EAS_DATA_DIR", BASE_DIR / "data"))
CERTS_DIR = Path(os.environ.get("EAS_CERTS_DIR", BASE_DIR / "certs"))
CAPTURES_DIR = Path(os.environ.get("EAS_CAPTURES_DIR", BASE_DIR / "captures"))
FRONTEND_DIR = BASE_DIR / "frontend"

DB_PATH = Path(os.environ.get("EAS_DB_PATH", DATA_DIR / "ecas.db"))
SECRET_FILE = Path(os.environ.get("EAS_SECRET_FILE", DATA_DIR / ".secret"))
TLS_CERT_FILE = Path(os.environ.get("EAS_CERT_FILE", CERTS_DIR / "server.crt"))
TLS_KEY_FILE = Path(os.environ.get("EAS_KEY_FILE", CERTS_DIR / "server.key"))

# Network endpoints (CO5: IP addressing and well-defined application ports)
BIND_HOST = os.environ.get("EAS_BIND_HOST", "127.0.0.1")
TCP_PORT = int(os.environ.get("EAS_TCP_PORT", "9001"))
UDP_PORT = int(os.environ.get("EAS_UDP_PORT", "9002"))
TLS_PORT = int(os.environ.get("EAS_TLS_PORT", "9003"))
API_PORT = int(os.environ.get("EAS_API_PORT", "8000"))

# Authentication & token settings
PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_SEC = int(os.environ.get("EAS_TOKEN_TTL_SEC", "43200"))  # 12 hours

VALID_ROLES = ("admin", "police", "ambulance", "fire", "hospital", "citizen")
RESPONDER_ROLES = ("police", "ambulance", "fire", "hospital", "citizen")
SENSITIVE_ROLES = ("hospital", "police")

# Transport / timer / queue settings (CO3)
ACK_TIMEOUT_SEC = float(os.environ.get("EAS_ACK_TIMEOUT_SEC", "2.0"))
MAX_RETRIES = int(os.environ.get("EAS_MAX_RETRIES", "3"))
BACKOFF_BASE_SEC = float(os.environ.get("EAS_BACKOFF_BASE_SEC", "0.5"))
HEARTBEAT_INTERVAL_SEC = float(os.environ.get("EAS_HEARTBEAT_INTERVAL_SEC", "5.0"))
HEARTBEAT_TIMEOUT_SEC = float(os.environ.get("EAS_HEARTBEAT_TIMEOUT_SEC", "15.0"))
AGING_THRESHOLD_SEC = float(os.environ.get("EAS_AGING_THRESHOLD_SEC", "15.0"))
REDELIVERY_INTERVAL_SEC = float(os.environ.get("EAS_REDELIVERY_INTERVAL_SEC", "1.5"))

# Topology role -> node mapping (CO4)
ROLE_NODE_MAP = {
    "police": "POLICE",
    "fire": "FIRE",
    "ambulance": "AMBULANCE",
    "hospital": "HOSPITAL",
    "citizen": "TOWER_SOUTH",
    "admin": "ECC_HQ",
}


def ensure_directories() -> None:
    """Ensure runtime data, certs, and captures directories exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

