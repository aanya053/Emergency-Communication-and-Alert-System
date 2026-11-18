"""Authentication, password hashing, HMAC token signing, and RBAC for ECAS.

- Password hashing: PBKDF2-HMAC-SHA256 with 200,000 iterations and 16-byte random salt.
- Session tokens: URL-safe base64 JSON payload signed with HMAC-SHA256 and expiry check.
- Secret key: Loaded from EAS_SECRET_KEY env var or generated & persisted in data/.secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend import config
from backend.db import Database

DEFAULT_SEED_USERS: dict[str, tuple[str, str]] = {
    "admin": ("admin123", "admin"),
    "police": ("police123", "police"),
    "ambulance": ("ambulance123", "ambulance"),
    "fire": ("fire123", "fire"),
    "hospital": ("hospital123", "hospital"),
    "citizen": ("citizen123", "citizen"),
}

_bearer_scheme = HTTPBearer(auto_error=False)


class AuthError(Exception):
    """Raised on authentication or token verification failure."""


def get_secret_key(secret_file: Path | None = None) -> bytes:
    """Return HMAC signing secret from EAS_SECRET_KEY or persistent data/.secret."""
    env_secret = os.environ.get("EAS_SECRET_KEY")
    if env_secret:
        return env_secret.encode("utf-8")

    path = secret_file if secret_file is not None else config.SECRET_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        if raw:
            return raw.encode("utf-8")

    generated = secrets.token_hex(32)
    path.write_text(generated, encoding="utf-8")
    return generated.encode("utf-8")


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    if not password:
        raise ValueError("Password must not be empty")
    salt_bytes = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        config.PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${config.PBKDF2_ITERATIONS}${salt_bytes.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2-HMAC-SHA256 hash."""
    try:
        scheme, iter_str, salt_hex, hash_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt_bytes = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        iterations,
    )
    return hmac.compare_digest(derived, expected)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def create_token(
    username: str,
    role: str,
    *,
    ttl_sec: int | None = None,
    secret_file: Path | None = None,
) -> str:
    """Create an HMAC-SHA256 signed session token with explicit expiry."""
    now = int(time.time())
    ttl = ttl_sec if ttl_sec is not None else config.TOKEN_TTL_SEC
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(8),
    }
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    secret = get_secret_key(secret_file)
    sig = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(sig)}"


def verify_token(token: str, *, secret_file: Path | None = None) -> dict[str, Any]:
    """Verify HMAC signature and expiry on a session token, returning claims."""
    if not token or "." not in token:
        raise AuthError("Malformed token")
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as exc:
        raise AuthError("Invalid token encoding") from exc

    secret = get_secret_key(secret_file)
    expected_sig = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(sig_bytes, expected_sig):
        raise AuthError("Invalid token signature")

    try:
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise AuthError("Invalid token payload") from exc

    if not isinstance(claims, dict) or "sub" not in claims or "role" not in claims or "exp" not in claims:
        raise AuthError("Incomplete token claims")

    if int(claims["exp"]) < int(time.time()):
        raise AuthError("Token expired")

    if claims["role"] not in config.VALID_ROLES:
        raise AuthError("Invalid role in token")

    return claims


def seed_default_users(db: Database) -> None:
    """Ensure the six standard ECAS role accounts exist in SQLite."""
    for username, (password, role) in DEFAULT_SEED_USERS.items():
        if db.get_user(username) is None:
            db.ensure_user(username, hash_password(password), role)


def authenticate_user(db: Database, username: str, password: str) -> dict[str, Any] | None:
    """Authenticate username + password against the users table."""
    user = db.get_user(username)
    if user is None:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def require_role(*roles: str) -> Callable[..., dict[str, Any]]:
    """FastAPI dependency enforcing valid Bearer token (401) and allowed role (403)."""

    async def _dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> dict[str, Any]:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        secret_file = getattr(request.app.state, "secret_file", None)
        try:
            claims = verify_token(credentials.credentials, secret_file=secret_file)
        except AuthError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        if roles and claims["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{claims['role']}' is not authorized for this resource",
            )
        return claims

    return _dependency


def verify_socket_credentials(
    token: str | None,
    claimed_role: str | None,
    *,
    secret_file: Path | None = None,
) -> dict[str, Any]:
    """Verify a socket client's token and confirm the claimed role matches the token role."""
    if not token:
        raise AuthError("Missing authentication token")
    claims = verify_token(token, secret_file=secret_file)
    if not claimed_role or claims["role"] != claimed_role:
        raise AuthError(
            f"Role mismatch: token role '{claims['role']}' != claimed '{claimed_role}'"
        )
    return claims

