"""TLS 1.2+/1.3 alert server using cryptography-generated X.509 certificates.

Course Mapping:
- CO2 (Application-layer protocol): Speaks framed EMRG protocol over TLS.
- CO3 (Transport & Security): Encrypted reliable socket channel for sensitive
  patient/tactical alerts (Hospital / Police).
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend import config
from backend.db import Database
from backend.servers.tcp_server import TcpAlertServer


def ensure_tls_certificates(
    cert_path: Path | None = None,
    key_path: Path | None = None,
    *,
    common_name: str = "localhost",
) -> tuple[Path, Path]:
    """Ensure self-signed X.509 cert & private key exist on disk, generating via cryptography if needed."""
    crt = Path(cert_path) if cert_path is not None else config.TLS_CERT_FILE
    key = Path(key_path) if key_path is not None else config.TLS_KEY_FILE
    crt.parent.mkdir(parents=True, exist_ok=True)
    key.parent.mkdir(parents=True, exist_ok=True)

    if crt.exists() and key.exists():
        return crt, key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Uttar Pradesh"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Noida"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JIIT Noida ECAS"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv6Address("::1")),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    key.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return crt, key


class TlsAlertServer(TcpAlertServer):
    """TLS 1.2+/1.3 authenticated alert server for sensitive traffic."""

    protocol_name = "TLS"

    def __init__(
        self,
        host: str = config.BIND_HOST,
        port: int = config.TLS_PORT,
        *,
        cert_file: Path | None = None,
        key_file: Path | None = None,
        db: Database | None = None,
        metrics: Any = None,
        secret_file: Path | None = None,
        ack_timeout_sec: float = config.ACK_TIMEOUT_SEC,
        max_retries: int = config.MAX_RETRIES,
        backoff_base_sec: float = config.BACKOFF_BASE_SEC,
        heartbeat_timeout_sec: float = config.HEARTBEAT_TIMEOUT_SEC,
    ) -> None:
        super().__init__(
            host=host,
            port=port,
            db=db,
            metrics=metrics,
            secret_file=secret_file,
            ack_timeout_sec=ack_timeout_sec,
            max_retries=max_retries,
            backoff_base_sec=backoff_base_sec,
            heartbeat_timeout_sec=heartbeat_timeout_sec,
        )
        self.cert_file, self.key_file = ensure_tls_certificates(cert_file, key_file)
        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl_ctx.load_cert_chain(certfile=str(self.cert_file), keyfile=str(self.key_file))

    def _wrap_client_socket(self, conn: socket.socket) -> ssl.SSLSocket:
        return self._ssl_ctx.wrap_socket(conn, server_side=True)

