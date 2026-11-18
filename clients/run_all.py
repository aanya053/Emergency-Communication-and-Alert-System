"""Single-command launcher for ECAS: starts FastAPI + socket servers + all separate responder processes.

Non-Negotiable Rule #2:
Responders (Police, Ambulance, Fire, Hospital, Citizen) run as SEPARATE OS PROCESSES
that connect over real sockets, never as threads inside the server.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend import config


def wait_for_server(api_url: str, timeout_sec: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_sec
    url = f"{api_url.rstrip('/')}/api/alerts"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return
        except urllib.error.HTTPError as exc:
            # FastAPI is ready and enforcing auth (401 on unauthenticated GET)
            if exc.code in (401, 403):
                return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.3)
    raise TimeoutError(f"ECAS server did not become ready at {url} within {timeout_sec}s")


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch ECAS server and all separate responder processes")
    parser.add_argument("--host", default=config.BIND_HOST)
    parser.add_argument("--api-port", type=int, default=config.API_PORT)
    args = parser.parse_args()

    api_url = f"http://{args.host}:{args.api_port}"
    python_exe = sys.executable
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT_DIR)

    procs: list[tuple[str, subprocess.Popen[bytes]]] = []

    def _shutdown() -> None:
        print("\n[run_all] Shutting down all ECAS processes...", flush=True)
        for name, p in reversed(procs):
            if p.poll() is None:
                print(f"[run_all] Stopping {name} (PID {p.pid})...", flush=True)
                p.terminate()
        deadline = time.monotonic() + 5.0
        for name, p in reversed(procs):
            remaining = max(0.2, deadline - time.monotonic())
            try:
                p.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                p.kill()

    try:
        print(f"[run_all] Starting ECAS Backend (FastAPI + TCP:{config.TCP_PORT} + UDP:{config.UDP_PORT} + TLS:{config.TLS_PORT})...", flush=True)
        server_proc = subprocess.Popen(
            [
                python_exe,
                "-m",
                "uvicorn",
                "backend.api:app",
                "--host",
                args.host,
                "--port",
                str(args.api_port),
            ],
            cwd=str(ROOT_DIR),
            env=env,
        )
        procs.append(("server", server_proc))

        wait_for_server(api_url, timeout_sec=20.0)
        print(f"[run_all] Server ready at {api_url}", flush=True)

        client_specs: list[tuple[str, list[str]]] = [
            (
                "police",
                [
                    python_exe,
                    str(ROOT_DIR / "clients" / "responder.py"),
                    "--role",
                    "police",
                    "--server",
                    args.host,
                    "--tls",
                    "--also-tcp-port",
                    str(config.TCP_PORT),
                    "--udp-port",
                    str(config.UDP_PORT),
                    "--api-url",
                    api_url,
                ],
            ),
            (
                "hospital",
                [
                    python_exe,
                    str(ROOT_DIR / "clients" / "responder.py"),
                    "--role",
                    "hospital",
                    "--server",
                    args.host,
                    "--tls",
                    "--also-tcp-port",
                    str(config.TCP_PORT),
                    "--udp-port",
                    str(config.UDP_PORT),
                    "--api-url",
                    api_url,
                ],
            ),
            (
                "ambulance",
                [
                    python_exe,
                    str(ROOT_DIR / "clients" / "responder.py"),
                    "--role",
                    "ambulance",
                    "--server",
                    args.host,
                    "--udp-port",
                    str(config.UDP_PORT),
                    "--api-url",
                    api_url,
                ],
            ),
            (
                "fire",
                [
                    python_exe,
                    str(ROOT_DIR / "clients" / "responder.py"),
                    "--role",
                    "fire",
                    "--server",
                    args.host,
                    "--udp-port",
                    str(config.UDP_PORT),
                    "--api-url",
                    api_url,
                ],
            ),
            (
                "citizen",
                [
                    python_exe,
                    str(ROOT_DIR / "clients" / "citizen.py"),
                    "--server",
                    args.host,
                    "--port",
                    str(config.UDP_PORT),
                    "--api-url",
                    api_url,
                ],
            ),
        ]

        for name, cmd in client_specs:
            p = subprocess.Popen(cmd, cwd=str(ROOT_DIR), env=env)
            procs.append((name, p))
            print(f"[run_all] Launched {name} responder process (PID {p.pid})", flush=True)

        print(f"\n[run_all] All processes running. Open {api_url} in your browser. Press Ctrl+C to stop.\n", flush=True)
        while True:
            if server_proc.poll() is not None:
                print(f"[run_all] Server exited with code {server_proc.returncode}", flush=True)
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown()


if __name__ == "__main__":
    main()
