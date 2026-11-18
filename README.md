# Emergency Communication and Alert System (ECAS)

**Course:** Computer Networks Lab (`24B15CS313`) — Jaypee Institute of Information Technology (JIIT), Noida  
**Submitted To:** Dr. Mukta Goyal  
**Submitted By:** Udit Kumar Singh (`992401030002`), Tanmay Sharma (`992401030005`), Ayan Juneja (`992401030018`), Sudarshan Jha (`992401030025`)

---

## 1. Setup & Quick Start

### Prerequisites
- **Windows (Host):** Python 3.10+, Wireshark + Npcap (with Loopback Adapter enabled)
- **Ubuntu / WSL (for NS-2):** `ns2` package (`sudo apt-get update && sudo apt-get install -y ns2`)

### Installation
```powershell
python -m pip install -r requirements.txt
```

### Launch Everything (`run_all.py`)
```powershell
python run_all.py
```
`run_all.py` starts:
1. FastAPI + Uvicorn control/telemetry server on `http://127.0.0.1:8000`
2. TCP alert server on `127.0.0.1:9001`
3. UDP broadcast server on `127.0.0.1:9002`
4. TLS 1.2+/1.3 server on `127.0.0.1:9003` (auto-generating X.509 cert in `certs/`)
5. **Five separate OS responder processes** connecting over real sockets:
   - `clients/responder.py --role police --tls --also-tcp-port 9001 --udp-port 9002`
   - `clients/responder.py --role hospital --tls --also-tcp-port 9001 --udp-port 9002`
   - `clients/responder.py --role ambulance --udp-port 9002`
   - `clients/responder.py --role fire --udp-port 9002`
   - `clients/citizen.py` (UDP listener on port `9002`)

Open `http://127.0.0.1:8000` in your browser.

---

## 2. Default Accounts (PBKDF2-HMAC-SHA256, 200k iterations)

| Username | Password | Role | Access Scope |
|---|---|---|---|
| `admin` | `admin123` | `admin` | Full ECC Console, Topology/Link failure controls, Routing, Metrics, Clear |
| `police` | `police123` | `police` | Police Inbox + Manual ACK + Network/Wireshark/NS-2 views |
| `ambulance` | `ambulance123` | `ambulance` | Ambulance Inbox + Manual ACK + Network/Wireshark/NS-2 views |
| `fire` | `fire123` | `fire` | Fire Inbox + Manual ACK + Network/Wireshark/NS-2 views |
| `hospital` | `hospital123` | `hospital` | Hospital Inbox + Manual ACK + Network/Wireshark/NS-2 views |
| `citizen` | `citizen123` | `citizen` | Create SOS alerts only + Citizen UDP Inbox + Network/Wireshark/NS-2 views |

### Account Registration (`POST /api/auth/register`)
- **Citizen self-registration:** Available on the login screen (**Register (Citizen)** tab) or via `POST /api/auth/register`; role is always forced to `citizen`.
- **Responder account creation:** Only `admin` may create `police`, `ambulance`, `fire`, or `hospital` accounts via `POST /api/auth/register` (with admin Bearer token) or the **Create Responder Account** panel in the ECC Console.
- Validation: username `3–30` alphanumeric/underscore characters (`^[A-Za-z0-9_]{3,30}$`), unique username (`409` on duplicate), password minimum 8 characters.

---

## 3. Course Outcome (CO) Mapping

| Course Outcome | Concept | Where Implemented |
|---|---|---|
| **CO2** | Application-layer protocol design (own binary-framed protocol over sockets) | `backend/protocol.py` (`EMRG` 20-byte header + JSON payload), `backend/servers/{tcp,udp,tls}_server.py`, `wireshark/emrg.lua` |
| **CO3** | Transport layer: TCP vs UDP, retransmission/timers, flow & congestion behavior, performance evaluation | `backend/servers/tcp_server.py` (ACK/RTT + exponential backoff retries), `backend/servers/udp_server.py` (connectionless broadcast + sequence-gap loss), `backend/pqueue.py` (priority + anti-starvation aging), `backend/link_emulator.py` (DropTail + token bucket), `backend/metrics.py`, `ns2/emergency.tcl` (TCP Reno `cwnd_` vs UDP CBR) |
| **CO4** | Routing: Shortest Path (Dijkstra) AND Distance Vector (Bellman-Ford), comparison & link failure | `backend/routing.py` (`dijkstra` & `distance_vector` returning identical costs + convergence rounds), `backend/dispatcher.py` (`REROUTED` alternate paths), `ns2/emergency.tcl` (`rtproto DV` + `rtmodel-at` down/up) |
| **CO5** | CRC error detection, IP addressing/ports | `backend/protocol.py` (`zlib.crc32` over zeroed-CRC header + payload; `IntegrityError` on mismatch), `backend/db.py` & `backend/routing.py` (3-subnet `/24` IPv4 addressing plan + hop-by-hop IPs), `backend/config.py` (ports `9001`, `9002`, `9003`, `8000`), `wireshark/emrg.lua`, `backend/pcap_reader.py` |

### CO5 IPv4 Addressing & Subnet Plan

| Node ID | Role / Type | Subnet CIDR | IPv4 Address | Subnet Mask | Default Gateway |
|---|---|---|---|---|---|
| `ECC_HQ` | Core Control (`admin`) | `10.0.0.0/24` | `10.0.0.10` | `255.255.255.0` | `10.0.0.1` |
| `TOWER_NORTH` | Relay Tower | `10.0.1.0/24` | `10.0.1.11` | `255.255.255.0` | `10.0.1.1` |
| `TOWER_SOUTH` | Relay Tower (`citizen` sector) | `10.0.1.0/24` | `10.0.1.12` | `255.255.255.0` | `10.0.1.1` |
| `SUBSTATION_A` | Relay Substation | `10.0.1.0/24` | `10.0.1.13` | `255.255.255.0` | `10.0.1.1` |
| `POLICE` | Responder (`police`) | `10.0.2.0/24` | `10.0.2.21` | `255.255.255.0` | `10.0.2.1` |
| `FIRE` | Responder (`fire`) | `10.0.2.0/24` | `10.0.2.22` | `255.255.255.0` | `10.0.2.1` |
| `AMBULANCE` | Responder (`ambulance`) | `10.0.2.0/24` | `10.0.2.23` | `255.255.255.0` | `10.0.2.1` |
| `HOSPITAL` | Responder (`hospital`) | `10.0.2.0/24` | `10.0.2.24` | `255.255.255.0` | `10.0.2.1` |

---

## 4. Real vs. Emulated Components

| Component | Status | Implementation Detail |
|---|---|---|
| TCP / UDP / TLS Sockets & Framing | **REAL** | OS loopback sockets (`127.0.0.1:9001-9003`), separate OS client processes, real TLS 1.2+/1.3 X.509 handshake |
| RTT, Throughput, ACK Rate, Loss | **REAL (Measured)** | Computed directly from `time.monotonic()` send-to-ACK timestamps, sliding 10s byte window, ACK timeouts, and UDP sequence gaps |
| Authentication & RBAC | **REAL** | 200k-round PBKDF2-HMAC-SHA256, HMAC-SHA256 tokens with expiry, enforced on every REST, WebSocket, and socket `REGISTER` |
| CRC-32 Frame Validation | **REAL** | IEEE 802.3 CRC-32 computed and verified on every frame |
| Per-Hop Delay, Bandwidth, DropTail Queues | **EMULATED (`"emulated link"`)** | `backend/link_emulator.py` applies configured propagation delay, token-bucket rate limiting, and finite DropTail queues across the 8-node graph so congestion & queue overflows occur deterministically |
| Packet Capture & Network Simulation | **REAL TOOLS ONLY** | Real Wireshark + Npcap `.pcap/.pcapng` uploads and real NS-2 `.tr` traces from Ubuntu/WSL; zero synthetic trace or packet generation |

---

## 5. Wireshark Analysis (Windows Npcap Loopback)

1. Install Wireshark with **Npcap** (check *"Support loopback traffic capture"* during Npcap installation).
2. Load the custom dissector `wireshark/emrg.lua`:
   ```powershell
   wireshark -X lua_script:wireshark\emrg.lua
   ```
3. Start capture on **Adapter for loopback traffic capture (`Npcap Loopback Adapter`)**.
4. Apply display filter:
   ```text
   tcp.port==9001 || udp.port==9002 || tcp.port==9003
   ```
5. Dispatch TCP, UDP, and TLS alerts in ECAS, stop capture, save as `.pcap` or `.pcapng`, and upload it in the **Wireshark** tab to inspect decoded EMRG fields and raw hex dumps.
   *(Note: Live Windows socket captures use loopback IP `127.0.0.1` on ports `9001/9002/9003`, while the CO5 logical topology routes across `10.0.0.10` -> `10.0.1.x` -> `10.0.2.x` as shown on the Topology Canvas and `/api/routes`.)*

---

## 6. NS-2 Simulation in Ubuntu / WSL

Run inside Ubuntu / WSL in the project's `ns2/` directory:
```bash
cd ns2
bash run_ns2.sh
```
This runs `ns emergency.tcl low`, `ns emergency.tcl normal`, and `ns emergency.tcl heavy` using the **exact same 8-node topology, delays, bandwidths, and DropTail queue-limits** as the ECAS app (`ECC_HQ`, `TOWER_NORTH`, `TOWER_SOUTH`, `SUBSTATION_A`, `POLICE`, `FIRE`, `AMBULANCE`, `HOSPITAL`), with `rtproto DV`, link failure (`rtmodel-at 3.0 down` / `6.0 up`), TCP Reno (`fid_ 1`, `cwnd_` traced), and UDP CBR (`fid_ 2`).

Upload `real_trace_low.tr`, `real_trace_normal.tr`, and `real_trace_heavy.tr` in the **NS-2 Simulation** tab to view:
- Low / Normal / Heavy comparison table and bar chart
- TCP Reno vs UDP CBR packet loss, delay, and throughput
- `cwnd` congestion window plot
- Trace-event-driven replay animation

---

## 7. Synopsis Requirements Checklist

- **ECC creates classified alerts for Police, Ambulance, Fire, Hospital, Citizen:** `POST /api/alerts`, ECC Console & Citizen SOS tabs.
- **TCP reliable ACK/retry vs UDP fast connectionless broadcast:** `tcp_server.py` (timeout + exponential backoff + dedupe) vs `udp_server.py` (per-sender seq + gap loss reporting).
- **Priority queue (`Critical > High > Normal`):** `pqueue.py` min-heap with FIFO tie-breaking and anti-starvation aging.
- **Authentication + RBAC + TLS sockets:** `auth.py` + `tls_server.py` (`cryptography` X.509 cert; sensitive alerts restricted to TLS for Hospital/Police).
- **ACK, delivery tracking, logging:** `db.py` (`alerts`, `deliveries`, `network_logs` in SQLite WAL).
- **Routing with shortest path & link failure:** `routing.py` (Dijkstra + Bellman-Ford Distance Vector) + `dispatcher.py` (`WAITING_NETWORK` with `estimated_wait_sec`, redelivery worker, and `REROUTED` alternate paths).
- **Wireshark & NS-2 analysis:** `wireshark/emrg.lua`, `backend/pcap_reader.py`, `ns2/emergency.tcl`, `ns2/parse_trace.py`.

---

## 8. Live Demo Script & Tests

### Run Automated Tests & Load Test
```powershell
python -m pytest -v
python tests/load_test.py
```

### Live Acceptance Walkthrough
1. Start `python run_all.py` and open `http://127.0.0.1:8000` (verify login is required everywhere).
2. Sign in as `admin` (`admin123`) and dispatch multiple Normal alerts followed by a Critical alert -> observe Critical preempting Normal in deliveries.
3. Terminate one responder terminal/PID (e.g., `fire`), dispatch a Fire alert -> observe `WAITING_NETWORK` and `Waiting for network - est. ~Xs`; restart `python clients/responder.py --role fire` -> observe automatic redelivery and `ACKNOWLEDGED`.
4. In **Network & Routing**, click **Fail Link** on both `L_ECC_NORTH` and `L_ECC_SOUTH`, send an alert -> observe `WAITING_NETWORK` + estimated delay; restore one link -> observe `REROUTED` delivery over alternate path and `ACKNOWLEDGED`.
5. Upload a real Wireshark `.pcap`/`.pcapng` capture and real NS-2 `.tr` traces from WSL.

