# XTI-SOC — Extended Threat Intelligence Security Operations Center

> **A real-time network intrusion detection system combining Machine Learning, Temporal Correlation, Layer 2 ARP monitoring, and live Cyber Threat Intelligence enrichment — all surfaced through a professional SOC-grade dashboard.**

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [Dashboard Pages](#dashboard-pages)
- [Detection Capabilities](#detection-capabilities)
- [Alert Classification](#alert-classification)
- [Tuning Detection Rules](#tuning-detection-rules)
- [Testing Scenarios](#testing-scenarios)
- [Notes](#notes)

---

## Overview

XTI-SOC is a research-grade, end-to-end network security monitoring platform built for academic and lab demonstration purposes. It passively captures live network traffic, extracts flow-level features, classifies threats using pre-trained ML models, correlates multi-flow attack patterns, and enriches flagged IPs with global threat intelligence — pushing every alert to a live web dashboard in real time via WebSocket.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CAPTURE LAYER                               │
│   NFStream (Flow Export)          Scapy (ARP Layer 2 Monitor)       │
└────────────┬──────────────────────────────────┬────────────────────┘
             │                                  │
             ▼                                  ▼
┌─────────────────────────┐       ┌─────────────────────────────┐
│  ML ENGINE              │       │  ARP MONITOR                │
│  • Binary XGBoost       │       │  • IP-MAC table tracking    │
│  • Multiclass XGBoost   │       │  • Spoofing detection       │
│  • SHAP Explainability  │       │  • Instant L2 alerts        │
└────────────┬────────────┘       └──────────────┬──────────────┘
             │                                   │
             ▼                                   │
┌─────────────────────────┐                      │
│  CORRELATION ENGINE     │                      │
│  • Port Scan detection  │                      │
│  • SYN Stealth Scan     │◄─────────────────────┘
│  • SSH/FTP Brute Force  │
│  • Volumetric Flood     │
│  • DNS Flood            │
│  • 60s rolling window   │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  CTI ENRICHMENT         │
│  • AbuseIPDB v2 API     │
│  • In-memory cache (1h) │
│  • Private IP bypass    │
│  • Risk score blending  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐        ┌──────────────────────────┐
│  ALERT STORE (SQLite)   │        │  FASTAPI + WEBSOCKET     │
│  • WAL journal mode     │◄──────►│  • Real-time WS push     │
│  • Indexed by risk/time │        │  • REST API (rate-limited)│
└─────────────────────────┘        └──────────────┬───────────┘
                                                   │
                                                   ▼
                                   ┌──────────────────────────┐
                                   │  NEXT.JS DASHBOARD       │
                                   │  • Live Alert Feed       │
                                   │  • Global Threat Map     │
                                   │  • SHAP Visualizations   │
                                   │  • CTI Reputation Cards  │
                                   └──────────────────────────┘
```

---

## Features

### 🧠 Machine Learning Engine
- **Binary Classifier** — XGBoost model trained on CICIDS-2017 dataset classifies every network flow as `BENIGN` or `MALICIOUS` (75% probability threshold).
- **Multiclass Classifier** — A second XGBoost model identifies the specific attack category: `DoS`, `DDoS`, `BruteForce`, `WebAttack`, `Infiltration`, `Botnet`, or `UNKNOWN_ANOMALY`.
- **SHAP Explainability** — Every malicious flow verdict is backed by a SHAP feature importance chart showing the top 5 contributing features (e.g., flow duration, packet rate, byte ratios).

### 🔗 Temporal Correlation Engine
- Maintains a **60-second rolling window** of flows per source IP.
- Detects cross-flow attack patterns that single-flow ML cannot catch:
  - **Port Scan** — > 50 distinct destination ports in 60s
  - **SYN Stealth Scan** — > 30 half-open TCP connections
  - **SSH/FTP Brute Force** — > 100 rapid auth attempts to port 21/22
  - **Volumetric Flood** — > 1000 flows in 60s
  - **DNS Flooding** — > 100 DNS queries in 60s
- **60-second alert cooldown** per IP per attack type to prevent alert storms.

### 🔍 Layer 2 ARP Monitor
- Runs a dedicated Scapy sniffer thread, independent of NFStream.
- Maintains a live IP → MAC binding table.
- Instantly detects **ARP Spoofing / Man-in-the-Middle** when an IP changes its MAC address.

### 🌐 Cyber Threat Intelligence (CTI)
- Enriches every alert with live **AbuseIPDB** reputation data.
- Returns: abuse confidence score (0–100), country code, total historical reports.
- **Blended risk scoring** — Final risk score = `(ML probability × 70%) + (CTI score × 30%)` for `ML+CTI` alerts.
- **1-hour in-memory cache** per IP — saves API quota.
- **Private IP bypass** — RFC-1918 / loopback IPs skip the API entirely.

### 📡 Real-Time Dashboard (WebSocket)
- Alerts are pushed **instantly** to the browser via WebSocket — no page refresh needed.
- **Auto-reconnect** — Dashboard reconnects automatically if the backend restarts.
- **Global Threat Map** — Animated pulsing dots for every geolocation-resolved threat.
- **Realtime Event Bus Log** — Scrolling terminal-style log of the last 6 events.

### 🔒 Secure API
- All REST endpoints and the WebSocket require an `X-API-Key` header.
- Rate-limited via `slowapi` (100 req/min for alerts, 60/min for stats).
- Security headers (`X-Frame-Options`, `X-Content-Type-Options`) on all responses.

---

## Project Structure

```
project/
├── online/                     # Live pipeline — the core detection engine
│   ├── main.py                 # Entry point: starts capture + API server
│   ├── nfstream_engine.py      # NFStream flow capture + ML inference
│   ├── ml_engine.py            # XGBoost model loader + predict + SHAP
│   ├── feature_extractor.py    # Extracts 25 features from NFStream flows
│   ├── correlation_engine.py   # Temporal multi-flow attack correlation
│   ├── arp_monitor.py          # Scapy Layer 2 ARP spoofing detection
│   ├── cti_cache.py            # AbuseIPDB enrichment + in-memory cache
│   ├── alert_store.py          # SQLite WAL persistence (alerts.db)
│   ├── alert_queue.py          # Thread-safe queue between capture & API
│   ├── interfaces.py           # Network interface discovery (Windows)
│   ├── session_store.py        # Flow session tracking
│   └── parser.py               # Flow parser utilities
│
├── api/
│   └── server.py               # FastAPI app: REST /alerts, /stats, /ws WebSocket
│
├── Offline2/                   # ML training pipeline (reference only)
│   ├── offline/                # Training notebooks and scripts
│   └── artifacts/              # Pre-trained model artifacts (used at runtime)
│       ├── model.pkl               # Binary XGBoost classifier
│       ├── scaler.pkl              # Binary RobustScaler
│       ├── explainer.pkl           # SHAP TreeExplainer
│       ├── feature_list.pkl        # List of 25 feature names
│       ├── model_multiclass.pkl    # Multiclass XGBoost classifier
│       ├── scaler_multiclass.pkl   # Multiclass RobustScaler
│       └── label_map.pkl           # Integer → attack label mapping
│
├── dashboard/                  # Next.js 16 SOC dashboard (frontend)
│   ├── app/
│   │   ├── page.tsx            # Main dashboard (live feed + map)
│   │   ├── incidents/          # Incidents management page
│   │   ├── forensics/          # Forensic alert deep-dive page
│   │   ├── log-stream/         # Raw event log stream page
│   │   ├── threat-intelligence/# CTI overview page
│   │   ├── reports/            # Reports summary page
│   │   └── asset-map/          # Network asset topology page
│   ├── components/
│   │   ├── AlertCard.tsx       # Individual alert card with SHAP + CTI
│   │   ├── AlertFeed.tsx       # Sortable live alert feed
│   │   ├── Header.tsx          # Top nav + WS status indicator
│   │   ├── Sidebar.tsx         # Left navigation sidebar
│   │   ├── StatsRow.tsx        # Stats bar (total, high, medium, low)
│   │   └── ShapChart.tsx       # SHAP feature bar chart component
│   └── lib/
│       └── api.ts              # API base URL, WS URL, fetch helpers, types
│
├── config.yaml                 # Tunable detection thresholds
├── requirements.txt            # Python dependencies
├── alerts.db                   # SQLite database (auto-created at runtime)
└── .env                        # API keys (not committed to git)
```

> **Note:** The `artifacts/` folder at project root and the `online/` legacy subdirectories are **not used** at runtime. All ML artifacts are loaded exclusively from `Offline2/artifacts/`.

---

## Prerequisites

### System Requirements
- **OS:** Windows 10/11 (64-bit) — required for NFStream + Npcap
- **Python:** 3.10 or 3.11 recommended (3.12+ may have SHAP compatibility issues)
- **Node.js:** 18.x or later
- **RAM:** 4GB+ recommended (ML models load ~25MB into memory)
- **Privileges:** Must run the Python backend **as Administrator** (required for raw packet capture)

### External Dependencies
- **[Npcap](https://npcap.com/#download)** — Windows packet capture driver. Install with *"WinPcap API-compatible mode"* checked.
- **[AbuseIPDB API Key](https://www.abuseipdb.com/register)** — Free account gives 1,000 API calls/day. Required for CTI enrichment. The system works without it but CTI cards will be empty.

---

## Installation

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd XTI-SOC/project
```

### 2. Install Npcap
Download and install Npcap from [npcap.com](https://npcap.com/#download).  
✅ Make sure to check **"Install Npcap in WinPcap API-compatible mode"** during installation.

### 3. Set Up the Database

**`alerts.db` is not included in the repository.** It is automatically created on the first backend run — you do not need to create it manually.

**SQLite is already included with Python** (it is part of the Python standard library). No separate installation or `pip install` is required.

The database file will appear at `project/alerts.db` the moment you run `python -m online.main` for the first time. It uses WAL (Write-Ahead Logging) mode for concurrent read/write performance.

> **Optional — SQLite Browser:** If you want to visually inspect the raw database tables, download [DB Browser for SQLite](https://sqlitebrowser.org/) (free, cross-platform). Open `alerts.db` with it and browse the `alerts` table directly.

To manually verify the database was created and contains data:
```bash
# From the project/ root (with venv activated)
python -c "import sqlite3; conn = sqlite3.connect('alerts.db'); print(conn.execute('SELECT COUNT(*) FROM alerts').fetchone()); conn.close()"
```

To **clear all alerts** between test sessions:
```bash
python -c "import sqlite3; conn = sqlite3.connect('alerts.db'); conn.execute('DELETE FROM alerts'); conn.commit(); conn.close(); print('Database cleared.')"
```

### 4. Set Up Python Environment
```bash
# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate

# Install all Python dependencies
pip install -r requirements.txt
```

### 5. Set Up the Dashboard
```bash
cd dashboard
npm install
cd ..
```

### 6. Configure Environment Variables
Create a `.env` file in the `project/` root (same level as `requirements.txt`):
```env
ABUSEIPDB_KEY=your_abuseipdb_api_key_here
XTI_SOC_API_KEY=your_chosen_secret_key_here
```

Also create `dashboard/.env.local` to connect the frontend to the backend:
```env
NEXT_PUBLIC_API_BASE=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_API_KEY=your_chosen_secret_key_here
```

> ⚠️ The `XTI_SOC_API_KEY` in `.env` and `NEXT_PUBLIC_API_KEY` in `dashboard/.env.local` **must match exactly**.

---

## Configuration

Detection thresholds can be tuned without touching any code by editing `config.yaml`:

```yaml
rules:
  port_scan_threshold: 50       # Distinct dst ports in 60s to trigger Port Scan
  brute_force_threshold: 100    # Flows to port 21/22 in 60s for Brute Force
  volumetric_threshold: 1000    # Total flows in 60s for Volumetric Flood
  dns_flood_threshold: 100      # DNS queries in 60s for DNS Flood
  half_open_threshold: 30       # SYN-only flows in 60s for SYN Stealth Scan
```

Changes take effect on the next backend restart.

---

## Running the System

> ⚠️ The Python backend **must be run as Administrator** for raw packet capture to work.

### Terminal 1 — Start the Backend (as Administrator)
```bash
# In project/ root, with venv activated
python -m online.main
```

You will be prompted to select a network interface. Press **Enter** for the default, or type the number of your Wi-Fi/LAN adapter.

```
Available network interfaces:
------------------------------------------------------------
  [0] WAN Miniport (Network Monitor)
  [4] MediaTek Wi-Fi 6E MT7922 160MHz Wireless LAN Card — default
  ...
------------------------------------------------------------
Select interface [0-8] (Enter = default):
```

On successful start:
```
✅ Capture started on \Device\NPF_{...}
🔌 API server: http://localhost:8000
📊 Dashboard:  http://localhost:3000
```

### Terminal 2 — Start the Dashboard
```bash
cd dashboard
npm run dev
```

Open **http://localhost:3000** in your browser.

### Clearing the Alert Database
To reset the database between test sessions:
```bash
python -c "import sqlite3; conn = sqlite3.connect('alerts.db'); conn.execute('DELETE FROM alerts'); conn.commit(); conn.close(); print('Database cleared.')"
```

---

## Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| **Live Feed** | `/` | Real-time alert stream with SHAP charts, CTI cards, and Global Threat Map |
| **Incidents** | `/incidents` | Alert management and triage view |
| **Forensics** | `/forensics` | Deep-dive forensic analysis of individual alerts |
| **Log Stream** | `/log-stream` | Raw event bus log viewer |
| **Threat Intelligence** | `/threat-intelligence` | CTI reputation overview |
| **Reports** | `/reports` | Summary statistics and export |
| **Asset Map** | `/asset-map` | Network asset topology visualization |

---

## Detection Capabilities

| Attack Type | Detection Method | Layer |
|-------------|-----------------|-------|
| DoS / DDoS | ML (XGBoost binary + multiclass) | L3/L4 |
| Port Scan (horizontal) | Correlation (distinct dst ports > 50/60s) | L3/L4 |
| SYN Stealth Scan | Correlation (half-open TCP > 30/60s) | L4 |
| SSH / FTP Brute Force | Correlation (auth flows to 21/22 > 100/60s) | L4 |
| Volumetric Flood | Correlation (flow count > 1000/60s) | L3/L4 |
| DNS Flooding | Correlation (DNS queries > 100/60s) | L7 |
| Web Attacks | ML (multiclass: WebAttack class) | L7 |
| Botnet C2 | ML (multiclass: Botnet class) | L3/L4 |
| Infiltration | ML (multiclass: Infiltration class) | L3/L4 |
| ARP Spoofing / MitM | ARP Monitor (MAC table flip detection) | L2 |
| Malicious Public IPs | CTI (AbuseIPDB reputation check) | Reputation |

---

## Alert Classification

Every alert is assigned one of four types:

| Type | Meaning | Confidence |
|------|---------|-----------|
| `ML+CTI` | ML flagged **and** AbuseIPDB score > 25 | **High** |
| `ML_ONLY` | ML flagged, target IP is private or clean reputation | **Medium** |
| `CTI_ONLY` | ML says benign, but AbuseIPDB score > 25 | **Low** |
| `CORRELATION` | Multi-flow pattern detected (Port Scan, Flood, etc.) | **Medium** |
| `ARP_ANOMALY` | MAC address table flip detected (Layer 2) | **High** |

**Risk Score Formula:**
- `ML+CTI` → `(ml_probability × 70) + (cti_score / 100 × 30)`, capped at 100
- `ML_ONLY` → `ml_probability × 100`
- `CORRELATION` → Fixed per rule (Port Scan: 80, Brute Force: 85, Flood: 90, DNS: 75) + CTI boost up to +15 if public spoofed IP is known malicious
- `ARP_ANOMALY` → Fixed at 85

---

## Tuning Detection Rules

The `config.yaml` thresholds are intentionally set for lab environments where traffic volume is low. For a busier production network, raise them:

```yaml
rules:
  port_scan_threshold: 150      # Higher for busy networks
  brute_force_threshold: 300
  volumetric_threshold: 5000
  dns_flood_threshold: 500
  half_open_threshold: 100
```

---

## Testing Scenarios

### Scenario 1 — Insider Threat (Same Wi-Fi / Hotspot)
Both machines on the same subnet. Tests ML and Correlation detection.

| Test | Tool (Kali Linux) | Expected Alert |
|------|--------------------|---------------|
| ARP Spoofing | `arpspoof -i eth0 -t <victim-ip> <gateway-ip>` | `ARP_ANOMALY` |
| Port Scan | `nmap -sS -p 1-65535 <victim-ip>` | `CORRELATION / Port Scan` |
| SYN Flood | `hping3 -S --flood -p 80 <victim-ip>` | `ML_ONLY / DDoS` |
| SSH Brute Force | `hydra -l root -P rockyou.txt ssh://<victim-ip>` | `CORRELATION / SSH Brute Force` |

### Scenario 2 — Simulated Public Attack (Ngrok)
Expose the victim machine via Ngrok to simulate an internet-facing attack. Tests CTI enrichment.

1. Run Ngrok on the victim: `ngrok tcp 22`
2. Attack the public Ngrok address from a separate network.
3. The Correlation Engine will detect the attack pattern, and the CTI engine will query AbuseIPDB for the attacker's real public IP.

### Scenario 3 — CTI Integration Test
Force the CTI pipeline to fire without needing a real public attacker:
- Temporarily set `_is_private_ip` in `online/cti_cache.py` to always return `False`.
- Run any attack. The system will query AbuseIPDB for the local IP (it will return no abuse data, but verifies the full pipeline).

---

## Notes

- **Windows Firewall** — Disable both Public and Private profiles during testing to prevent Windows from dropping incoming probe packets before NFStream can capture them. Re-enable after testing.
- **Outbound Traffic** — The system monitors **inbound and lateral traffic only**. Outbound flows are filtered to reduce noise and avoid self-flagging.
- **SHAP on Python 3.12+** — If the `explainer.pkl` fails to load, SHAP explanations will be silently disabled. Re-serialize the explainer using the same Python version as the training environment (`Offline2/`).
- **AbuseIPDB Quota** — Free tier allows 1,000 checks/day. The 1-hour in-memory cache ensures repeated attacks from the same IP only consume 1 API call per hour.
- **`alerts.db`** — Auto-created in the project root on first run. Uses SQLite WAL mode for concurrent read/write without locking.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
