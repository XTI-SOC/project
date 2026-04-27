# XTI-SOC: Advanced ML Network Detection & Response (NDR)

![XTI-SOC Banner](https://img.shields.io/badge/Security-SOC_Intelligence-blueviolet?style=for-the-badge&logo=shield)
![Status](https://img.shields.io/badge/Status-Production_Ready-success?style=for-the-badge)
![Python Version](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Next.js](https://img.shields.io/badge/Frontend-Next.js_15-black?style=for-the-badge&logo=next.js)

**XTI-SOC** is an enterprise-grade Network Detection and Response (NDR) platform. It combines kernel-level packet inspection, multi-layered machine learning, and temporal correlation to provide real-time visibility and defense against modern cyber threats. 

Unlike traditional signature-based IDS, XTI-SOC uses **Explainable AI (XAI)** to not only detect attacks but explain *why* they were flagged in plain English.

---

## 💎 Premium Features

### 🧠 Explainable Intelligence (XAI)
*   **Plain English SHAP Explanations**: No more cryptic bar charts. The system translates complex SHAP (Shapley Additive Explanations) correlation values into human-readable forensic insights.
*   **Rule-Based Forensics**: Dynamically generates logic-based explanations for Layer-2 and Temporal attacks, including live metrics like conflicting MAC addresses and port scan counts.

### 🛡️ Hybrid Detection Engine
*   **ML-Powered Inference**: High-precision XGBoost classifier trained on **NF-UNSW-NB15** and **CICIDS2018** datasets for detecting encrypted behavioral anomalies.
*   **Temporal Correlation**: A lock-free, sliding-window engine that tracks per-IP behavior over 60 seconds to detect multi-flow attacks (DDoS, Brute Force, Port Scans).
*   **Layer-2 ARP Monitoring**: A dedicated Scapy-powered sniffer detects MITM and ARP Poisoning attacks that are invisible to standard IP-layer monitors.

### 🌐 Real-Time Cyber-Dashboard
*   **Live Event Streaming**: High-speed WebSockets stream alerts from the kernel capture directly to the browser in milliseconds.
*   **Dynamic Threat Mapping**: An interactive global map that visualizes attack origins based on IP-reputation intelligence.
*   **Secure API Integration**: Protected by mandatory X-API-Key authentication and granular Rate Limiting to prevent SOC-side DoS.

---

## 🏗️ System Architecture

### 1. The Processing Pipeline
1.  **Ingestion**: `NFStreamEngine` performs kernel-level capture via Npcap/Libpcap.
2.  **L2 Monitoring**: `ARPMonitor` tracks hardware-address conflicts asynchronously.
3.  **Filtration**: Local traffic and authorized protocols are whitelisted to ensure 0% CPU waste on known-safe data.
4.  **Inference**: `ML_Engine` performs feature scaling and XGBoost classification.
5.  **Correlation**: `CorrelationEngine` analyzes temporal patterns against thresholds in `config.yaml`.
6.  **Enrichment**: `CTI_Cache` queries AbuseIPDB for global reputation data.
7.  **Alerting**: Validated threats are stored in SQLite and broadcasted via WebSockets.

### 2. Security Infrastructure
*   **Startup Guard**: The system refuses to boot if the `XTI_SOC_API_KEY` is missing from the environment.
*   **Adaptive Rate Limiting**: Powered by `SlowAPI`, using raw client IP tracking to prevent proxy-spoofing during dashboard access.
*   **Encapsulated Logic**: Models, scalers, and explainers are version-checked during unpickling to prevent environment mismatch.

---

## 🛠️ Setup & Installation

### Prerequisites
*   **OS**: Windows 10/11 (with Npcap installed) or Linux (with Libpcap).
*   **Python**: v3.10 or higher.
*   **Node.js**: v18.0 or higher.

### Installation
```bash
# Clone and enter the project
git clone https://github.com/XTI-SOC/project.git
cd project

# Environment Setup
python -m venv venv
source venv/Scripts/activate # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure Secrets
# Create a .env file in the root directory:
XTI_SOC_API_KEY=your_secure_backend_key
ABUSEIPDB_KEY=your_abuseipdb_api_key

# Dashboard Setup
cd dashboard
npm install
```

---

## 🚦 Running the SOC

### 1. Start the Engine & API
Launch the capture engine and the FastAPI backend simultaneously:
```bash
python -m online.main
```
*Select your network interface when prompted. The engine will automatically initialize the database and security guards.*

### 2. Start the Dashboard
In a new terminal, launch the Next.js frontend:
```bash
cd dashboard
npm run dev
```
Access the dashboard at `http://localhost:3000`.

---

## 📂 Project Roadmap
- [x] **Phase 1**: Real-time NFStream Integration.
- [x] **Phase 2**: XGBoost Inference & Feature Scaling.
- [x] **Phase 3**: Temporal Correlation & CTI Enrichment.
- [x] **Phase 4**: Explainable AI (XAI) Dashboard Integration.
- [ ] **Phase 5**: Automated Mitigation (Active Firewall Blocking).
- [ ] **Phase 6**: SIEM Export (Syslog/ELK Integration).

---
*Developed by the XTI-SOC Engineering Team. Protecting networks with Explainable AI.*
