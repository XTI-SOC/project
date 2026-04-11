# XTI-SOC: Advanced ML Network Intrusion Detection System

![XTI-SOC Shield](https://img.shields.io/badge/Security-SOC-blueviolet?style=for-the-badge&logo=shield)
![Python Version](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Framework](https://img.shields.io/badge/Engine-NFStream-orange?style=for-the-badge&logo=python)
![ML](https://img.shields.io/badge/ML-XGBoost-success?style=for-the-badge&logo=scikit-learn)

**XTI-SOC** is a high-performance, machine-learning-based Intrusion Detection System (IDS) designed for real-time traffic analysis and threat classification. It leverages kernel-level packet capture through NFStream and advanced binary classification via XGBoost to detect cyberattacks with high precision.

---

## 🚀 Key Features

*   **⚡ Kernel-Level Capture**: Powered by **NFStream v6.6.0**, providing non-blocking, multi-core flow processing on Windows via Npcap.
*   **🧠 Intelligence**: Integrated **XGBoost Classifier** trained on the CICIDS2018 dataset, capable of detecting DDoS, DoS, BruteForce, and Web Attacks.
*   **🛡️ Robust Preprocessing**: Uses a **RobustScaler** to mitigate the impact of network noise and outliers during inference.
*   **📊 Quality Filtering**: Intelligent micro-flow elimination (Threshold: ≥4 packets & ≥10ms duration) to reduce false positives from background noise.
*   **🕹️ Attack Simulator**: Custom-built testing suite to generate realistic attack patterns (SYN Floods, UDP Floods, Botnets, and Infiltration) on loopback.

---

## 🏗️ Technical Architecture

### 1. Data Pipeline
1.  **Ingestion**: `NFStreamEngine` performs live capture on the selected interface.
2.  **Flow Assembly**: Packets are grouped into bidirectional 5-tuple flows.
3.  **Feature Extraction**: NFStream's `statistical_analysis` computes 25 key network features (latencies, flag counts, byte ratios).
4.  **Transformation**: The `ml_engine` scales the features using `RobustScaler` artifacts.
5.  **Inference**: The model computes a malicious probability (`p`).
6.  **Alerting**: Detections are pushed to the `alert_queue` for real-time terminal display.

### 2. Supported Attack Detections
The system is optimized for the following CICIDS2018-aligned patterns:
*   **DDoS/DoS**: LOIC-HTTP, HOIC, Slowloris, Hulk, GoldenEye.
*   **Brute Force**: FTP, SSH, Web, XSS.
*   **Botnet**: Beaconing patterns and C2 communication.
*   **Infiltration**: Large data drops and lateral movements.

---

## 🛠️ Setup & Installation

### Prerequisites
*   **OS**: Windows 10/11 or Linux.
*   **Npcap**: Must be installed on Windows (ensure "WinPcap API compatibility" is checked).
*   **Python**: v3.10 or higher.

### Steps
```bash
# Clone the repository
git clone https://github.com/XTI-SOC/project.git
cd project

# Create virtual environment
python -m venv venv
source venv/Scripts/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🚦 Usage

### 1. Launch the SOC Pipeline
Run the main engine to start monitoring your network interfaces:
```bash
python -m online.main
```
*You will be prompted to select an interface. On Windows, use the index for your Wi-Fi/Ethernet card or the Loopback interface for testing.*

### 2. Generate Attack Traffic
In a separate terminal, use the simulator to verify detection capabilities:
```bash
python attack.py
```
*Select **[7] Full sequence** to run a stress test of all implemented attack types.*

---

## 📉 Quality Thresholds
To ensure high-fidelity alerts, XTI-SOC silences flows that do not meet the minimum "meaningful activity" threshold:
*   **Min Packets**: 4 (Ensures enough data for statistical analysis).
*   **Min Duration**: 10ms (Prevents infinity/NaN errors in byte-rate calculations).

---

## 📂 Project Structure
*   `online/`: The core real-time pipeline (Capture, ML Engine, Alerting).
*   `artifacts/`: Pickled ML models, scalers, and feature lists.
*   `scripts/`: Validation and diagnostic utilities.
*   `attack.py`: The localization-only attack simulation tool.

---
*Created by the XTI-SOC Development Team.*
