# XTI-SOC — ML Model (Phase 0)

> Part of the **XTI-SOC: Explainable and Threat-Intelligence Driven Security Operations Framework**  
> VI Semester Mini Project | CIP67 / CYP67 | CSE (AI & ML) and CSE (Cyber Security)

---

## Overview

This repository contains the offline training pipeline for XTI-SOC. It trains an XGBoost binary classifier on the CSE-CIC-IDS2018 dataset and produces four serialized artifacts used by the live detection pipeline.

---

## Team

| Name | Department |
|---|---|
| Bhojak Bhargav Hemen | CSE (Cyber Security) |
| Bhuvan Agarwal | CSE (AI & ML) |
| Khushi Nawal | CSE (AI & ML) |
| Naman Jain | CSE (Cyber Security) |

**Guide:** Dr. Sajini G, Assistant Professor

---

## Dataset

**CSE-CIC-IDS2018** — Canadian Institute for Cybersecurity  
10 CSV files, ~6.4GB, generated using CICFlowMeter

| Stat | Value |
|---|---|
| Raw rows loaded | 16,232,943 |
| After cleaning | 9,777,285 |
| Training rows | 7,821,828 |
| Test rows | 1,955,457 |
| Benign | 86.8% |
| Attack | 13.2% |

Attack types: DDoS (LOIC-HTTP, HOIC, LOIC-UDP), DoS (Hulk, GoldenEye, Slowloris, SlowHTTPTest), BruteForce (FTP, SSH, Web, XSS), SQL Injection, Infiltration, Bot

---

## Model

| Parameter | Value |
|---|---|
| Algorithm | XGBoost (XGBClassifier) |
| Trees | 300 |
| Max depth | 8 |
| Learning rate | 0.05 |
| Imbalance handling | scale_pos_weight = 6.58 |
| Features | 25 flow-level features |

---

## Results

| Metric | Benign | Attack |
|---|---|---|
| Precision | 0.99 | 0.92 |
| Recall | 0.99 | 0.93 |
| F1 Score | 0.99 | 0.93 |

| | Value |
|---|---|
| Overall Accuracy | 0.98 |
| False Positive Rate | 1.18% |
| False Negative Rate | 7.23% |
| Primary weakness | Infiltration — 84.1% miss rate |

Infiltration attacks are designed to mimic benign traffic at the flow-feature level. Detection requires behavioral baselining or deep packet inspection beyond the scope of this framework.

---

## Artifacts

| File | Description |
|---|---|
| `artifacts/model.pkl` | Trained XGBClassifier |
| `artifacts/scaler.pkl` | StandardScaler fitted on training data only |
| `artifacts/explainer.pkl` | SHAP TreeExplainer bound to model |
| `artifacts/feature_list.pkl` | Ordered list of 25 feature names |

These four files are loaded at startup by the online runtime pipeline.

---

## Features

```
Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts,
Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Bwd Pkt Len Max,
Bwd Pkt Len Min, Bwd Pkt Len Mean, Flow Byts/s, Flow Pkts/s, Flow IAT Mean,
Fwd IAT Mean, Bwd IAT Mean, Fwd PSH Flags, FIN Flag Cnt, SYN Flag Cnt,
RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt, Down/Up Ratio,
Fwd Seg Size Avg, Bwd Seg Size Avg
```

---

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Place CSE-CIC-IDS2018 CSV files in `D:\CSE-CICIDS2018\` then run `offline/train.ipynb` top to bottom.

---

## Part of XTI-SOC

This repository is Phase 0 of the full XTI-SOC framework:

| Phase | Description | Repo |
|---|---|---|
| Phase 0 | Offline ML training | `ml_model` ← you are here |
| Phase 1 | Packet capture + session tracking | `online` |
| Phase 2 | Feature extraction + ML inference | `online` |
| Phase 3 | SHAP explanation + alert builder | `online` |
| Phase 4 | CTI enrichment | `online` |
| Phase 5 | FastAPI + WebSocket + dashboard | `online` |
