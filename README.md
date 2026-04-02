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
| Bhojak Bhargav Hemen | CSE (AI & ML) |
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
| Training rows (post-SMOTE) | 7,849,692 |
| Test rows | 1,955,457 |
| Benign | 86.8% |
| Attack | 13.2% |

Attack types: DDoS (LOIC-HTTP, HOIC, LOIC-UDP), DoS (Hulk, GoldenEye, Slowloris, SlowHTTPTest), BruteForce (FTP, SSH, Web, XSS), SQL Injection, Infiltration, Bot

---

## Pipeline

### Cleaning
- Junk header rows removed (`Label == 'Label'`)
- Float infinity replaced with column mean
- 6.3M duplicate rows dropped (LOIC flood artifacts)
- Tuesday file (3.9GB) loaded in chunks to manage RAM

### Class Imbalance — Two-Tier SMOTE
Applied before training on multi-class labels, after train/test split:

| Tier | Condition | Target | k |
|---|---|---|---|
| Tier 1 | < 100 samples | 2,000 | 3 |
| Tier 2 | 100–5,000 samples | 5,000 | 5 |

Classes boosted:
```
FTP-BruteForce:      42  →  2,000  (Tier 1, k=3)
DoS-SlowHTTPTest:    44  →  2,000  (Tier 1, k=3)
SQL Injection:       64  →  2,000  (Tier 1, k=3)
Brute Force -XSS:   180  →  5,000  (Tier 2, k=5)
Brute Force -Web:   422  →  5,000  (Tier 2, k=5)
DDOS-LOIC-UDP:    1,384  →  5,000  (Tier 2, k=5)
```

### Scaling
RobustScaler fitted on training data only. Test set transformed only — no fit.

---

## Model

| Parameter | Value |
|---|---|
| Algorithm | XGBoost (XGBClassifier) |
| Trees | 300 |
| Max depth | 8 |
| Learning rate | 0.05 |
| Subsample | 0.8 |
| Colsample by tree | 0.8 |
| Min child weight | 3 |
| Imbalance handling | scale_pos_weight = 6.46 |
| Features | 25 flow-level features |

---

## Results

### Cross Validation (5-Fold Stratified)
| Fold | F1 |
|---|---|
| 1 | 0.9241 |
| 2 | 0.9247 |
| 3 | 0.9239 |
| 4 | 0.9238 |
| 5 | 0.9251 |
| **Mean** | **0.9243 ± 0.0005** |

### Test Set Performance
| Metric | Benign | Attack |
|---|---|---|
| Precision | 0.99 | 0.92 |
| Recall | 0.99 | 0.93 |
| F1 Score | 0.99 | 0.92 |

| | Value |
|---|---|
| Overall Accuracy | 0.98 |
| False Positive Rate | 1.27% |
| False Negative Rate | 7.18% |

### Miss Rate Per Attack Class
| Attack Type | Miss Rate |
|---|---|
| DDoS attacks-LOIC-HTTP | 7.5% |
| DDOS attack-HOIC | 6.9% |
| DoS attacks-Hulk | 7.0% |
| DoS attacks-GoldenEye | 6.8% |
| Bot | 7.5% |
| SSH-Bruteforce | 6.6% |
| DoS attacks-Slowloris | 6.3% |
| Infiltration | 6.8% |
| DDOS attack-LOIC-UDP | 7.0% |
| Brute Force -Web | 12.5% |
| Brute Force -XSS | 0.0%* |
| FTP-BruteForce | 0.0%* |
| SQL Injection | 0.0%* |
| DoS attacks-SlowHTTPTest | 0.0%* |

*Insufficient test samples for statistical significance (<5 samples)

---

## Artifacts

| File | Description |
|---|---|
| `artifacts/model.pkl` | Trained XGBClassifier (3.3 MB) |
| `artifacts/scaler.pkl` | RobustScaler fitted on training data only |
| `artifacts/explainer.pkl` | SHAP TreeExplainer bound to model (12.6 MB) |
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

All 25 features are computable from raw Scapy packet capture at runtime.

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

| Phase | Description | Status |
|---|---|---|
| Phase 0 | Offline ML training | ✅ Complete |
| Phase 1 | Packet capture + session tracking | 🔜 |
| Phase 2 | Feature extraction + ML inference | 🔜 |
| Phase 3 | SHAP explanation + alert builder | 🔜 |
| Phase 4 | CTI enrichment | 🔜 |
| Phase 5 | FastAPI + WebSocket + dashboard | 🔜 |