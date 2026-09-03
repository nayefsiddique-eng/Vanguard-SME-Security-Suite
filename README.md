<div align="center">

# 🛡️ Vanguard SME Security Suite

**A unified cybersecurity scanning, posture-monitoring, and explainable Machine Learning threat detection platform for small and medium businesses**

[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=flat&logo=next.js&logoColor=white)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9-F7931E?style=flat&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

*Demonstration project for technical and hackathon evaluation*

[Overview](#project-overview) • [ML Architecture](#machine-learning-architecture) • [Features](#key-features) • [Getting Started](#getting-started) • [Judge Evaluation Demo](#judge-evaluation-walkthrough)

</div>

---

## Project Overview

Small and medium businesses are frequent targets of phishing, malware, network intrusion, and payment fraud, but rarely have the budget or staffing for a dedicated security operations team.

**Vanguard SME Security Suite** consolidates five critical attack-surface checks — file/malware, malicious URLs, network exposure, phishing email, and UPI payment fraud — into a single authenticated dashboard. It pairs **deterministic security rules** with **three explainable Machine Learning models**, correlating results into an overall security posture score and auto-escalating findings into incidents mapped to the **MITRE ATT&CK** framework.

---

## Machine Learning Architecture

```
                       ┌─────────────────────────┐
                       │       User Input        │
                       │ (Email / UPI / Network) │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │    Security Scanner     │
                       │ (Headers / Nmap / PSP)  │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   Feature Extraction    │
                       │(Numeric vector + bounds)│
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │        ML Model         │
                       │  (RF / GB / IsoForest)  │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │ Prediction & Explain    │
                       │(Probas, Scores, Signals)│
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │     FastAPI Endpoint    │
                       │ (/api/scan/* & /api/ml) │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   Next.js ResultCard    │
                       │   (🧠 ML Analysis UI)   │
                       └─────────────────────────┘
```

### The Three Models

| Vector | Algorithm | Task | Score Type | Explainability Mechanism |
|---|---|---|---|---|
| **Email Phishing** | `RandomForestClassifier` | `phishing_detection` | Probability (0–100%) | Genuine tree-split `feature_importances_` |
| **UPI Fraud** | `GradientBoostingClassifier` | `upi_fraud_detection` | Probability (0–100%) | Genuine boosted `feature_importances_` |
| **Network Anomaly** | `IsolationForest` | `network_anomaly_detection` | Anomaly Score (0–100%) | Ranked **Contributing Signals / Risk Indicators** |

> [!IMPORTANT]
> **Dataset Methodology & Honest Scoping:**  
> The current prototype models are trained on a controlled, reproducible **Synthetic Prototype Dataset** for pipeline validation, demonstration stability, and explainability verification. Production deployment requires ongoing validation and retraining using curated real-world telemetry. The backend tracks dataset metadata and records full train/test evaluation metrics (Accuracy, Precision, Recall, F1-score, and False Positive Rate) retrievable via `GET /api/ml/model-info`.

---

## Key Features

### 1. Detection Engines
* **Email Phishing Analyzer**: Heuristic parser for SPF, DKIM, DMARC, and lookalike domains paired with a **Random Forest** classifier.
* **UPI Payment Fraud Verifier**: Handle syntax validation, brand keyword detection, and entropy scoring paired with a **Gradient Boosting** fraud scorer.
* **Network Exposure Scanner**: Port scanning via Nmap (with safe socket-level fallback) paired with an **Isolation Forest** anomaly detector.
* **Malware & File Scanner**: Scans binary files for known malware signatures with ClamAV.
* **URL Reputation Scanner**: Cross-references links against threat intelligence feeds via VirusTotal.

### 2. Explainable UX (ResultCard)
The application strictly separates **Security Rule Analysis** from **ML Analysis**:
* Displays explicit confidence probabilities for supervised classifiers and **Anomaly Scores** for Isolation Forest.
* Displays genuine feature importances for tree models and ranked active risk indicators for unsupervised anomaly detection (never fabricated weights).
* Built-in interactive AI assistant to explain technical terms to non-technical SME owners.

### 3. Posture Trend & Incident Correlation
* **Rolling Posture Score**: Aggregated dynamic rating across all scan history.
* **MITRE ATT&CK Mapping**: High-severity incidents are auto-correlated and tagged with authentic tactic and technique IDs.
* **Live Dashboard Intelligence**: Tracks Total Scans, Threats Found, Clean Scans, and ML-evaluated inspections in real time.

---

## Getting Started

### Prerequisites
* Python 3.12+
* Node.js 18+

### 1. Backend Setup

```bash
cd backend
# Create environment
py -3.12 -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start backend server (trains/loads ML models on startup)
uvicorn app.main:app --reload --port 8000
```
Backend Swagger API Docs: `http://localhost:8000/docs`

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Frontend Web Dashboard: `http://localhost:3000`

---

## Judge Evaluation Walkthrough

The suite includes pre-configured, deterministic demonstration test cases on every page for immediate hackathon judging:

### 1. Phishing Detection Demo (`/phishing`)
* Navigate to **Phishing Analyser** → switch to **Email Header Analyser**.
* Click **"⚡ Load Phishing Demo Sample"** and click **Analyze Headers**.
* **Expected Result**: Rule analysis flags SPF/DKIM failures and Paytm brand impersonation. The **🧠 ML Analysis** panel expands to reveal the **Random Forest** prediction (`PHISHING`), confidence score, and feature importances.

### 2. UPI Fraud Detection Demo (`/upi`)
* Navigate to **UPI Payment Verifier**.
* Click **"⚡ Load Fraud Demo"** (loads `fake-kyc-refund99283@paytm`) and click **Verify Payment**.
* **Expected Result**: The **Gradient Boosting** scorer classifies the handle as high risk with detailed lexical and entropy signal contributions.

### 3. Network Anomaly Detection Demo (`/ransomware`)
* Scroll down to **Network Vulnerability Check**.
* Click **"⚡ Load Anomalous Host Demo"** and click **Quick Scan**.
* **Expected Result**: Nmap identifies exposed critical services (Ports 23, 445, 3389, 3306). The **Isolation Forest** model reports an **Anomaly Score: ~75%** with active **Contributing Signals** (Telnet, SMB, RDP, MySQL).

### 4. Direct ML Predictor Dashboard (`/ml-predictor`)
* Navigate to **ML Threat Predictor** in the sidebar.
* Switch between Email Phishing, UPI Fraud, and Network Anomaly tabs to test custom feature values or click one-click demo presets.

---

## Automated Test Verification

Run the comprehensive test suite verifying authentication, ML model metadata, scanner pipelines, and input validation:

```powershell
py -3.12 -m pytest backend/test_main.py -v
```
All 10 integration tests run end-to-end against the live FastAPI application and scikit-learn models.

---

## Authors

* **Mohammed Nayef Siddique** (Chair, IEEE Computer Society Student Branch | [GitHub](https://github.com/nayefsiddique-eng))
* **Noor Laiba Maheen**
* **Sobiya Ayaz**
* **Nadira Fatima Sireen Sultana**
* **Mohammed Ameen Ul Haq**
