# 🛡️ Vanguard SME Security Suite

**A unified cybersecurity scanning and posture-monitoring platform built for small businesses — personal portfolio project.**

![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat&logo=next.js&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)

---

## 📋 Table of Contents
- [What This Is](#what-this-is)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Screenshots](#screenshots)
- [Getting Started](#getting-started)
- [Known Limitations & Roadmap](#known-limitations--roadmap)
- [License](#license)

---

## What This Is

Vanguard SME Security Suite is a full-stack security platform that lets a small business owner run five different security checks — file/malware, URL, network, phishing email, and UPI payment fraud — from one dashboard, then automatically correlates the results into a running security posture score. Suspicious findings are auto-escalated into incidents mapped against real MITRE ATT&CK tactics/techniques, with plain-language explanations for every verdict.

---

## Features

**Detection Tools**
- 🦠 **File/Malware Scan** — ClamAV-based scanning of uploaded files
- 🔗 **URL Scanner** — VirusTotal-backed reputation and threat lookup
- 🌐 **Network Scanner** — Nmap-based port/service exposure scanning
- ✉️ **Email/Phishing Analyzer** — SPF/DKIM/DMARC validation, lookalike-domain and brand-impersonation detection
- 💳 **UPI Fraud Check** — Format/handle validation with fraud-pattern heuristics (ownership verification is out of scope — see Limitations)

**Security Posture & Correlation**
- 📈 Rolling **Security Posture Score** trend chart aggregating scan history over time
- 🔄 **IOC Correlation Engine** — automatically links related findings and escalates them into incidents
- 🎯 **MITRE ATT&CK Mapping** — every high-severity incident is tagged with a real tactic/technique (e.g. `Discovery → Network Service Discovery (T1046)`), verified working end-to-end against live scan data

**Explainability**
- 🔍 **Detection Signals Panel** — an expandable "how we know" breakdown for every verdict, showing the actual signals that triggered it instead of a black-box score

**Auth & Access**
- 🔐 JWT-based authentication
- 👥 Role-based access control (RBAC) with roles including SOC Analyst, Threat Hunter, and Admin

**Reporting**
- 📄 One-click **text incident report export** for any flagged incident

---

## Architecture

```mermaid
flowchart LR
    User[User Browser] --> FE[Next.js Frontend]
    FE -->|JWT Auth| API[FastAPI Backend]
    API --> Auth[Auth & RBAC]
    API --> Scan[Scan Services]
    Scan --> ClamAV[ClamAV]
    Scan --> VT[VirusTotal]
    Scan --> Nmap[Nmap]
    Scan --> Email[Email Analyzer]
    Scan --> UPI[UPI Checker]
    Scan --> Correlation[IOC Correlation Engine]
    Correlation --> MITRE[MITRE ATT&CK Mapper]
    Correlation --> DB[(PostgreSQL)]
    API --> Reports[Text Report Export]
```

---

## Tech Stack

| Frontend | Backend |
|---|---|
| Next.js (App Router) | FastAPI |
| React | SQLAlchemy |
| TypeScript | PostgreSQL |
| Tailwind CSS | JWT (python-jose) |
| Recharts | bcrypt |
| Lucide Icons | SlowAPI (rate limiting) |

---

## Screenshots

> 📸 Add real screenshots here before publishing — placeholders below.

![Dashboard](docs/screenshots/dashboard.png)
![Scan Result](docs/screenshots/scan-result.png)

---

## Getting Started

```bash
# Clone
git clone https://github.com/nayefsiddique-eng/vanguard-sme-suite.git
cd vanguard-sme-suite

# Install everything (frontend + backend deps)
npm run install:all

# Configure environment
cp backend/.env.example backend/.env
# Fill in DATABASE_URL, SECRET_KEY (generate with: python -c "import secrets; print(secrets.token_hex(32))")

# Run both services
npm run dev
```

Frontend: `http://localhost:3000` · Backend: `http://localhost:8000`

---

## Known Limitations & Roadmap

- **UPI verification is format-only** — validates handle structure, not actual PSP-side ownership
- **Reports export as plain text**, not PDF
- **No database migration tooling** — schema is managed via `create_all`, fine for portfolio scale, not production-ready
- **Audit logging** is modeled in the schema but not yet fully wired for all actions

---

## License

No license file yet — all rights reserved by default until one is added.
