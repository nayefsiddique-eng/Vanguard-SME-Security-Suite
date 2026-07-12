# Vanguard SME Security Suite Backend

Vanguard SME Security Suite is a unified, multi-vector cybersecurity platform designed specifically for Small and Medium Enterprises (SMEs). It protects businesses by scanning and analyzing multiple threat vectors, generating automated rolling posture scores, and surfacing explainable AI security insights in simple terms.

> [!NOTE]
> This is the backend API service. The corresponding frontend React/Next.js dashboard web application is available at [Vanguard SME Security Suite Frontend](https://github.com/nayefsiddique-eng/vanguard-sme-frontend).

## Features

### Authentication & Security
- **JWT Authentication**: Full JSON Web Token authentication using HTTP Bearer headers to protect private routes.
- **Direct Cryptography (Direct Bcrypt)**: Custom-built password hashing and salt verification using standard `bcrypt` to prevent plaintext exposure.
- **Rate Limiting**: Custom limits (`5/minute`) on all scan endpoints to prevent abuse.
- **CORS Allowed Origins**: Strict origin checking parsed from the `ALLOWED_ORIGINS` environment variables.

### Multi-Vector Detection Scanner
- **URL Scanning**: Real URL reputation scanning integrating with VirusTotal.
- **Network Open Port Scans**: Custom scanner running `Nmap` with direct socket scanning failovers to check exposed services.
- **Email Spoofing Checker**: Complete SMTP header analysis verifying SPF, DKIM, DMARC alignment and look-alike domains.
- **Malware Scanner**: File checks integrating with ClamAV and safe temporary UUID isolation mechanisms.
- **UPI Fraud Detector**: Regex handle format checking and security keywords validation (capped at SUSPICIOUS to prevent spoofing).

### Tech Stack
- **FastAPI** (Fast Python API backend framework)
- **SQLite / PostgreSQL** (via SQLAlchemy ORM database logging)
- **JWT (python-jose)** and **Bcrypt** (Authentication)
- **SlowAPI** (Rate Limiter)

---

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/register` | Register a new profile | No |
| POST | `/login` | Authenticate credentials and return JWT | No |
| POST | `/api/scan/url` | Check link reputation | Yes |
| POST | `/api/scan/network` | Port-scan target host IP | Yes |
| POST | `/api/scan/email` | Verify spoofing checks on email headers | Yes |
| POST | `/api/scan/file` | Scan file for malware signatures | Yes |
| POST | `/api/scan/upi` | Check UPI payment handles for fraud markers | Yes |
| GET | `/scan-history` | Fetch logs of scanned entries | Yes |
| GET | `/dashboard-summary` | Aggregated threat stats for dashboard calculations | Yes |
| DELETE | `/scan-history/{id}` | Remove a scan record | Yes |

---

## Setup and Running

1. **Environment Config**: Create a `.env` file in the root based on `.env.example`:
   ```env
   DATABASE_URL=sqlite:///./cyber_risk_dashboard.db
   SECRET_KEY=insecure-default-dev-key-change-in-production
   ALLOWED_ORIGINS=http://localhost:3000
   VIRUSTOTAL_API_KEY=your_key_here
   AI_SERVICE_URL=http://localhost:5000/analyze
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Launch API**:
   ```bash
   uvicorn app.main:app --reload
   ```
