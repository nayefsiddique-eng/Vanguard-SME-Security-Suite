# Vanguard SME Security Suite

Vanguard SME Security Suite is a unified, multi-vector cybersecurity scanning and rolling posture assessment platform designed specifically for Small and Medium Enterprises (SMEs). It protects businesses by scanning and analyzing multiple threat vectors, generating automated rolling posture scores, and surfacing explainable AI security insights in simple terms.

## Repository Organization

This is a unified single-repository containing both frontend and backend modules:

- **[`/backend`](./backend)**: FastAPI application providing secure endpoints, rate limiting, and integrations for ClamAV, Nmap, VirusTotal, and custom threat rules.
- **[`/frontend`](./frontend)**: Next.js (App Router) React application displaying the security dashboard, rolling security posture charts, and interactive scanning tools.

---

## How to Run Both Services

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

---

### Step 1: Running the Backend API

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and configure your environment variables:
   ```bash
   cp .env.example .env
   ```
   *(Ensure to configure appropriate keys/database paths inside `.env`)*
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload
   ```
   The backend API will run at [http://localhost:8000](http://localhost:8000).

---

### Step 2: Running the Frontend Dashboard

1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```
2. Create and configure your environment variables:
   ```bash
   cp .env.example .env.local
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   The dashboard app will run at [http://localhost:3000](http://localhost:3000).
