# Vanguard SME Security Suite Frontend

Vanguard SME Security Suite is a unified, multi-vector cybersecurity platform designed specifically for Small and Medium Enterprises (SMEs). It protects businesses by scanning and analyzing multiple threat vectors, generating automated rolling posture scores, and surfacing explainable AI security insights in simple terms.

This repository contains the **frontend** web application, built with **Next.js (App Router)**, **React**, **TailwindCSS**, **Lucide Icons**, and **Recharts**.

> [!NOTE]
> This is the Next.js React frontend dashboard. The corresponding backend API service is available at [Vanguard SME Security Suite Backend](https://github.com/nayefsiddique-eng/vanguard-sme-backend).

## Key Features

1. **Unified Security Dashboard**: Real-time rolling security posture score trend lines mapped dynamically using **Recharts** from historical scans.
2. **Explainable AI Signals Panel**: Integrated within the `ResultCard` component, allowing users to expand and view technical indicators (SPF/DKIM statuses, open ports lists, or threat signatures) backing any verdict.
3. **Five Advanced Scanners**:
   - **URL Scan**: Check domain reputations and look-alike spoofing.
   - **Email Header Scan**: Deep SPF/DKIM verification.
   - **Malware Scanner**: File checks isolated with safe temp directories.
   - **Port Scanner**: Network vulnerability checks.
   - **UPI Verifier**: Syntactic check preventing payment handle spoofing.
4. **Session Expiry & Rate Limit Handling**: Automatic redirections on token expiration and formatted warnings on rate limit errors.

---

## Setup and Running

1. **Environment Config**: Create a `.env.local` file in the root directory:
   ```env
   NEXT_PUBLIC_API_URL=http://localhost:8000
   ```
2. **Install dependencies**:
   ```bash
   npm install
   ```
3. **Run local dev server**:
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) to view the application.

---

## Deployment

Build the optimized production bundle with:
```bash
npm run build
npm start
```

---

## Project Status & Limitations (Honesty Section)

- **Local Scanner Fallbacks**: Scans such as Network Open Ports are performed via real system execution where Nmap CLI is available. In environments without Nmap installed or when targets time out, the backend seamlessly falls back to a clean socket-based TCP port scanner to prevent failure.
- **Explainable Threat Logic**: The threat analysis report leverages deterministic indicators mapping (SPF alignment, ports count, domain age metrics) and aggregates evidence without relying on unpredictable external models, preventing hallucination bugs.
