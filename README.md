<div align="center">

# 🛡️ VYUHA.AI

**AI-Powered Endpoint Detection & Response (EDR) Platform**
*with Attack Path Intelligence and AI-Assisted Remediation*

[![Frontend](https://img.shields.io/badge/Frontend-React%2018-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Backend](https://img.shields.io/badge/Backend-Fastify-000000?logo=fastify)](https://fastify.dev/)
[![Database](https://img.shields.io/badge/Database-Supabase%20PostgreSQL-3ECF8E?logo=supabase)](https://supabase.com/)
[![AI](https://img.shields.io/badge/AI-Groq%20Llama%203.3-orange)](https://groq.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#-license)

</div>

---

## 📖 Overview

**VYUHA.AI** is an AI-powered Endpoint Detection & Response (EDR) platform that transforms raw vulnerability scan data into actionable security intelligence.

Unlike traditional vulnerability scanners that simply list CVEs, VYUHA.AI correlates vulnerabilities into **probable attack paths**, prioritizes risk using **real-world threat intelligence**, and assists analysts through an **AI-powered SOC Copilot** — while keeping humans in complete control of remediation.

---

## ✨ Features

| Category | Capability |
|---|---|
| 🔍 **Scan Ingestion** | Import vulnerability scans from **Nmap** and **OpenVAS** |
| 🧬 **CVE Enrichment** | Automatic enrichment using the **NVD API** |
| 🎯 **Exploit Intelligence** | **CISA KEV** exploitability detection |
| 📊 **Risk Scoring** | Intelligent, context-aware risk prioritization |
| 🕸️ **Attack Path Mapping** | Interactive attack path visualization |
| 🤖 **AI Copilot** | Conversational AI Security Copilot for investigation |
| 🖥️ **Monitoring** | Real-time endpoint monitoring dashboard |
| ✅ **Human-in-the-Loop** | Approval workflow for all remediation actions |
| 📄 **Reporting** | Executive PDF & CSV report generation |
| 🔔 **Alerts** | Live notifications |
| 🔐 **Access Control** | JWT authentication & Role-Based Access Control (RBAC) |

---

## 🏗️ System Architecture

```text
             Nmap / OpenVAS
                    │
                    ▼
      Detection & Risk Analysis
                    │
                    ▼
        Attack Path Correlation
                    │
                    ▼
          AI Security Copilot
                    │
                    ▼
       Approval & Remediation
                    │
                    ▼
 Dashboard • Reports • Notifications
```

---

## 🛠 Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18 · TypeScript · Vite · Tailwind CSS · React Query · React Flow · Recharts · Framer Motion |
| **Backend** | Node.js · Fastify · Supabase (PostgreSQL) · JWT Authentication |
| **AI & Threat Intelligence** | Groq (Llama 3.3 / `openai/gpt-oss-120b`) · ChromaDB · NetworkX · NVD API · CISA KEV · MITRE ATT&CK · OpenVAS · Nmap |

---

## 📂 Project Structure

```text
VYUHA-AI/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── layouts/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── types/
│   │   └── utils/
│   ├── public/
│   └── package.json
│
├── backend/
│   ├── src/
│   │   ├── routes/
│   │   ├── services/
│   │   ├── middleware/
│   │   ├── core/
│   │   ├── types/
│   │   └── utils/
│   ├── package.json
│   └── .env.example
│
├── integration/
│   ├── import_nmap.py
│   ├── import_openvas.py
│   ├── classifier.py
│   ├── fetch_cve_data.py
│   ├── sample_nmap.xml
│   ├── sample_openvas.xml
│   └── requirements.txt
│
├── package.json
├── README.md
└── .env.example
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Akshu121796/VYUHA-AI.git
cd VYUHA-AI
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment

Create a `.env` file:

```env
SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
GROQ_API_KEY=
NVD_API_KEY=
```

### 4. Run the Project

```bash
npm run dev
```

This starts:
- ✅ Frontend
- ✅ Backend

---

## 🧭 Application Modules

- Dashboard
- Findings
- Endpoints
- Attack Paths
- AI Copilot
- Approval Queue
- Reports
- Settings

---

## 🔄 Demo Workflow

1. Import Nmap / OpenVAS scan
2. Parse and normalize findings
3. Enrich CVEs using NVD & CISA KEV
4. Calculate risk scores
5. Generate attack paths
6. Investigate findings via AI Copilot
7. Approve remediation
8. Export executive reports

---

## 🔒 Security Highlights

- Human-in-the-loop remediation
- Role-Based Access Control (RBAC)
- JWT authentication
- Audit logging
- Risk-based prioritization
- Attack path correlation
- AI-assisted investigation

---

## 🗺️ Future Roadmap

- [ ] SIEM Integration
- [ ] Compliance Mapping
- [ ] Multi-Tenant Deployment
- [ ] CI/CD Security Scanning
- [ ] Automated Threat Intelligence Feeds
- [ ] Malware Sandbox Integration
- [ ] Cloud Asset Discovery

---

## 👥 Team

| Name | Role |
|---|---|
| Akshata Chettiar | Full Stack Developer |
| Kaveesh Kadirvel | Frontend |
| Pavitra Boga | Backend |
| Paras Kumbhkar | AI/ML |

---

## 🚀 Production Deployment

### Deployed Services

| Service | URL |
|---|---|
| **Frontend App** | https://vyuha-ai-virid.vercel.app |
| **Backend Service** | https://vyuha-backend.onrender.com |

### Backend Deployment (Render)

1. **New Web Service** — Connect your GitHub repository to a new Render web service.
2. **Environment** — Select `Node` environment.
3. **Build Command:**
   ```bash
   npm install && (pip3 install -r requirements.txt || pip install -r requirements.txt || echo "pip install skipped") && npm run build --prefix backend
   ```
4. **Start Command:**
   ```bash
   npm run start --prefix backend
   ```
5. **Environment Variables:**

   | Variable | Description |
   |---|---|
   | `PORT` | `8000` |
   | `SUPABASE_URL` | Your Supabase project URL |
   | `SUPABASE_SERVICE_ROLE_KEY` | Your Supabase service role key |
   | `SUPABASE_JWT_SECRET` | Your Supabase JWT secret |
   | `GROQ_API_KEY` | Your Groq API key |
   | `NVD_API_KEY` | *(Optional)* Your NVD developer API key |

### Frontend Deployment (Vercel)

1. **New Project** — Import the repository in Vercel.
2. **Root Directory** — Set to `frontend` (or build from root).
3. **Build Command** — `npm run build` (if root directory is `frontend`).
4. **Environment Variables:**

   | Variable | Description |
   |---|---|
   | `VITE_API_URL` | Your deployed Render backend URL (e.g. `https://vyuha-backend.onrender.com`) |

---

## 📜 License

This project is licensed under the **MIT License**.

---

<div align="center">

### 🛡️ *VYUHA.AI — Think Like an Attacker. Defend Like an Analyst.*

</div>
