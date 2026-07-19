# 🛡️ VYUHA.AI
 **AI-Powered Endpoint Detection & Response (EDR) Platform with Attack Path Intelligence and AI-Assisted Remediation**

# Overview
VYUHA.AI is an AI-powered Endpoint Detection & Response (EDR) platform that transforms raw vulnerability scan data into actionable security intelligence.

Unlike traditional vulnerability scanners that simply list CVEs, VYUHA.AI correlates vulnerabilities into probable attack paths, prioritizes risks using real-world threat intelligence, and assists analysts through an AI-powered SOC Copilot while keeping humans in complete control of remediation.


# Features
- 🔍 Import vulnerability scans from **Nmap** and **OpenVAS**
- ⚠️ Automatic CVE enrichment using **NVD API**
- 🚨 CISA KEV exploitability detection
- 📊 Intelligent risk scoring
- 🗺️ Interactive Attack Path Visualization
- 🤖 AI Security Copilot
- 💻 Endpoint Monitoring Dashboard
- 📑 Human Approval Workflow
- 📄 Executive PDF & CSV Reports
- 🔔 Live Notifications
- 🔐 JWT Authentication & Role-Based Access Control


#  System Architecture

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


# 🛠️ Tech Stack
## Frontend

- React 18
- TypeScript
- Vite
- Tailwind CSS
- React Query
- React Flow
- Recharts
- Framer Motion

## Backend

- Node.js
- Fastify
- Supabase (PostgreSQL)
- JWT Authentication

## AI & Threat Intelligence

- Groq (Llama 3.3)
- ChromaDB
- NetworkX
- NVD API
- CISA KEV
- MITRE ATT&CK
- OpenVAS
- Nmap

---

# 📂 Project Structure
```text
## 📂 Project Structure
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

# 🚀 Installation
## Clone Repository

```bash
git clone https://github.com/Akshu121796/VYUHA-AI.git
cd VYUHA-AI
```

---
## Install Dependencies

```bash
npm install
```

---

## Configure Environment

Create a `.env` file.
```env
SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
GROQ_API_KEY=
NVD_API_KEY=
```

---
## Run the Project

```bash
npm run dev
```
This starts:
- ✅ Frontend
- ✅ Backend

---

# 📸 Application Modules

- Dashboard
- Findings
- Endpoints
- Attack Paths
- AI Copilot
- Approval Queue
- Reports
- Settings

---

# 🎯 Demo Workflow

1. Import Nmap/OpenVAS Scan
2. Parse and Normalize Findings
3. Enrich CVEs using NVD & CISA KEV
4. Calculate Risk Scores
5. Generate Attack Paths
6. Investigate Findings via AI Copilot
7. Approve Remediation
8. Export Executive Reports

---

# 🔐 Security Highlights
- Human-in-the-loop remediation
- Role-Based Access Control (RBAC)
- JWT Authentication
- Audit Logging
- Risk-based Prioritization
- Attack Path Correlation
- AI-assisted Investigation

---

# 🛣️ Future Roadmap

- SIEM Integration
- Compliance Mapping
- Multi-Tenant Deployment
- CI/CD Security Scanning
- Automated Threat Intelligence Feeds
- Malware Sandbox Integration
- Cloud Asset Discovery

---

# 👥 Team

| Name | Role |
|------|------|
| Akshata Chettiar | Full Stack Developer |
| Kaveesh Kadirvel | Frontend |
| Pavitra Boga | Backend |
| Paras Kumbhkar | AI/ML |

---

# 📄 License
This project is licensed under the **MIT License**.

---

<p align="center">

### 🛡️ *VYUHA.AI — Think Like an Attacker. Defend Like an Analyst.*

</p>
