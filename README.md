<div align="center">
🛡️ VYUHA.AI
AI-Powered Endpoint Detection & Response Platform
Vulnerability and Yield-driven Unified Hardening Assistant

"Anticipate • Analyze • Fortify"

Show Image Show Image Show Image Show Image Show Image Show Image

<br/>
PS2 — AI-Powered Vulnerability Analysis and Attack Path Assistant

Built for Hackathon 2025 · Target: 15 July 2026

</div>
📌 One-Line Pitch
An AI-enhanced EDR with one clear innovation: Attack Path Intelligence — correlating detected vulnerabilities into likely attack chains, explained in plain language by an AI copilot, with a human always approving the final action.

What makes VYUHA.AI different from a generic vulnerability scanner: vulnerability scanning is a solved problem. What's missing is connecting isolated low and medium findings into the actual path an attacker would take, and explaining that chain in language a human can act on immediately. That correlation + explanation layer is our core differentiator.

🧩 Architecture
Data Sources
     │
     ▼
┌─────────────────────────────┐
│  Module 1 — Detection &     │  ← Nmap + OpenVAS + NVD + CISA KEV + OSV
│  Risk Analysis               │    CVE enrichment · CVSS scoring · KEV flagging
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  Module 2 — Attack Path     │  ← NetworkX graph · 2–3 hardcoded attack patterns
│  Analysis                   │    Weak credential → Lateral movement → Priv esc
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  Module 3 — AI Security     │  ← Groq LLaMA 3.3 70B · ChromaDB RAG
│  Copilot                    │    MITRE ATT&CK · CVE reference · Natural language
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  Module 4 — Response &      │  ← Human approval gate · Simulated fix · Re-scan
│  Remediation                │    Audit log · Escalation alerts
└─────────────────────────────┘
             │
             ▼
     Outputs: Dashboard · Reports · Notifications
Design Principles
Endpoint security only — not a generic do-everything scanner
AI for analysis and explanation only — never for silent, unapproved action
Real data sources only — NVD, CISA KEV, OSV, MITRE ATT&CK
Human always in the loop — single approval gate before any fix is applied
✨ Features
Core
Feature	Description
🔍 Vulnerability Detection	Ingests Nmap + OpenVAS scan output, normalises findings, matches CVEs via NVD API
⚠️ Risk Prioritisation	CVSS v3 score + CISA KEV exploitation status + asset criticality = risk score
🗺️ Attack Path Visualisation	Interactive graph (React Flow) showing how vulnerabilities chain into attack paths
🤖 AI Security Copilot	RAG-based chatbot — ask in natural language, get evidence-backed answers grounded in real CVE/MITRE data
✅ Human Approval Gate	No action taken without explicit admin approval — one gate, logged to audit trail
📊 SOC Dashboard	Real-time findings count, severity distribution, unacknowledged alert escalation
📄 Report Generation	One-click executive PDF with risk summary, top CVEs, attack path, remediation roadmap
Depth
Feature	Description
🚨 Escalation Timer	Critical findings unacknowledged past a time window auto-escalate via second channel
📋 Audit Log	Every action (scan, approval, fix applied, resolution) logged with timestamp and user
🔐 Role-Based Access	Two roles: Admin (approve fixes) · Analyst (view and query) — JWT-based auth
📈 Remediation Tracking	Full lifecycle: pending → approved → applied → resolved/failed
🛠️ Tech Stack
Frontend
Technology	Purpose
React 18 + Vite	Dashboard UI with fast HMR
Tailwind CSS	Utility-first styling — professional UI fast
React Flow	Interactive attack path graph with node drill-down
Recharts	Severity distribution charts, CVSS heatmaps
React Query (TanStack)	Smart caching + background sync for live dashboard
Backend
Technology	Purpose
Node.js + Express	REST API — CRUD, auth, approval workflow
Supabase (PostgreSQL)	Shared database — assets, findings, attack paths, approvals, audit log
JWT	Auth with two roles: Admin, Analyst
Realtime subscriptions	Live dashboard updates when new findings arrive
AI / ML
Technology	Purpose
Groq API (LLaMA 3.3 70B)	Fast inference for AI Copilot responses — free tier
ChromaDB	Local vector store for CVE + MITRE reference corpus
HuggingFace Sentence-Transformers	One-time offline embedding of reference documents
NetworkX (Python)	Attack path graph building + hardcoded pattern correlation
scikit-learn	Risk scoring pipeline
Threat Intelligence
Source	What it provides
NVD API (NIST)	CVSS v3 scores, CPE data, patch status — free, no key required
CISA KEV Catalog	Actively exploited CVEs in the wild — free JSON feed
OSV API	Open source dependency vulnerability scanning
MITRE ATT&CK	Technique and tactic labels for attack path nodes
Nmap	Network discovery and port scanning
OpenVAS / Greenbone	Comprehensive vulnerability scanning
Infrastructure
Technology	Purpose
Vercel	Frontend deployment — zero config
Railway / Render	Backend + ML service deployment — free tier
Cloudflare R2	PDF report storage
Docker	Containerised scanner environment
📁 Project Structure
VYUHA-AI/
│
├── frontend/                    # React dashboard
│   ├── src/
│   │   ├── components/          # UI components
│   │   │   ├── Dashboard/       # SOC dashboard, severity charts
│   │   │   ├── AttackGraph/     # React Flow graph visualisation
│   │   │   ├── Copilot/         # AI chatbot interface
│   │   │   ├── Findings/        # CVE findings table
│   │   │   ├── Approvals/       # Admin approval screen
│   │   │   └── Reports/         # PDF report trigger
│   │   ├── services/            # API service layer
│   │   ├── hooks/               # React Query hooks
│   │   └── pages/               # Route pages
│   ├── package.json
│   └── vite.config.ts
│
├── backend/                     # Node.js REST API
│   ├── src/
│   │   ├── routes/              # API endpoints
│   │   ├── middleware/          # Auth, RBAC, error handling
│   │   ├── services/            # Business logic
│   │   └── db/                  # Supabase client + queries
│   ├── package.json
│   └── .env.example
│
├── ml-service/                  # Python AI + attack path service
│   ├── rag/                     # RAG pipeline (embeddings + ChromaDB + Groq)
│   ├── attack_path/             # NetworkX graph + correlation rules
│   ├── classifier.py            # Risk scoring formula
│   ├── main.py                  # FastAPI entry point
│   └── requirements.txt
│
├── integration/                 # Data pipeline scripts
│   ├── fetch_cve_data.py        # NVD + CISA KEV fetcher
│   ├── import_nmap.py           # Nmap XML → Supabase importer
│   ├── scan_output.xml          # Real Nmap scan (Kali Linux)
│   ├── sample_nmap.xml          # Rich demo scan data
│   └── requirements.txt
│
├── .env.example                 # Environment variable template
├── .gitignore
└── README.md
⚙️ Setup & Installation
Prerequisites
Node.js 20+
Python 3.11+
A Supabase account (free tier)
A Groq API key (free tier)
An NVD API key (free, instant email)
1. Clone the repo
bash
git clone https://github.com/Akshu121796/VYUHA-AI.git
cd VYUHA-AI
2. Set up environment variables
bash
cp .env.example .env
# Fill in your actual values — see Environment Variables section below
3. Set up the database
Copy and run the schema SQL in your Supabase SQL Editor:

sql
create table assets (
  id uuid primary key default gen_random_uuid(),
  hostname text not null,
  ip_address text,
  os_type text,
  criticality text check (criticality in ('low', 'medium', 'high', 'critical')),
  created_at timestamp default now()
);

create table findings (
  id uuid primary key default gen_random_uuid(),
  asset_id uuid references assets(id),
  cve_id text,
  cvss_score decimal,
  severity text check (severity in ('low', 'medium', 'high', 'critical')),
  is_kev boolean default false,
  risk_score decimal default 0,
  description text,
  remediation text,
  status text default 'open' check (status in ('open', 'acknowledged', 'resolved')),
  detected_at timestamp default now()
);

create table attack_paths (
  id uuid primary key default gen_random_uuid(),
  scan_id text,
  path_nodes jsonb,
  entry_point text,
  target_asset text,
  risk_score decimal,
  tactic_chain text[],
  created_at timestamp default now()
);

create table approvals (
  id uuid primary key default gen_random_uuid(),
  finding_id uuid references findings(id),
  recommended_fix text,
  status text default 'pending'
    check (status in ('pending','approved','rejected','applied','resolved','failed')),
  approved_by uuid,
  created_at timestamp default now()
);

create table audit_log (
  id uuid primary key default gen_random_uuid(),
  action text,
  performed_by uuid,
  details jsonb,
  created_at timestamp default now()
);
4. Install and run — Frontend
bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
5. Install and run — Backend
bash
cd backend
npm install
npm run dev
# Runs on http://localhost:3000
6. Install and run — ML Service
bash
cd ml-service
pip install -r requirements.txt
uvicorn main:app --reload --port 8001
# Runs on http://localhost:8001
7. Seed the database with vulnerability data
bash
cd integration
pip install -r requirements.txt
python fetch_cve_data.py    # pulls live CVE data from NVD + CISA KEV
python import_nmap.py       # imports Nmap scan results into Supabase
🔑 Environment Variables
Copy .env.example and fill in your values:

env
# Supabase
SUPABASE_URL=https://yourproject.supabase.co
SUPABASE_ANON_KEY=your-anon-public-key
SUPABASE_SECRET_KEY=your-service-role-secret-key

# AI
GROQ_API_KEY=your-groq-api-key

# Threat Intelligence
NVD_API_KEY=your-nvd-api-key
Where to find each:

Variable	Where to get it
SUPABASE_URL	Supabase → Settings → API → Project URL
SUPABASE_ANON_KEY	Supabase → Settings → API → anon public
SUPABASE_SECRET_KEY	Supabase → Settings → API → service_role
GROQ_API_KEY	console.groq.com → API Keys
NVD_API_KEY	nvd.nist.gov/developers/request-an-api-key
⚠️ Never commit your .env file. It is in .gitignore. Share key names via .env.example only.

🎯 Demo Flow
The winning walkthrough for judges — 8 steps, one complete analyst story:

Step	Action	What the judge sees
1	Upload Nmap/OpenVAS scan report	Parser ingests XML, normalises findings in real time
2	AI enriches all CVEs	CVSS scores, EPSS, CISA KEV status populated in < 5 sec
3	Risk scores calculated	Findings ranked by CVSS + KEV + asset criticality
4	Attack path graph generated	Interactive graph: entry point → lateral movement → target
5	Analyst queries AI Copilot	"Which CVEs chain to the database?" — grounded answer with MITRE refs
6	Admin approves remediation	Single approval gate — logged to audit trail
7	Simulated fix applied	Verification re-scan confirms resolved status
8	PDF report exported	Executive-ready report in under 10 seconds
🔐 Security Decisions
Decision	Reason
Open-weight LLM via Groq	No GPU infra needed; free tier; fast; no data sent to closed APIs
Scans run once ahead of time	Demo reliability — no fragile live scanning in front of judges
Single approval gate	Keeps scope realistic; prevents silent AI action on real systems
Compliance labels only (not computed)	NIST CSF / ISO 27001 / PCI-DSS appear as report tags only — honest scope
🗺️ Future Roadmap
These are legitimate production features — named honestly as not-yet-built:

 Live SIEM integration — bidirectional Splunk/ELK connector
 Compliance mapping engine — actual CVE-to-control logic for NIST CSF, ISO 27001, PCI-DSS
 BAS integration — continuous automated attack simulation feeding exploitability scores
 Real sandbox detonation — safely isolated malware behaviour capture
 Multi-tenant support — data isolation for multiple client organisations
 Rollback logic — automatic rollback + escalation if verification fails after a fix
 CI/CD pipeline hooks — GitHub Actions integration for shift-left security scanning
 Post-quantum readiness scanner — flag RSA/ECC usage before quantum threat materialises
👥 Team & Responsibilities
Role	Ownership
Frontend	Dashboard, attack graph (React Flow), AI Copilot chat UI, approval screen, role-based views
Backend	REST API, approval workflow, JWT auth, RBAC, notification integration, audit log
ML / AI	RAG pipeline, risk scoring formula, NetworkX attack patterns, ChromaDB embeddings, Groq integration
Integration	NVD + CISA KEV + OSV data pipeline, Nmap/OpenVAS import scripts, end-to-end wiring
📄 License
MIT License — see LICENSE for details.

<div align="center">
"VYUHA.AI doesn't just scan for vulnerabilities — it thinks like an attacker, acts like an analyst, and reports like a CISO."

Built for Hackathon 2025 · PS2: AI-Powered Vulnerability Analysis and Attack Path Assistant

</div>








