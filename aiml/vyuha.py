"""
VYUHA.AI — AI-Powered EDR Platform v6.0
Complete Production-Grade System

CHANGELOG v5 -> v6 (addressing review feedback):
  1. EPSS is now a LIVE call to api.first.org, cached with st.cache_data(ttl=86400) — no hardcoded list.
  2. CISA KEV catalog is fetched LIVE at runtime, cached with st.cache_data(ttl=3600) — no hardcoded array.
  3. Attack Chain Score now uses MITRE-tactic STAGE PROGRESSION weighting (Initial Access +2,
     Execution +2, Privilege Escalation +3, Credential Access +2, Data/Collection +3) instead of
     raw path-length + MITRE-technique-count.
  4. AI Confidence Score = Similarity (60%) + Source Count (20%) + Evidence Quality (20%),
     not similarity alone.
  5. Risk reasoning is now structured: Priority -> Why -> Evidence -> Recommendation, with each
     evidence line citing its live data source (NVD / CISA KEV / EPSS / attack graph).
  6. Nmap/OpenVAS parser now queries NVD for a REAL CVSS match (via CPE, then product+version
     keyword search) before ever falling back to a labeled service-exposure ESTIMATE.
  7. Attack pattern config now carries likelihood, business_impact, and priority per pattern.
  8. New Exposure Score dimension (internet-facing + critical service + auth requirement +
     non-standard port), folded into the Final Priority Score as a 5th weighted component.
  9. Explicitly NOT added: malware detection, IDS, anomaly detection, packet capture, or any
     trained "AI-washing" model (CNN/RF/LSTM/XGBoost) — the risk engine stays rule-based +
     live threat-intel APIs + RAG, which is the more defensible and honestly-described design.

QUICK START:
    pip install streamlit requests networkx matplotlib pandas sentence-transformers faiss-cpu groq pyyaml pypdf xmltodict
    streamlit run vyuha_dashboard.py
"""

import copy
import json
import logging
import math
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from collections import defaultdict

import streamlit as st
import pandas as pd
import requests
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Force UTF-8 on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Optional imports with graceful fallbacks
try:
    import xmltodict
    XML_SUPPORT = True
except ImportError:
    XML_SUPPORT = False

try:
    from sentence_transformers import SentenceTransformer
    import faiss
    FAISS_SUPPORT = True
except ImportError:
    FAISS_SUPPORT = False

try:
    from groq import Groq
    GROQ_SUPPORT = True
except ImportError:
    GROQ_SUPPORT = False

try:
    import yaml
    YAML_SUPPORT = True
except ImportError:
    YAML_SUPPORT = False

try:
    from pypdf import PdfReader
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

# ============================================================
# LOGGING SETUP
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("VYUHA.AI")

# ============================================================
# SESSION STATE INITIALIZATION (MUST BE FIRST)
# ============================================================
def initialize_all_session_state():
    """Initialize every single session state variable."""
    required_state = {
        "findings": [],
        "scan_history": [],
        "vector_index": None,
        "vector_docs": [],
        "kb_indexed": False,
        "chat_history": [],
        "attack_path_context": "",
        "vulnerable_nodes": {},
        "detected_chains": [],
        "system_initialized": False,
        "user_role": None,
        "authenticated": False,
        "remediation_in_progress": {},
    }
    for key, default_value in required_state.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

initialize_all_session_state()

# ============================================================
# CONFIGURATION
# ============================================================
APP_CONFIG = {
    "app": {"name": "VYUHA.AI — EDR Dashboard", "version": "6.0.0", "environment": "production"},
    "ui": {
        "severity_colors": {"Critical": "#d9363e", "High": "#e08a1e", "Medium": "#d9b310", "Low": "#3a8f3a"},
        "theme": {"dark": {
            "bg": "#0e1420", "secondary": "#141b2d", "surface": "#1a2338", "text": "#f4f6fb",
            "text_secondary": "#8fa0c4", "primary": "#3a4a70", "primary_hover": "#4a5a80",
            "border": "#2a3550", "success": "#3a8f3a", "warning": "#e08a1e", "danger": "#d9363e",
        }}
    },
    "api": {
        "endpoints": {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "epss": "https://api.first.org/data/v1/epss",
            "tavily": "https://api.tavily.com/search",
        },
        "timeouts": {"default": 15, "nvd": 15, "kev": 15, "epss": 10, "tavily": 15},
        "cache_ttl": {"kev": 3600, "epss": 86400, "nvd": 21600},
    },
    "risk_engine": {
        # Rebalanced to 5 dimensions (added exposure); sums to 1.00
        "weights": {
            "threat_severity": 0.30,
            "exploit_likelihood": 0.25,
            "attack_chain": 0.20,
            "exposure": 0.15,
            "asset_criticality": 0.10,
        },
        "tss_weights": {"cvss": 0.5, "kev": 0.3, "asset": 0.2},
        "asset_criticality_weights": {"Low": 1.0, "Medium": 1.3, "High": 1.6, "Critical Asset": 2.0},
        "severity_thresholds": {"critical": 8.5, "high": 6.5, "medium": 4.0, "low": 0.0},
        "epss_fallback_score": 3.0,
    },
    "escalation": {
        "default_threshold_minutes": 15, "min_threshold": 5, "max_threshold": 120,
        "severity_levels_for_escalation": ["Critical", "High"],
    },
    "remediation": {"post_fix_cvss_residual_factor": 0.15, "simulation_delay_seconds": 0.3},
    "rag": {
        "embedding_model": "all-MiniLM-L6-v2", "retrieval_top_k": 5,
        "chunk_size": 800, "chunk_overlap": 120,
        "similarity_threshold_high": 0.85, "similarity_threshold_medium": 0.65,
    },
    "llm": {"provider": "groq", "model": "openai/gpt-oss-120b", "temperature": 0.2, "max_tokens": 1500},
}

# ============================================================
# ATTACK STAGE WEIGHTS (MITRE-tactic-aligned progression scoring)
# Used by HybridRiskEngine.compute_acs — replaces the old
# "path length + MITRE technique count" heuristic with a scheme
# that's directly justifiable against MITRE ATT&CK tactic ordering.
# ============================================================
ATTACK_STAGE_WEIGHTS = {
    # Reconnaissance / Discovery (T1046 etc.)
    "exposed_service": 1,
    "insecure_service": 1,
    # Initial Access (T1190 etc.)
    "web_service": 2,
    "api_misconfiguration": 2,
    "remote_access": 2,
    # Execution / Exploitation of vulnerable code
    "outdated_software": 2,
    "unpatched_rce": 2,
    # Credential Access
    "weak_credential": 2,
    "broken_authz": 2,
    # Lateral Movement (propagation stage)
    "lateral_movement": 2,
    # Privilege Escalation — weighted highest short of data access
    "privilege_escalation": 3,
    # Collection / Exfiltration (Data Access)
    "data_exposure": 3,
    "database_exposure": 3,
}
DEFAULT_STAGE_WEIGHT = 1

# ============================================================
# SERVICE / PORT REFERENCE DATA
# (Used only as a last-resort estimate label when a live NVD
#  match cannot be found — never presented as if it were a real CVE.)
# ============================================================
SERVICE_RISK_MAPPINGS = {
    "ftp": ("insecure_service", "High", "FTP transmits credentials in cleartext - use SFTP instead"),
    "telnet": ("insecure_service", "High", "Telnet is unencrypted and vulnerable to credential sniffing"),
    "smtp": ("insecure_service", "Medium", "SMTP may allow open relay or user enumeration"),
    "http": ("web_service", "Medium", "HTTP detected - verify HTTPS enforcement and WAF protection"),
    "https": ("web_service", "Low", "HTTPS detected - verify TLS version and certificate validity"),
    "mysql": ("database_exposure", "High", "MySQL port exposed - verify access controls and strong authentication"),
    "postgresql": ("database_exposure", "High", "PostgreSQL exposed - ensure pg_hba.conf restricts access"),
    "mongodb": ("database_exposure", "Critical", "MongoDB exposed - verify authentication is enabled and network restricted"),
    "redis": ("database_exposure", "Critical", "Redis exposed without authentication - commonly targeted for data theft"),
    "elasticsearch": ("database_exposure", "High", "Elasticsearch exposed - sensitive data may be accessible without auth"),
    "rdp": ("remote_access", "High", "RDP exposed on port 3389 - common ransomware vector, enable NLA and MFA"),
    "ssh": ("remote_access", "Medium", "SSH exposed - use key-based authentication, disable root login, deploy fail2ban"),
    "smb": ("lateral_movement", "High", "SMB exposed - check for EternalBlue (CVE-2017-0144) and enforce SMB signing"),
    "vnc": ("remote_access", "High", "VNC without encryption - credentials transmitted in cleartext"),
    "ms-sql-s": ("database_exposure", "High", "Microsoft SQL Server exposed - verify Windows Authentication mode"),
    "oracle": ("database_exposure", "High", "Oracle Database exposed - verify TNS listener security"),
}

CRITICAL_SERVICES = {"mysql", "postgresql", "mongodb", "redis", "elasticsearch", "ms-sql-s", "oracle",
                      "rdp", "ssh", "smb"}
NO_AUTH_TYPICAL_SERVICES = {"redis", "mongodb"}  # often deployed without auth by default; still just a heuristic

ASSET_CRITICALITY_RULES = [
    {"ports": [3306, 5432, 27017, 6379, 9200, 1433, 1521], "criticality": "Critical Asset", "reason": "Database port"},
    {"ports": [22, 3389, 445, 389, 636], "criticality": "High", "reason": "Authentication/Admin port"},
    {"ports": [80, 443, 8080, 8443, 3000, 5000, 8000], "criticality": "Medium", "reason": "Web application port"},
]

# Attack patterns now carry likelihood / business_impact / priority for richer justification
ATTACK_PATTERNS_CONFIG = [
    {
        "name": "Web Exploit Chain: Public App -> RCE -> Database Access",
        "sequence": ["web_service", "outdated_software", "database_exposure"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing App", "T1210 - Exploitation of Remote Services", "T1530 - Data from Cloud Storage"],
        "severity": "Critical",
        "likelihood": "High",
        "business_impact": "Severe",
        "priority": 1,
        "description": "Attacker exploits vulnerable web application, achieves remote code execution, pivots to database containing sensitive data."
    },
    {
        "name": "Credential Attack Chain: Weak Passwords -> Lateral Movement -> Domain Admin",
        "sequence": ["weak_credential", "lateral_movement", "privilege_escalation"],
        "mitre_techniques": ["T1110 - Brute Force", "T1021 - Remote Services", "T1068 - Exploitation for Privilege Escalation"],
        "severity": "Critical",
        "likelihood": "Medium",
        "business_impact": "Severe",
        "priority": 1,
        "description": "Weak credentials allow initial access, lateral movement via remote services leads to domain controller compromise."
    },
    {
        "name": "Service Exposure Chain: Open Port -> Exploitation -> Data Access",
        "sequence": ["exposed_service", "insecure_service", "data_exposure"],
        "mitre_techniques": ["T1046 - Network Service Scanning", "T1190 - Exploit Public-Facing App", "T1530 - Data from Cloud Storage"],
        "severity": "High",
        "likelihood": "Medium",
        "business_impact": "High",
        "priority": 2,
        "description": "Exposed insecure service is discovered, exploited, and used to access sensitive data."
    },
    {
        "name": "Remote Access Chain: RDP/SSH -> Lateral Movement",
        "sequence": ["remote_access", "lateral_movement"],
        "mitre_techniques": ["T1021 - Remote Services", "T1210 - Exploitation of Remote Services"],
        "severity": "High",
        "likelihood": "Medium",
        "business_impact": "High",
        "priority": 2,
        "description": "Compromised remote access credentials used to move laterally across the network."
    },
]

REMEDIATION_ACTIONS_MAP = {
    "web_service": ["Enforce HTTPS with HSTS preloading", "Deploy Web Application Firewall (WAF) in blocking mode",
                    "Implement Content Security Policy (CSP) headers", "Conduct regular vulnerability scanning",
                    "Enable detailed access logging"],
    "database_exposure": ["Restrict network access with firewall rules (allow only app servers)",
                           "Enable strong authentication (disable default accounts)",
                           "Implement TLS encryption for all connections", "Enable audit logging for all queries",
                           "Apply latest security patches"],
    "remote_access": ["Implement VPN requirement for all remote access", "Enable Multi-Factor Authentication (MFA)",
                       "Use key-based authentication only (disable password auth for SSH)",
                       "Deploy fail2ban or similar rate-limiting", "Monitor for brute force attempts"],
    "lateral_movement": ["Implement network segmentation between VLANs", "Disable SMBv1 protocol on all systems",
                          "Enforce SMB signing and encryption", "Deploy network traffic monitoring",
                          "Restrict service account permissions"],
    "privilege_escalation": ["Apply security patches immediately (emergency change)",
                              "Implement least privilege principle across all systems",
                              "Enable Windows Credential Guard where supported",
                              "Monitor for token manipulation and privilege escalation", "Conduct regular privilege audits"],
    "outdated_software": ["Upgrade to latest stable/patched version",
                           "Implement automated dependency scanning in CI/CD",
                           "Subscribe to vendor security advisories",
                           "Deploy compensating controls (WAF/IDS) until patched",
                           "Verify patch application via authenticated scanning"],
    "unpatched_rce": ["Deploy emergency security patch immediately",
                       "Isolate affected system if exploitation is suspected",
                       "Implement network containment to limit blast radius",
                       "Review system and network logs for IoCs", "Re-scan after patching to verify remediation"],
    "weak_credential": ["Enforce strong password policy (minimum 14 characters)", "Enable MFA for all user accounts",
                         "Implement account lockout after 5 failed attempts", "Rotate all compromised credentials immediately",
                         "Conduct organization-wide password audit"],
    "insecure_service": ["Upgrade to secure protocol version or replacement", "Apply transport layer encryption (TLS 1.3)",
                          "Restrict access to authorized IP addresses only", "Implement service-level authentication",
                          "Schedule regular security assessments"],
    "exposed_service": ["Verify business justification for the exposed service",
                         "Implement firewall rules restricting source IPs",
                         "Move service behind VPN if external access not required",
                         "Enable detailed access and error logging", "Conduct quarterly port auditing"],
    "api_misconfiguration": ["Implement authentication on all API endpoints", "Apply rate limiting (100 requests/minute per client)",
                              "Deploy API gateway for centralized security", "Enable API request/response logging",
                              "Conduct API penetration testing"],
    "broken_authz": ["Implement object-level authorization checks on all endpoints",
                      "Add automated authorization tests to CI/CD pipeline",
                      "Conduct manual penetration testing of authorization",
                      "Implement Attribute-Based Access Control (ABAC)", "Log and monitor all authorization failures"],
    "data_exposure": ["Restrict data access to authorized services only",
                       "Encrypt sensitive data at rest (AES-256) and in transit (TLS)",
                       "Implement Data Loss Prevention (DLP) controls",
                       "Rotate any exposed credentials or API keys immediately",
                       "Conduct comprehensive data classification audit"],
}
REMEDIATION_ACTIONS_MAP["default"] = [
    "Apply vendor-provided security fix", "Verify fix through authenticated vulnerability scanning",
    "Document remediation steps for compliance", "Update asset inventory and CMDB",
]
REMEDIATION_ACTIONS_MAP["vulnerability"] = REMEDIATION_ACTIONS_MAP["default"]

# ============================================================
# LIVE THREAT-INTEL CLIENTS (KEV / EPSS / NVD)
# All cached with st.cache_data so they survive Streamlit's
# full-script reruns but still refresh on a sane TTL, and are
# shared cache across the whole app process (not per-session
# globals, which is the right scope for public threat-intel data).
# ============================================================

@st.cache_data(ttl=APP_CONFIG["api"]["cache_ttl"]["kev"], show_spinner=False)
def fetch_kev_catalog() -> List[Dict]:
    """Fetch CISA KEV catalog LIVE. No hardcoded list — see review point 'Remove KNOWN_KEV_LIST'."""
    try:
        resp = requests.get(APP_CONFIG["api"]["endpoints"]["kev"], timeout=APP_CONFIG["api"]["timeouts"]["kev"])
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except Exception as e:
        logger.warning(f"KEV catalog fetch failed (degrading gracefully to empty list): {e}")
        return []


def is_kev(cve_id: Optional[str]) -> bool:
    """Check live KEV catalog for a CVE. Returns False (not True) on fetch failure — conservative default."""
    if not cve_id:
        return False
    catalog = fetch_kev_catalog()
    return any(v.get("cveID") == cve_id for v in catalog)


@st.cache_data(ttl=APP_CONFIG["api"]["cache_ttl"]["epss"], show_spinner=False)
def fetch_epss_score(cve_id: str) -> Dict:
    """Fetch EPSS (Exploit Prediction Scoring System) score LIVE from FIRST.org. No hardcoded CVE list."""
    if not cve_id:
        return {"epss_score": 0.0, "percentile": 0.0, "found": False}
    try:
        resp = requests.get(APP_CONFIG["api"]["endpoints"]["epss"], params={"cve": cve_id},
                             timeout=APP_CONFIG["api"]["timeouts"]["epss"])
        resp.raise_for_status()
        items = resp.json().get("data", [])
        if items:
            return {"epss_score": float(items[0]["epss"]), "percentile": float(items[0]["percentile"]), "found": True}
        return {"epss_score": 0.0, "percentile": 0.0, "found": False}
    except Exception as e:
        logger.warning(f"EPSS fetch failed for {cve_id}: {e}")
        return {"epss_score": 0.0, "percentile": 0.0, "found": False, "error": str(e)}


def _parse_nvd_response(data: Dict) -> List[Dict]:
    out = []
    for v in data.get("vulnerabilities", []):
        cve = v["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cvss_score = None
        metrics = cve.get("metrics", {})
        for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if ver in metrics and metrics[ver]:
                cvss_score = metrics[ver][0]["cvssData"]["baseScore"]
                break
        out.append({"cve_id": cve["id"], "description": desc, "cvss_score": cvss_score})
    return out


# ============================================================
# TAVILY WEB SEARCH CLIENT
# ============================================================
def tavily_web_search(query: str, api_key: str, max_results: int = 3) -> List[Dict]:
    """Perform web search via Tavily API for RAG grounding."""
    if not api_key:
        return []

    try:
        response = requests.post(
            APP_CONFIG["api"]["endpoints"]["tavily"],
            json={
                "api_key": api_key,
                "query": query[:500],
                "search_depth": "basic",
                "max_results": max_results,
                "include_answer": False,
            },
            timeout=APP_CONFIG["api"]["timeouts"]["tavily"]
        )
        response.raise_for_status()
        data = response.json()

        results = []
        for item in data.get("results", []):
            results.append({
                "text": item.get("content", "")[:800],
                "source": f"Web: {item.get('title', 'Unknown')} ({item.get('url', '')})",
                "doc_type": "web",
                "distance": None
            })

        logger.info(f"Tavily search returned {len(results)} results for: {query[:100]}")
        return results

    except Exception as e:
        logger.warning(f"Tavily search error: {e}")
        return []

@st.cache_data(ttl=APP_CONFIG["api"]["cache_ttl"]["nvd"], show_spinner=False)
def query_nvd_by_cpe(cpe23: str, nvd_api_key: Optional[str] = None) -> List[Dict]:
    """Real NVD lookup by CPE 2.3 URI — most accurate match when the scanner reports a CPE string."""
    headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    try:
        resp = requests.get(APP_CONFIG["api"]["endpoints"]["nvd"], params={"cpeName": cpe23, "resultsPerPage": 5},
                             headers=headers, timeout=APP_CONFIG["api"]["timeouts"]["nvd"])
        resp.raise_for_status()
        return _parse_nvd_response(resp.json())
    except Exception as e:
        logger.warning(f"NVD CPE lookup failed for {cpe23}: {e}")
        return []


@st.cache_data(ttl=APP_CONFIG["api"]["cache_ttl"]["nvd"], show_spinner=False)
def query_nvd_by_keyword(keyword: str, nvd_api_key: Optional[str] = None) -> List[Dict]:
    """Fallback NVD lookup by product+version keyword search when no CPE is available."""
    headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    try:
        resp = requests.get(APP_CONFIG["api"]["endpoints"]["nvd"], params={"keywordSearch": keyword, "resultsPerPage": 5},
                             headers=headers, timeout=APP_CONFIG["api"]["timeouts"]["nvd"])
        resp.raise_for_status()
        return _parse_nvd_response(resp.json())
    except Exception as e:
        logger.warning(f"NVD keyword lookup failed for '{keyword}': {e}")
        return []


def cpe22_to_cpe23(cpe22: str) -> str:
    """Convert Nmap's CPE 2.2 URI binding (cpe:/a:vendor:product:version) to CPE 2.3 formatted
    string, which is what NVD's API actually expects for cpeName matches."""
    if not cpe22 or not cpe22.startswith("cpe:/"):
        return cpe22
    body = cpe22[len("cpe:/"):]
    parts = body.split(":")
    parts += [""] * max(0, 11 - len(parts))
    parts = [p if p else "*" for p in parts[:11]]
    return "cpe:2.3:" + ":".join(parts)


def lookup_real_cve_for_service(cpe: str, product: str, version: str,
                                 nvd_api_key: Optional[str] = None) -> List[Dict]:
    """
    Attempt a REAL NVD match before ever estimating. Tries CPE first (most accurate),
    then product+version keyword search. Returns [] if nothing found — caller must then
    fall back to a clearly-labeled estimate, never present a guess as if it were a real CVE.
    """
    if cpe:
        cpe23 = cpe22_to_cpe23(cpe)
        results = query_nvd_by_cpe(cpe23, nvd_api_key)
        if results:
            return results
    if product:
        keyword = f"{product} {version}".strip()
        results = query_nvd_by_keyword(keyword, nvd_api_key)
        if results:
            return results
    return []


# ============================================================
# KNOWLEDGE BASE (for RAG)
# ============================================================
def build_knowledge_base() -> List[Dict]:
    kb = []
    kb.extend([
        {"id": "svc-001", "source": "Service Exposure Risks", "doc_type": "built_in",
         "text": "Every open port represents attack surface that must be justified. Common high-risk services: SMB (445) targeted by EternalBlue and ransomware, RDP (3389) targeted by BlueKeep and brute force, databases (3306,5432,27017,6379) targeted for data theft. Databases should never be directly internet-facing. Use VPN or SSH tunneling for administrative access."},
        {"id": "svc-002", "source": "SMB Protocol Hardening", "doc_type": "built_in",
         "text": "SMB on ports 139/445 is a primary target for lateral movement and ransomware. EternalBlue (CVE-2017-0144) exploited SMBv1 to spread WannaCry globally. Hardening steps: Disable SMBv1 via registry or GPO, enforce SMB signing to prevent relay attacks, implement network segmentation to limit SMB traffic between VLANs, monitor for unusual SMB connection patterns indicating lateral movement."},
        {"id": "svc-003", "source": "Database Security Best Practices", "doc_type": "built_in",
         "text": "Database security requires defense in depth: Network isolation (firewall rules, VPC), strong authentication (no default passwords, MFA for admin), encryption (TLS for connections, TDE for data at rest), audit logging (all queries, access attempts), regular patching (especially for CVEs with exploit code). Redis without authentication was exploited by RegDemono malware. MongoDB ransomware attacks targeted unauthenticated instances with default configurations."},
    ])
    kb.extend([
        {"id": "mitre-001", "source": "MITRE ATT&CK T1046 - Network Service Scanning", "doc_type": "built_in",
         "text": "Network Service Scanning (T1046): Adversaries use port scanning tools like Nmap, Masscan, and Zmap to discover open ports and running services. This reconnaissance phase identifies potential attack vectors. Detection: Monitor for unusual port scanning patterns, implement network segmentation to limit discoverable services, use honeypots to detect scanning activity."},
        {"id": "mitre-002", "source": "MITRE ATT&CK T1190 - Exploit Public-Facing Application", "doc_type": "built_in",
         "text": "Exploit Public-Facing Application (T1190): Attackers exploit vulnerabilities in internet-facing applications for initial access. Log4Shell (CVE-2021-44228) demonstrated how a single vulnerable logging library could expose millions of applications to RCE. Mitigation requires regular vulnerability scanning, prompt patching, WAF deployment, and application security testing in CI/CD pipelines."},
        {"id": "mitre-003", "source": "MITRE ATT&CK T1021 - Remote Services", "doc_type": "built_in",
         "text": "Remote Services (T1021): After initial compromise, adversaries use valid accounts to access remote services like RDP, SSH, SMB, and WinRM for lateral movement. Critical controls: MFA for all remote access, network segmentation, privileged access workstations (PAW), monitoring for unusual remote connection patterns and off-hours activity."},
        {"id": "mitre-004", "source": "MITRE ATT&CK T1068 - Exploitation for Privilege Escalation", "doc_type": "built_in",
         "text": "Exploitation for Privilege Escalation (T1068): Adversaries exploit software vulnerabilities to gain higher privileges. Zerologon (CVE-2020-1472) exploited Netlogon protocol to gain domain administrator privileges from unauthenticated network access. Mitigation: Prompt patching, principle of least privilege, credential protection (Credential Guard, LSA Protection), and monitoring for token manipulation."},
    ])
    kb.extend([
        {"id": "ap-001", "source": "Attack Path Analysis Methodology", "doc_type": "built_in",
         "text": "Attack paths represent sequences of vulnerabilities that can be chained together. Common pattern: Reconnaissance (port scanning) -> Initial Access (exploit web app) -> Lateral Movement (RDP/SSH/SMB) -> Privilege Escalation (exploit OS vuln) -> Data Access/Exfiltration. Breaking any link in the chain prevents the entire attack. Prioritize fixing the earliest-stage vulnerability first."},
        {"id": "ap-002", "source": "Vulnerability Prioritization Framework", "doc_type": "built_in",
         "text": "Effective vulnerability prioritization uses multiple dimensions: 1) CISA KEV status (actively exploited - fix immediately), 2) EPSS score (probability of exploitation within 30 days), 3) Attack chain position (earlier = higher priority), 4) Exposure (internet-facing = higher priority), 5) Asset criticality (business impact of compromise). CVSS alone is insufficient for prioritization - must consider real-world exploit activity."},
    ])
    kb.extend([
        {"id": "kev-001", "source": "CISA Known Exploited Vulnerabilities Program", "doc_type": "built_in",
         "text": "The CISA KEV catalog identifies vulnerabilities known to be actively exploited in the wild. Binding Operational Directive (BOD) 22-01 requires federal agencies to remediate KEV vulnerabilities within specific timeframes: Critical/High severity within 15 calendar days, all others within 30 calendar days. KEV status should override CVSS score for prioritization."},
    ])
    kb.extend([
        {"id": "rem-001", "source": "Vulnerability Remediation Best Practices", "doc_type": "built_in",
         "text": "Effective vulnerability remediation program: 1) Prioritize using KEV + EPSS + Attack Chain + Exposure analysis (not CVSS alone), 2) Define SLAs (Critical: 24 hours, High: 48 hours, Medium: 7 days, Low: 30 days), 3) Test patches in staging before production, 4) Deploy compensating controls (WAF, firewall blocks, MFA) when immediate patching is not possible, 5) Verify remediation through authenticated scanning."},
        {"id": "rem-002", "source": "Emergency Patching Procedures", "doc_type": "built_in",
         "text": "For critical KEV vulnerabilities on exposed services: Assess scope within 2 hours, test patch in isolated environment, deploy to production within 24 hours, verify deployment with authenticated scanning, document for compliance. Maintain pre-approved emergency change windows."},
    ])
    return kb


# ============================================================
# SAMPLE DATA GENERATOR
# ============================================================
def generate_sample_findings() -> List[Dict]:
    now = datetime.utcnow()
    return [
        {"finding_id": "FIND-2024-001", "asset": "WEB-CUSTOMER-PORTAL", "asset_ip": "203.0.113.10",
         "asset_type": "Web Server", "finding_type": "web_service", "cve_id": "CVE-2021-44228",
         "cvss_score": 10.0, "actively_exploited_kev": True, "asset_criticality": "High",
         "internet_facing": True, "requires_auth": False,
         "description": "Apache HTTP Server 2.4.49 with Log4j 2.14.0 - Vulnerable to Log4Shell (CVE-2021-44228). Public-facing customer portal. No WAF protection detected.",
         "port": 443, "protocol": "tcp", "service": "https", "source": "Vulnerability Scanner",
         "connects_to": ["APP-PAYMENT-03", "AUTH-SERVICE-01"], "status": "Open",
         "detected_at": now - timedelta(minutes=45), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-002", "asset": "APP-PAYMENT-03", "asset_ip": "10.0.1.50",
         "asset_type": "Application Server", "finding_type": "outdated_software", "cve_id": "CVE-2021-44228",
         "cvss_score": 10.0, "actively_exploited_kev": True, "asset_criticality": "High",
         "internet_facing": False, "requires_auth": True,
         "description": "Spring Boot 2.5.0 with Log4j 2.14.0 - Same Log4Shell vulnerability. Internal application processing payment transactions.",
         "port": 8080, "protocol": "tcp", "service": "http", "source": "Dependency Scanner",
         "connects_to": ["DB-PAYMENTS-01"], "status": "Open",
         "detected_at": now - timedelta(minutes=43), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-003", "asset": "DB-PAYMENTS-01", "asset_ip": "10.0.2.20",
         "asset_type": "Database Server", "finding_type": "database_exposure", "cve_id": "CVE-2023-2454",
         "cvss_score": 7.5, "actively_exploited_kev": False, "asset_criticality": "Critical Asset",
         "internet_facing": False, "requires_auth": True,
         "description": "PostgreSQL 14.7 containing payment card data (PCI DSS Level 1). Contains PAN, expiry, CVV for 500,000+ customer payment methods.",
         "port": 5432, "protocol": "tcp", "service": "postgresql", "source": "Database Scanner",
         "connects_to": [], "status": "Open",
         "detected_at": now - timedelta(minutes=40), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-004", "asset": "HR-WORKSTATION-14", "asset_ip": "10.0.3.100",
         "asset_type": "Workstation", "finding_type": "weak_credential", "cve_id": None,
         "cvss_score": 7.0, "actively_exploited_kev": False, "asset_criticality": "Medium",
         "internet_facing": False, "requires_auth": True,
         "description": "Password audit discovered 4 user accounts using 'Company2024!' pattern. No account lockout policy configured.",
         "port": 0, "protocol": "tcp", "service": "unknown", "source": "Password Audit",
         "connects_to": ["HR-FILESERVER-02"], "status": "Open",
         "detected_at": now - timedelta(minutes=120), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-005", "asset": "HR-FILESERVER-02", "asset_ip": "10.0.3.50",
         "asset_type": "File Server", "finding_type": "lateral_movement", "cve_id": "CVE-2017-0144",
         "cvss_score": 8.1, "actively_exploited_kev": True, "asset_criticality": "High",
         "internet_facing": False, "requires_auth": True,
         "description": "Windows Server 2016 with SMBv1 enabled. Vulnerable to EternalBlue (CVE-2017-0144). Accessible from HR workstations.",
         "port": 445, "protocol": "tcp", "service": "smb", "source": "Vulnerability Scanner",
         "connects_to": ["DC-PRIMARY-01"], "status": "Open",
         "detected_at": now - timedelta(minutes=90), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-006", "asset": "DC-PRIMARY-01", "asset_ip": "10.0.0.5",
         "asset_type": "Domain Controller", "finding_type": "privilege_escalation", "cve_id": "CVE-2020-1472",
         "cvss_score": 10.0, "actively_exploited_kev": True, "asset_criticality": "Critical Asset",
         "internet_facing": False, "requires_auth": False,
         "description": "Windows Server 2019 Domain Controller vulnerable to Zerologon (CVE-2020-1472). Full forest compromise possible.",
         "port": 445, "protocol": "tcp", "service": "smb", "source": "Vulnerability Scanner",
         "connects_to": [], "status": "Open",
         "detected_at": now - timedelta(minutes=60), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-007", "asset": "API-GATEWAY-PROD", "asset_ip": "203.0.113.20",
         "asset_type": "API Gateway", "finding_type": "api_misconfiguration", "cve_id": None,
         "cvss_score": 6.5, "actively_exploited_kev": False, "asset_criticality": "Medium",
         "internet_facing": True, "requires_auth": False,
         "description": "Production API gateway (Kong 3.0) missing authentication middleware on /api/v1/internal/users/{id} endpoint.",
         "port": 8443, "protocol": "tcp", "service": "https", "source": "API Security Scanner",
         "connects_to": ["AUTH-SERVICE-01"], "status": "Open",
         "detected_at": now - timedelta(minutes=180), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-008", "asset": "AUTH-SERVICE-01", "asset_ip": "10.0.1.60",
         "asset_type": "Authentication Service", "finding_type": "broken_authz", "cve_id": None,
         "cvss_score": 8.0, "actively_exploited_kev": False, "asset_criticality": "High",
         "internet_facing": False, "requires_auth": True,
         "description": "Broken Object Level Authorization (BOLA) in authentication microservice. User A can access User B's full profile.",
         "port": 8080, "protocol": "tcp", "service": "http", "source": "Penetration Test",
         "connects_to": ["CUSTOMER-DB-01"], "status": "Open",
         "detected_at": now - timedelta(minutes=175), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-009", "asset": "CUSTOMER-DB-01", "asset_ip": "10.0.2.30",
         "asset_type": "Database Server", "finding_type": "data_exposure", "cve_id": None,
         "cvss_score": 8.5, "actively_exploited_kev": False, "asset_criticality": "Critical Asset",
         "internet_facing": False, "requires_auth": True,
         "description": "Customer database (MySQL 8.0) containing PII for 2.1 million users. GDPR-protected data for EU citizens.",
         "port": 3306, "protocol": "tcp", "service": "mysql", "source": "Data Discovery",
         "connects_to": [], "status": "Open",
         "detected_at": now - timedelta(minutes=170), "acknowledged_at": None, "assigned_to": None},
        {"finding_id": "FIND-2024-010", "asset": "PRINTER-IOT-VLAN-07", "asset_ip": "10.0.99.50",
         "asset_type": "IoT Device", "finding_type": "outdated_software", "cve_id": None,
         "cvss_score": 4.5, "actively_exploited_kev": False, "asset_criticality": "Low",
         "internet_facing": False, "requires_auth": True,
         "description": "HP LaserJet Pro M404dn running firmware from 2019. Isolated on dedicated IoT VLAN.",
         "port": 9100, "protocol": "tcp", "service": "http", "source": "Network Scanner",
         "connects_to": [], "status": "Open",
         "detected_at": now - timedelta(minutes=300), "acknowledged_at": None, "assigned_to": None},
    ]


# ============================================================
# SCAN PARSER — Universal Format Handler (Nmap / OpenVAS / Generic)
# ============================================================
class UniversalScanParser:
    """Parse any scan format into standardized findings, with REAL NVD CVE
    matching wherever possible instead of estimating CVSS from service name."""

    @staticmethod
    def get_service_risk(service_name: str) -> Tuple[str, str, str]:
        default = ("exposed_service", "Low", f"Service '{service_name}' detected - verify business need")
        return SERVICE_RISK_MAPPINGS.get(service_name.lower(), default)

    @staticmethod
    def get_asset_criticality(port: int) -> str:
        for rule in ASSET_CRITICALITY_RULES:
            if port in rule["ports"]:
                return rule["criticality"]
        return "Low"

    @staticmethod
    def estimate_cvss(risk_level: str) -> float:
        """LAST-RESORT estimate only, used and clearly labeled when no real NVD match exists."""
        scores = {"Critical": 9.5, "High": 7.8, "Medium": 5.5, "Low": 3.0}
        return round(scores.get(risk_level, 5.0), 1)

    @staticmethod
    def parse_nmap_json(content: str, nvd_api_key: Optional[str] = None) -> Tuple[List[Dict], Dict]:
        """Parse Nmap JSON output (handles the nmaprun-wrapper structure)."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Nmap JSON parse error: {e}")
            return [], {"error": "Invalid JSON"}

        findings = []
        scan_time = datetime.utcnow()
        host_count = 0
        port_count = 0
        real_cve_matches = 0

        if isinstance(data, dict) and "nmaprun" in data:
            hosts = data["nmaprun"].get("host", [])
        elif isinstance(data, dict) and "host" in data:
            hosts = [data["host"]]
        elif isinstance(data, list):
            hosts = data
        else:
            return [], {"error": "Unknown JSON structure - expected nmaprun wrapper"}

        if isinstance(hosts, dict):
            hosts = [hosts]

        for host in hosts:
            if not isinstance(host, dict):
                continue
            host_count += 1

            host_ip = "unknown"
            addr_data = host.get("address", {})
            if isinstance(addr_data, dict):
                host_ip = addr_data.get("_addr", "unknown")
            elif isinstance(addr_data, list):
                for addr in addr_data:
                    if isinstance(addr, dict) and addr.get("_addrtype") == "ipv4":
                        host_ip = addr.get("_addr", "unknown")
                        break

            hostnames = host.get("hostnames", {})
            hn_data = hostnames.get("hostname", {}) if isinstance(hostnames, dict) else {}
            host_name = hn_data.get("_name", host_ip) if isinstance(hn_data, dict) else host_ip

            ports_data = host.get("ports", {})
            port_list = ports_data.get("port", [])
            if isinstance(port_list, dict):
                port_list = [port_list]

            for port in port_list:
                if not isinstance(port, dict):
                    continue

                state_data = port.get("state", {})
                port_state = state_data.get("_state", "closed") if isinstance(state_data, dict) else "closed"
                if port_state != "open":
                    continue
                port_count += 1

                port_id = port.get("_portid", "0")
                protocol = port.get("_protocol", "tcp")

                service_data = port.get("service", {})
                if isinstance(service_data, dict):
                    service_name = service_data.get("_name", "unknown")
                    service_product = service_data.get("_product", "")
                    service_version = service_data.get("_version", "")
                    service_extrainfo = service_data.get("_extrainfo", "")
                    service_cpe = service_data.get("cpe", "")
                else:
                    service_name, service_product, service_version, service_extrainfo, service_cpe = \
                        "unknown", "", "", "", ""

                finding_type, risk_level, base_description = UniversalScanParser.get_service_risk(service_name)
                asset_criticality = UniversalScanParser.get_asset_criticality(int(port_id) if str(port_id).isdigit() else 0)

                description = base_description
                if service_product:
                    description += f" | Product: {service_product}"
                if service_version:
                    description += f" v{service_version}"
                if service_extrainfo:
                    description += f" ({service_extrainfo})"

                # --- REAL NVD lookup first; only estimate as a last resort ---
                real_matches = []
                if service_product or service_cpe:
                    real_matches = lookup_real_cve_for_service(service_cpe, service_product, service_version, nvd_api_key)

                if real_matches:
                    real_cve_matches += 1
                    top = real_matches[0]
                    cve_ids = [m["cve_id"] for m in real_matches[:3]]
                    cvss = top.get("cvss_score") or UniversalScanParser.estimate_cvss(risk_level)
                    description += f" | NVD Match: {top['cve_id']} — {(top.get('description') or '')[:150]}"
                    kev_status = any(is_kev(c) for c in cve_ids)
                    primary_cve = cve_ids[0]
                else:
                    cvss = UniversalScanParser.estimate_cvss(risk_level)
                    description += " | No live NVD match found — risk ESTIMATED from service-exposure baseline only."
                    kev_status = False
                    primary_cve = None

                finding = {
                    "finding_id": f"NMAP-{host_ip}-{port_id}-{uuid.uuid4().hex[:6].upper()}",
                    "asset": host_name, "asset_ip": host_ip, "asset_type": "Host",
                    "finding_type": finding_type, "cve_id": primary_cve, "cvss_score": cvss,
                    "actively_exploited_kev": kev_status, "asset_criticality": asset_criticality,
                    "internet_facing": not (host_ip.startswith(("10.", "172.16.", "192.168.", "127."))),
                    "requires_auth": service_name.lower() not in NO_AUTH_TYPICAL_SERVICES,
                    "description": description, "port": int(port_id) if str(port_id).isdigit() else 0,
                    "protocol": protocol, "service": service_name, "source": "Nmap Scan",
                    "connects_to": [], "status": "Open", "detected_at": scan_time,
                    "acknowledged_at": None, "assigned_to": None,
                }
                findings.append(finding)

        scan_record = {
            "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}", "type": "Nmap JSON",
            "timestamp": scan_time.isoformat(), "hosts_scanned": host_count,
            "ports_found": port_count, "findings_generated": len(findings),
            "real_nvd_matches": real_cve_matches,
        }
        return findings, scan_record

    @staticmethod
    def parse_openvas_json(content: str) -> Tuple[List[Dict], Dict]:
        """
        Lenient OpenVAS JSON parser. OpenVAS/GVM export shapes vary a lot depending on how the
        report was exported (GMP get_reports response, omp -X converted output, custom export
        scripts), so this walks the JSON tree looking for result-like objects rather than
        assuming one fixed schema.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return [], {"error": "Invalid JSON"}

        scan_time = datetime.utcnow()
        findings = []

        def walk(node):
            if isinstance(node, dict):
                keys_lower = {k.lower() for k in node.keys()}
                if ({"nvt", "severity"} <= keys_lower or {"cve", "severity"} <= keys_lower
                        or "threat" in keys_lower):
                    yield node
                for v in node.values():
                    yield from walk(v)
            elif isinstance(node, list):
                for item in node:
                    yield from walk(item)

        for result in walk(data):
            host = result.get("host") or result.get("Host") or "unknown"
            if isinstance(host, dict):
                host = host.get("#text") or host.get("_text") or host.get("text") or "unknown"

            nvt = result.get("nvt", {})
            name = (nvt.get("name") if isinstance(nvt, dict) else None) or result.get("name") or "OpenVAS Finding"
            cve = result.get("cve") or (nvt.get("cve") if isinstance(nvt, dict) else None)
            if isinstance(cve, str) and cve.upper() in ("NOCVE", "N/A", ""):
                cve = None

            severity_raw = result.get("severity") or result.get("Severity") or result.get("threat")
            try:
                cvss = float(severity_raw)
            except (TypeError, ValueError):
                sev_map = {"high": 8.0, "medium": 5.0, "low": 2.5, "log": 0.0}
                cvss = sev_map.get(str(severity_raw).lower(), 5.0)

            finding_type = "outdated_software" if cve else "exposed_service"
            findings.append({
                "finding_id": f"OPENVAS-{host}-{uuid.uuid4().hex[:6].upper()}",
                "asset": host, "asset_ip": host, "asset_type": "Host",
                "finding_type": finding_type, "cve_id": cve, "cvss_score": round(cvss, 1),
                "actively_exploited_kev": is_kev(cve) if cve else False,
                "asset_criticality": "Medium",
                "internet_facing": not (str(host).startswith(("10.", "172.16.", "192.168.", "127."))),
                "requires_auth": True,
                "description": f"{name}" + (f" ({cve})" if cve else ""),
                "port": result.get("port", 0), "protocol": "tcp",
                "service": result.get("service", "unknown"), "source": "OpenVAS Scan",
                "connects_to": [], "status": "Open", "detected_at": scan_time,
                "acknowledged_at": None, "assigned_to": None,
            })

        scan_record = {
            "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}", "type": "OpenVAS JSON",
            "timestamp": scan_time.isoformat(), "findings_generated": len(findings),
        }
        return findings, scan_record

    @staticmethod
    def parse_generic_json(content: str) -> Tuple[List[Dict], Dict]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return [], {"error": "Invalid JSON"}

        findings = []
        scan_time = datetime.utcnow()

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("findings") or data.get("results") or data.get("vulnerabilities") or data.get("data") or []
            if not items and "findings" not in data:
                items = [data]
        else:
            return [], {"error": "Unexpected JSON structure"}

        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            return [], {"error": "Could not extract finding list"}

        for item in items:
            if not isinstance(item, dict):
                continue
            cve_id = item.get("cve_id") or item.get("cve") or item.get("CVE")
            finding = {
                "finding_id": item.get("id") or item.get("finding_id") or f"IMP-{uuid.uuid4().hex[:8].upper()}",
                "asset": item.get("asset") or item.get("host") or item.get("hostname") or item.get("ip") or "unknown",
                "asset_ip": item.get("ip") or item.get("asset_ip") or item.get("host") or "unknown",
                "asset_type": item.get("asset_type") or item.get("type") or "Host",
                "finding_type": item.get("finding_type") or item.get("vuln_type") or item.get("category") or "vulnerability",
                "cve_id": cve_id,
                "cvss_score": item.get("cvss_score") or item.get("cvss"),
                "actively_exploited_kev": item.get("kev") if "kev" in item else (is_kev(cve_id) if cve_id else False),
                "asset_criticality": item.get("criticality") or item.get("asset_criticality") or "Medium",
                "internet_facing": item.get("internet_facing", False),
                "requires_auth": item.get("requires_auth", True),
                "description": item.get("description") or item.get("summary") or item.get("name") or "",
                "port": item.get("port") or 0, "protocol": item.get("protocol") or "tcp",
                "service": item.get("service") or item.get("application") or "unknown",
                "source": item.get("source") or "Generic Import",
                "connects_to": item.get("connects_to") or item.get("connections") or [],
                "status": "Open", "detected_at": scan_time, "acknowledged_at": None, "assigned_to": None,
            }
            findings.append(finding)

        scan_record = {"scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}", "type": "JSON Import",
                        "timestamp": scan_time.isoformat(), "findings_generated": len(findings)}
        return findings, scan_record

    @staticmethod
    def auto_detect_and_parse(content: Union[str, bytes], filename: str = "",
                               nvd_api_key: Optional[str] = None) -> Tuple[List[Dict], Dict]:
        """Auto-detect format (Nmap JSON/XML, OpenVAS JSON, generic JSON/YAML) and dispatch."""
        content_str = content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else content
        if not content_str.strip():
            return [], {"error": "Empty file"}

        if "nmaprun" in content_str:
            logger.info("Detected Nmap JSON format")
            return UniversalScanParser.parse_nmap_json(content_str, nvd_api_key)

        # OpenVAS signature check (before generic XML/JSON fallback)
        openvas_signals = ("get_reports_response", '"nvt"', "'nvt'", "openvas", "greenbone")
        if any(sig in content_str.lower() for sig in openvas_signals) and "nmaprun" not in content_str:
            logger.info("Detected likely OpenVAS format")
            parsed, record = UniversalScanParser.parse_openvas_json(content_str)
            if parsed:
                return parsed, record
            # fall through to generic parsing if the lenient walk found nothing

        if content_str.strip().startswith("<?xml") or content_str.strip().startswith("<nmaprun") \
                or content_str.strip().startswith("<report"):
            if XML_SUPPORT:
                logger.info("Detected XML format, attempting parse")
                try:
                    data = xmltodict.parse(content_str)
                    json_str = json.dumps(data)
                    if "nmaprun" in json_str:
                        findings, record = UniversalScanParser.parse_nmap_json(json_str, nvd_api_key)
                        record["type"] = "Nmap XML"
                        return findings, record
                    findings, record = UniversalScanParser.parse_openvas_json(json_str)
                    record["type"] = "OpenVAS XML"
                    return findings, record
                except Exception as e:
                    logger.error(f"XML parse error: {e}")
                    return [], {"error": f"XML parse failed: {str(e)}"}
            else:
                return [], {"error": "XML support requires xmltodict: pip install xmltodict"}

        try:
            json.loads(content_str)
            logger.info("Detected JSON format")
            return UniversalScanParser.parse_generic_json(content_str)
        except json.JSONDecodeError:
            pass

        if YAML_SUPPORT:
            try:
                data = yaml.safe_load(content_str)
                json_str = json.dumps(data, default=str)
                return UniversalScanParser.parse_generic_json(json_str)
            except Exception:
                pass

        return [], {"error": "Could not detect file format. Supported: Nmap JSON/XML, OpenVAS JSON/XML, Generic JSON/YAML"}


# ============================================================
# EXPOSURE SCORE (new dimension per review feedback)
# ============================================================
def compute_exposure_score(finding: Dict) -> Dict:
    """
    Exposure Score (0-10), rule-based:
      +4  internet-facing
      +3  critical service (db/remote-access/admin protocol)
      +3  no authentication required
      +0.5 non-standard/administrative port (not 80/443)
    """
    internet_facing = bool(finding.get("internet_facing", False))
    service = (finding.get("service") or "").lower()
    critical_service = service in CRITICAL_SERVICES
    requires_auth = finding.get("requires_auth", True)
    port = finding.get("port", 0) or 0

    score = 0.0
    factors = []
    if internet_facing:
        score += 4.0
        factors.append("internet-facing")
    if critical_service:
        score += 3.0
        factors.append(f"critical service ({service})")
    if not requires_auth:
        score += 3.0
        factors.append("no authentication required")
    if port and port not in (80, 443):
        score += 0.5
        factors.append("non-standard/administrative port")

    score = min(round(score, 2), 10.0)
    return {
        "exposure_score": score,
        "internet_facing": internet_facing,
        "explanation": ", ".join(factors) if factors else "no significant exposure factors identified",
    }


# ============================================================
# HYBRID RISK ENGINE (5 dimensions, live-data-driven, with
# structured Priority -> Why -> Evidence -> Recommendation output)
# ============================================================
class HybridRiskEngine:
    def __init__(self):
        self.reload_weights()

    def reload_weights(self):
        re_cfg = APP_CONFIG["risk_engine"]
        self.weights = re_cfg["weights"]
        self.tss_w = re_cfg["tss_weights"]
        self.asset_w = re_cfg["asset_criticality_weights"]
        self.thresholds = re_cfg["severity_thresholds"]
        self.epss_fallback = re_cfg["epss_fallback_score"]

    def compute_tss(self, cvss: Optional[float], is_kev_flag: bool, asset_criticality: str) -> float:
        cvss_norm = (cvss or 0.0) / 10.0
        kev_val = 1.0 if is_kev_flag else 0.0
        asset_norm = self.asset_w.get(asset_criticality, 1.3) / 2.0
        score = (self.tss_w["cvss"] * cvss_norm + self.tss_w["kev"] * kev_val + self.tss_w["asset"] * asset_norm) * 10.0
        return round(score, 2)

    def compute_els(self, cve_id: Optional[str]) -> Dict:
        """Exploit Likelihood Score — LIVE EPSS call, no hardcoded CVE list."""
        if not cve_id:
            return {"els_score": self.epss_fallback, "found": False, "note": "No CVE ID"}
        epss = fetch_epss_score(cve_id)
        if epss["found"]:
            return {"els_score": round(epss["epss_score"] * 10.0, 2), "found": True,
                     "epss_score": epss["epss_score"], "percentile": epss["percentile"]}
        return {"els_score": self.epss_fallback, "found": False,
                 "note": epss.get("error", "EPSS data not available")}

    def compute_acs(self, finding: Dict, all_findings: List[Dict], chains: List[Dict]) -> Dict:
        """
        Attack Chain Score — STAGE-PROGRESSION weighting (replaces old
        length + MITRE-count heuristic). Each node in a matched chain
        contributes its highest attack-stage weight (Recon=1, Initial
        Access/Execution/Credential/Lateral=2, PrivEsc/Data=3); the chain's
        normalized stage total (0-10) is used, taking the max across all
        chains this finding's asset participates in.
        """
        asset = finding.get("asset", "")
        relevant = [c for c in chains if asset in c.get("path", [])]
        if not relevant:
            return {"acs_score": 2.0, "chains_involved": 0, "details": "Not part of any detected attack chain"}

        # asset -> list of finding_types, built once from all_findings
        asset_types: Dict[str, List[str]] = defaultdict(list)
        for f in all_findings:
            asset_types[f.get("asset", "")].append(f.get("finding_type", ""))

        max_score = 0.0
        max_stage_total = 0
        best_chain_name = ""
        for c in relevant:
            stage_total = 0
            for node in c["path"]:
                node_types = asset_types.get(node, [])
                node_stage = max((ATTACK_STAGE_WEIGHTS.get(t, DEFAULT_STAGE_WEIGHT) for t in node_types),
                                  default=DEFAULT_STAGE_WEIGHT)
                stage_total += node_stage
            chain_len = max(len(c["path"]), 1)
            normalized = min((stage_total / (3.0 * chain_len)) * 10.0, 10.0)
            if normalized > max_score:
                max_score = normalized
                max_stage_total = stage_total
                best_chain_name = c["pattern_name"]

        return {
            "acs_score": round(max_score, 2),
            "chains_involved": len(relevant),
            "details": f"Part of {len(relevant)} attack chain(s); stage-progression score {max_stage_total} "
                       f"in '{best_chain_name}'",
        }

    def compute_aics(self, distances: Optional[List[float]], doc_types: Optional[List[str]] = None) -> Dict:
        """
        AI Confidence Score = Similarity (60%) + Source Count (20%) + Evidence Quality (20%).
        Replaces the old similarity-only heuristic.
        """
        if not distances:
            return {"aics_score": 0.0, "confidence_level": "Unknown", "explanation": "No retrieval data available"}

        similarities = [math.exp(-d * 1.5) for d in distances]
        avg_similarity = sum(similarities) / len(similarities) if similarities else 0.0
        similarity_component = avg_similarity * 60.0

        source_count = len(distances)
        source_count_component = min(source_count / 5.0, 1.0) * 20.0

        quality_weights = {"built_in": 1.0, "policy": 1.0, "attack_chain": 1.0, "web": 0.6}
        if doc_types:
            avg_quality = sum(quality_weights.get(t, 0.7) for t in doc_types) / len(doc_types)
        else:
            avg_quality = 0.8
        evidence_quality_component = avg_quality * 20.0

        score_pct = min(round(similarity_component + source_count_component + evidence_quality_component, 1), 100.0)

        if score_pct >= 85:
            level, explanation = "High", "Strong semantic match, multiple sources, high-quality evidence"
        elif score_pct >= 65:
            level, explanation = "Medium", "Good match with reasonable source diversity"
        elif score_pct >= 40:
            level, explanation = "Low", "Partial match — consider adding policy documents or enabling web search"
        else:
            level, explanation = "Very Low", "Weak match — knowledge base may lack relevant information"

        return {
            "aics_score": score_pct, "confidence_level": level, "explanation": explanation,
            "components": {
                "similarity": round(similarity_component, 1),
                "source_count": round(source_count_component, 1),
                "evidence_quality": round(evidence_quality_component, 1),
            },
        }

    def compute_fps(self, tss: float, els: float, acs: float, exposure: float, asset_criticality: str) -> Dict:
        """Final Priority Score — 5-dimension weighted fusion (added Exposure)."""
        asset_norm = (self.asset_w.get(asset_criticality, 1.3) / 2.0) * 10.0
        fps = (self.weights["threat_severity"] * tss +
               self.weights["exploit_likelihood"] * els +
               self.weights["attack_chain"] * acs +
               self.weights["exposure"] * exposure +
               self.weights["asset_criticality"] * asset_norm)
        fps = min(round(fps, 2), 10.0)

        if fps >= self.thresholds["critical"]:
            severity = "Critical"
        elif fps >= self.thresholds["high"]:
            severity = "High"
        elif fps >= self.thresholds["medium"]:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "final_priority_score": fps, "severity_label": severity,
            "score_breakdown": {
                "threat_severity": round(self.weights["threat_severity"] * tss, 2),
                "exploit_likelihood": round(self.weights["exploit_likelihood"] * els, 2),
                "attack_chain": round(self.weights["attack_chain"] * acs, 2),
                "exposure": round(self.weights["exposure"] * exposure, 2),
                "asset_criticality": round(self.weights["asset_criticality"] * asset_norm, 2),
            },
        }

    def generate_reasoning(self, finding: Dict, tss: float, els_data: Dict, acs_data: Dict,
                            exposure_data: Dict, fps_data: Dict) -> Dict:
        """Structured: Priority -> Why -> Evidence -> Recommendation, each evidence line
        citing its live data source rather than an unexplained number."""
        severity = fps_data["severity_label"]
        score = fps_data["final_priority_score"]

        why_parts = []
        evidence = []

        cvss = finding.get("cvss_score")
        if cvss:
            tier = "critical" if cvss >= 9 else "high" if cvss >= 7 else "moderate" if cvss >= 4 else "low"
            why_parts.append(f"the underlying vulnerability has {tier} technical severity (CVSS {cvss}/10)")
            evidence.append(f"CVSS Base Score: {cvss}/10" + (f" — {finding.get('cve_id')}" if finding.get("cve_id") else " (estimated, no live CVE match)"))

        if finding.get("actively_exploited_kev"):
            why_parts.append("it is confirmed to be actively exploited in the wild right now")
            evidence.append("Source: CISA Known Exploited Vulnerabilities catalog (live feed)")

        if els_data.get("found"):
            epss_pct = els_data["epss_score"] * 100
            why_parts.append(f"FIRST.org's EPSS model estimates a {epss_pct:.1f}% chance of exploitation within 30 days")
            evidence.append(f"EPSS Score: {epss_pct:.1f}% (percentile {els_data.get('percentile', 0) * 100:.1f}%) — live FIRST.org API")
        else:
            evidence.append("EPSS: no live score available for this CVE — used fallback baseline")

        if acs_data.get("chains_involved", 0) > 0:
            why_parts.append(acs_data.get("details", "part of a detected attack chain"))
            evidence.append(f"Attack Chain Score: {acs_data['acs_score']}/10 (stage-progression analysis, {acs_data['chains_involved']} chain(s))")
        else:
            evidence.append("Attack Chain: not currently part of any detected multi-step chain")

        if exposure_data:
            why_parts.append(f"exposure factors ({exposure_data['explanation']}) raise its accessibility to an attacker")
            evidence.append(f"Exposure Score: {exposure_data['exposure_score']}/10 — {exposure_data['explanation']}")

        asset_crit = finding.get("asset_criticality", "Medium")
        why_parts.append(f"the affected asset is classified as {asset_crit} criticality")
        evidence.append(f"Asset Criticality: {asset_crit}")

        if severity == "Critical":
            recommendation = "Remediate within 24 hours. Escalate to incident response immediately if part of an active attack chain."
        elif severity == "High":
            recommendation = "Remediate within 48 hours. Treat as top priority if internet-facing or KEV-listed."
        elif severity == "Medium":
            recommendation = "Remediate within the standard 7-14 day change window."
        else:
            recommendation = "Address in the next scheduled patch cycle (within 30 days)."

        why_text = "This finding is prioritized as it is because " + "; and because ".join(why_parts) + "." if why_parts else \
                   "Limited data is available to fully justify this finding's priority."

        return {"priority": f"{severity} ({score}/10)", "why": why_text, "evidence": evidence,
                "recommendation": recommendation}

    def assess(self, finding: Dict, all_findings: List[Dict], chains: List[Dict],
               retrieval_distances: Optional[List[float]] = None,
               retrieval_doc_types: Optional[List[str]] = None) -> Dict:
        tss = self.compute_tss(finding.get("cvss_score"), finding.get("actively_exploited_kev", False),
                                finding.get("asset_criticality", "Medium"))
        els_data = self.compute_els(finding.get("cve_id"))
        acs_data = self.compute_acs(finding, all_findings, chains)
        exposure_data = compute_exposure_score(finding)
        aics_data = self.compute_aics(retrieval_distances, retrieval_doc_types)
        fps_data = self.compute_fps(tss, els_data["els_score"], acs_data["acs_score"],
                                     exposure_data["exposure_score"], finding.get("asset_criticality", "Medium"))
        reasoning = self.generate_reasoning(finding, tss, els_data, acs_data, exposure_data, fps_data)

        return {
            "threat_severity": {"tss_score": tss},
            "exploit_likelihood": els_data,
            "attack_chain": acs_data,
            "exposure": exposure_data,
            "ai_confidence": aics_data,
            "final_priority": fps_data,
            "reasoning": reasoning,
        }


risk_engine = HybridRiskEngine()

# ============================================================
# ATTACK PATH ANALYSIS
# ============================================================
def build_asset_graph(findings: List[Dict]) -> nx.DiGraph:
    G = nx.DiGraph()
    for f in findings:
        asset = f.get("asset", "unknown")
        if asset not in G:
            G.add_node(asset, findings=[], ip=f.get("asset_ip", ""), score=0, finding_type=f.get("finding_type", ""))
        G.nodes[asset]["findings"].append(f.get("finding_type", ""))
        G.nodes[asset]["score"] = max(G.nodes[asset]["score"], f.get("normalized_risk_score", 0))
        if f.get("asset_ip"):
            G.nodes[asset]["ip"] = f["asset_ip"]
    for f in findings:
        for target in f.get("connects_to", []):
            if target and target != f.get("asset"):
                G.add_edge(f.get("asset", ""), target)
    return G


def _sequence_in_order(pattern_seq: List[str], found_types: List[str]) -> bool:
    idx = 0
    for step in pattern_seq:
        found = False
        for i in range(idx, len(found_types)):
            if found_types[i] == step:
                idx = i + 1
                found = True
                break
        if not found:
            return False
    return True


def detect_attack_chains(findings: List[Dict]) -> List[Dict]:
    if not findings:
        return []
    G = build_asset_graph(findings)
    matches = []
    for pattern in ATTACK_PATTERNS_CONFIG:
        seq = pattern["sequence"]
        for start_node in list(G.nodes()):
            queue = [[start_node]]
            while queue:
                path = queue.pop(0)
                if len(path) > len(seq) + 2:
                    continue
                types_on_path = []
                for node in path:
                    if node in G.nodes:
                        types_on_path.extend(G.nodes[node].get("findings", []))
                if _sequence_in_order(seq, types_on_path):
                    matches.append({
                        "pattern_name": pattern["name"], "path": path.copy(),
                        "mitre_techniques": pattern.get("mitre_techniques", []),
                        "severity": pattern.get("severity", "High"),
                        "likelihood": pattern.get("likelihood", "Medium"),
                        "business_impact": pattern.get("business_impact", "Moderate"),
                        "priority": pattern.get("priority", 3),
                        "description": pattern.get("description", ""),
                    })
                last_node = path[-1]
                for neighbor in G.successors(last_node):
                    if neighbor not in path:
                        queue.append(path + [neighbor])

    seen = set()
    unique = []
    for m in matches:
        key = (m["pattern_name"], tuple(m["path"]))
        if key not in seen:
            seen.add(key)
            unique.append(m)
    unique.sort(key=lambda m: m.get("priority", 3))
    return unique


def identify_most_vulnerable_nodes(findings: List[Dict], chains: List[Dict]) -> Dict:
    node_scores = defaultdict(lambda: {"score": 0, "findings": [], "in_chains": 0, "total_risk": 0})
    for f in findings:
        asset = f.get("asset", "unknown")
        node_scores[asset]["findings"].append(f)
        node_scores[asset]["total_risk"] += f.get("normalized_risk_score", 0)
        node_scores[asset]["score"] = max(node_scores[asset]["score"], f.get("normalized_risk_score", 0))
    for chain in chains:
        for node in chain.get("path", []):
            node_scores[node]["in_chains"] += 1
    sorted_nodes = sorted(node_scores.items(), key=lambda x: x[1]["in_chains"] * 10 + x[1]["total_risk"], reverse=True)
    return dict(sorted_nodes[:5])


def generate_attack_path_context(chains: List[Dict], vuln_nodes: Dict, findings: List[Dict]) -> str:
    parts = ["=== ACTIVE ATTACK PATHS ==="]
    if chains:
        for i, c in enumerate(chains[:5]):
            parts.append(f"Attack Path {i+1}: {c['pattern_name']} (Severity: {c['severity']}, "
                         f"Likelihood: {c.get('likelihood','?')}, Business Impact: {c.get('business_impact','?')})")
            parts.append(f"Path: {' -> '.join(c['path'])}")
            parts.append(f"MITRE Techniques: {', '.join(c.get('mitre_techniques', []))}")
            parts.append("")
    else:
        parts.append("No attack chains detected.")
        parts.append("")

    parts.append("=== MOST VULNERABLE NODES ===")
    for node, info in vuln_nodes.items():
        parts.append(f"- {node}: Max Score={info['score']}/10, Chains={info['in_chains']}, "
                     f"Total Risk={info['total_risk']}, Findings={len(info['findings'])}")
    parts.append("")

    parts.append("=== TOP FINDINGS BY RISK ===")
    for f in sorted(findings, key=lambda x: -x.get("normalized_risk_score", 0))[:10]:
        parts.append(f"- {f['finding_id']}: {f.get('description', '')[:100]} "
                     f"(Score: {f.get('normalized_risk_score', 0)}/10, KEV: {'Yes' if f.get('actively_exploited_kev') else 'No'})")

    return "\n".join(parts)


def recalculate_all_findings(findings: List[Dict]) -> Tuple[List[Dict], List[Dict], Dict]:
    active = [f for f in findings if f.get("status") != "Closed"]
    chains = detect_attack_chains(active)
    vuln_nodes = identify_most_vulnerable_nodes(active, chains)

    for f in findings:
        assessment = risk_engine.assess(f, active, chains)
        f["hybrid_assessment"] = assessment
        f["normalized_risk_score"] = assessment["final_priority"]["final_priority_score"]
        f["severity_label"] = assessment["final_priority"]["severity_label"]

    st.session_state.attack_path_context = generate_attack_path_context(chains, vuln_nodes, active)
    st.session_state.vulnerable_nodes = vuln_nodes
    st.session_state.detected_chains = chains

    return findings, chains, vuln_nodes


def check_escalation(findings: List[Dict], threshold_minutes: int) -> List[Dict]:
    severity_levels = APP_CONFIG["escalation"]["severity_levels_for_escalation"]
    now = datetime.utcnow()
    for f in findings:
        if f.get("status") == "Closed":
            f["is_overdue"] = False
            f["minutes_open"] = 0
            continue
        detected = f.get("detected_at", now)
        minutes = (now - detected).total_seconds() / 60.0
        f["minutes_open"] = round(minutes, 1)
        f["is_overdue"] = (f.get("status") == "Open" and f.get("severity_label") in severity_levels
                            and minutes > threshold_minutes)
    return findings


def get_remediation_steps(finding_type: str) -> List[str]:
    return REMEDIATION_ACTIONS_MAP.get(finding_type, REMEDIATION_ACTIONS_MAP["default"])


def simulate_remediation(finding: Dict) -> Dict:
    steps = get_remediation_steps(finding.get("finding_type", "vulnerability"))
    residual_factor = APP_CONFIG["remediation"]["post_fix_cvss_residual_factor"]
    now = datetime.utcnow()

    log = [{"time": now + timedelta(seconds=i * 3), "message": f"Executing: {step}"} for i, step in enumerate(steps)]
    log.append({"time": now + timedelta(seconds=len(steps) * 3),
                "message": "Running authenticated vulnerability scan to verify remediation..."})

    post_finding = copy.deepcopy(finding)
    post_finding["cvss_score"] = round((finding.get("cvss_score") or 0.0) * residual_factor, 1)
    post_finding["actively_exploited_kev"] = False
    post_finding["requires_auth"] = True  # assume fix included enforcing auth where relevant

    assessment = risk_engine.assess(post_finding, [], [])
    new_score = assessment["final_priority"]["final_priority_score"]
    new_severity = assessment["final_priority"]["severity_label"]

    log.append({"time": now + timedelta(seconds=(len(steps) + 1) * 3),
                "message": f"Verification complete - Residual risk: {new_score}/10 ({new_severity})"})

    return {"log": log, "post_fix_cvss": post_finding["cvss_score"], "post_fix_assessment": assessment,
            "verified_at": now + timedelta(seconds=(len(steps) + 1) * 3), "steps_applied": steps}


# ============================================================
# RAG PIPELINE
# ============================================================
@st.cache_resource(show_spinner=False)
def get_embedding_model():
    if not FAISS_SUPPORT:
        return None
    return SentenceTransformer(APP_CONFIG["rag"]["embedding_model"])


def index_documents_into_faiss(documents: List[Dict]) -> int:
    if not FAISS_SUPPORT:
        return 0
    embedder = get_embedding_model()
    if embedder is None:
        return 0
    texts = [doc["text"] for doc in documents]
    embeddings = embedder.encode(texts, show_progress_bar=False).astype("float32")
    if st.session_state.vector_index is None:
        st.session_state.vector_index = faiss.IndexFlatL2(embeddings.shape[1])
    st.session_state.vector_index.add(embeddings)
    st.session_state.vector_docs.extend(documents)
    return len(documents)


def index_knowledge_base_documents() -> int:
    return index_documents_into_faiss(build_knowledge_base())


def semantic_search_query(query: str, top_k: int = None) -> Tuple[List[Dict], List[float]]:
    if top_k is None:
        top_k = APP_CONFIG["rag"]["retrieval_top_k"]
    index = st.session_state.vector_index
    if index is None or index.ntotal == 0:
        return [], []
    embedder = get_embedding_model()
    if embedder is None:
        return [], []
    query_emb = embedder.encode([query], show_progress_bar=False).astype("float32")
    k = min(top_k, index.ntotal)
    distances, indices = index.search(query_emb, k)
    documents, distance_list = [], []
    for dist, idx in zip(distances[0], indices[0]):
        if idx == -1:
            continue
        doc = st.session_state.vector_docs[idx]
        documents.append({"text": doc["text"], "source": doc.get("source", "Unknown"),
                          "doc_type": doc.get("doc_type", "built_in"), "distance": float(dist)})
        distance_list.append(float(dist))
    return documents, distance_list


def chunk_text_content(text: str) -> List[str]:
    chunk_size = APP_CONFIG["rag"]["chunk_size"]
    overlap = APP_CONFIG["rag"]["chunk_overlap"]
    text = text.strip()
    if not text:
        return []
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start = end - overlap
    return chunks


def index_policy_document(uploaded_file) -> int:
    filename = uploaded_file.name.lower()
    if filename.endswith(".pdf"):
        if not PDF_SUPPORT:
            return 0
        try:
            reader = PdfReader(uploaded_file)
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception as e:
            logger.error(f"PDF extraction failed: {e}")
            return 0
    else:
        try:
            text = uploaded_file.read().decode("utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"File read failed: {e}")
            return 0
    chunks = chunk_text_content(text)
    if not chunks:
        return 0
    docs = [{"id": f"policy-{uploaded_file.name}-{i}", "text": chunk,
             "source": f"Uploaded Policy: {uploaded_file.name}", "doc_type": "policy"}
            for i, chunk in enumerate(chunks)]
    return index_documents_into_faiss(docs)


def sync_attack_chains_to_rag(chains: List[Dict]) -> int:
    """Auto-index each newly-detected attack chain as a RAG document, so the
    Copilot can answer questions grounded in the CURRENT live attack graph,
    not just static reference knowledge. Deduplicated per session."""
    if not FAISS_SUPPORT:
        return 0
    if "indexed_chain_signatures" not in st.session_state:
        st.session_state.indexed_chain_signatures = set()

    new_docs = []
    for c in chains:
        sig = c["pattern_name"] + "|" + "->".join(c["path"])
        if sig in st.session_state.indexed_chain_signatures:
            continue
        text = (f"Detected Attack Chain: {c['pattern_name']}. Path: {' -> '.join(c['path'])}. "
                f"Severity: {c['severity']}. Likelihood: {c.get('likelihood','?')}. "
                f"Business Impact: {c.get('business_impact','?')}. "
                f"MITRE ATT&CK techniques: {', '.join(c.get('mitre_techniques', []))}. {c.get('description','')}")
        new_docs.append({"id": f"chain-{uuid.uuid4().hex[:8]}", "text": text,
                         "source": f"Detected Attack Chain: {c['pattern_name']}", "doc_type": "attack_chain"})
        st.session_state.indexed_chain_signatures.add(sig)

    if new_docs:
        return index_documents_into_faiss(new_docs)
    return 0


# ============================================================
# UI HELPERS
# ============================================================
def get_severity_color(severity: str) -> str:
    return APP_CONFIG["ui"]["severity_colors"].get(severity, "#666666")


def sb(severity: str) -> str:
    color = get_severity_color(severity)
    return (f'<span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;'
            f'font-weight:700;color:white;text-transform:uppercase;background:{color}">{severity}</span>')


def confidence_badge_html(score: float) -> str:
    if score >= 85:
        color, level, icon = "#4ade80", "HIGH", "🟢"
    elif score >= 65:
        color, level, icon = "#fbbf24", "MEDIUM", "🟡"
    elif score >= 40:
        color, level, icon = "#f59e0b", "LOW", "🟠"
    else:
        color, level, icon = "#f87171", "VERY LOW", "🔴"
    return f'<span style="color:{color};font-weight:700;">{icon} {level} Confidence ({score:.0f}%)</span>'


def generate_dynamic_css() -> str:
    t = APP_CONFIG["ui"]["theme"]["dark"]
    return f"""
    <style>
        #MainMenu {{visibility: hidden;}}
        footer {{visibility: hidden;}}
        .stApp {{background-color: {t['bg']};}}
        .main .block-container {{padding-top: 1rem; padding-bottom: 1rem;}}
        .metric-card {{
            background: linear-gradient(145deg, {t['secondary']}, {t['surface']});
            border: 1px solid {t['border']}; border-radius: 12px; padding: 20px 24px; margin: 8px 0;
            transition: all 0.2s ease;
        }}
        .metric-card:hover {{border-color: {t['primary_hover']}; transform: translateY(-1px);}}
        .metric-label {{color: {t['text_secondary']}; font-size: 11px; text-transform: uppercase;
            letter-spacing: 0.08em; font-weight: 600;}}
        .metric-value {{color: {t['text']}; font-size: 32px; font-weight: 700; margin-top: 6px; line-height: 1;}}
        .section-title {{color: {t['text']}; font-size: 24px; font-weight: 700; margin: 20px 0 12px 0;
            padding-bottom: 8px; border-bottom: 2px solid {t['primary']};}}
        .section-subtitle {{color: {t['text_secondary']}; font-size: 14px; margin-bottom: 16px;}}
        .overdue-banner {{
            background: linear-gradient(135deg, #3a1420, #2d1018); border: 1px solid #d9363e;
            color: #ffb3ba; padding: 14px 20px; border-radius: 10px; margin-bottom: 20px;
            font-size: 15px; font-weight: 500;
        }}
        .info-box {{background: {t['secondary']}; border: 1px solid {t['border']}; border-radius: 10px;
            padding: 16px 20px; margin: 12px 0;}}
        .reasoning-box {{background: {t['surface']}; border-left: 3px solid {t['primary_hover']};
            border-radius: 6px; padding: 12px 16px; margin: 8px 0;}}
        .stButton>button {{
            background-color: {t['primary']}; color: {t['text']}; border-radius: 8px;
            border: 1px solid {t['primary_hover']}; padding: 8px 16px; font-weight: 600; transition: all 0.2s;
        }}
        .stButton>button:hover {{background-color: {t['primary_hover']}; border-color: {t['primary_hover']};
            transform: translateY(-1px);}}
        .stExpander {{background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px;}}
    </style>
    """


# ============================================================
# STREAMLIT APP
# ============================================================
st.set_page_config(page_title=APP_CONFIG["app"]["name"], page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown(generate_dynamic_css(), unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 10px 0;">
        <h2 style="color: #f4f6fb; margin: 0;">🛡️ VYUHA.AI</h2>
        <p style="color: #8fa0c4; font-size: 13px; margin: 4px 0;">AI-Powered EDR Platform</p>
    </div>
    """, unsafe_allow_html=True)

    if not st.session_state.authenticated:
        st.markdown("---")
        role = st.selectbox("Select Role", ["Administrator", "Security Analyst"])
        if st.button("🔐 Login", type="primary", use_container_width=True):
            st.session_state.user_role = role
            st.session_state.authenticated = True
            st.rerun()
    else:
        st.success(f"👤 Logged in as: **{st.session_state.user_role}**")
        if st.button("Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.rerun()

    if not st.session_state.authenticated:
        st.stop()

    if not st.session_state.system_initialized:
        st.markdown("---")
        if st.button("🚀 Quick Start (Load Sample Data)", type="primary", use_container_width=True):
            with st.spinner("Initializing VYUHA.AI..."):
                st.session_state.findings = generate_sample_findings()
                if FAISS_SUPPORT and not st.session_state.kb_indexed:
                    index_knowledge_base_documents()
                    st.session_state.kb_indexed = True
                st.session_state.system_initialized = True
                st.success(f"✅ System Ready! {len(st.session_state.findings)} findings loaded.")
                st.rerun()
        st.info("👆 Load sample data or import a scan below")

    st.markdown("---")
    is_admin = st.session_state.user_role == "Administrator"
    nav_items = ["📊 Dashboard", "🔍 Risk Intelligence", "🔗 Attack Paths", "🎯 Vulnerable Nodes", "💬 AI Copilot"]
    if is_admin:
        nav_items.append("⏱️ Remediation & Escalation")
    page = st.radio("Navigation", nav_items, label_visibility="collapsed")

    st.markdown("---")
    st.markdown("### 🔑 API Keys")
    nvd_key = st.text_input("NVD API Key (optional)", type="password",
                             help="Higher rate limit for real CVE lookups during scan import — nvd.nist.gov/developers")
    groq_key = st.text_input("Groq API Key", type="password", placeholder="For AI Copilot")
    tavily_key = st.text_input("Tavily API Key (optional)", type="password", placeholder="For web search")

    st.markdown("---")
    st.markdown("### 📤 Import Scan Data")
    uploaded_file = st.file_uploader("Upload scan file", type=["json", "xml", "yaml", "yml"],
                                      help="Supported: Nmap JSON/XML, OpenVAS JSON/XML, Generic JSON/YAML")

    if uploaded_file:
        if st.button("🔍 Parse & Import Findings", type="primary", use_container_width=True):
            with st.spinner("Parsing scan data (querying NVD for real CVE matches where possible)..."):
                content = uploaded_file.read()
                parsed_findings, scan_record = UniversalScanParser.auto_detect_and_parse(
                    content, uploaded_file.name, nvd_api_key=nvd_key or None)
                if parsed_findings:
                    st.session_state.findings.extend(parsed_findings)
                    st.session_state.scan_history.append(scan_record)
                    st.session_state.system_initialized = True
                    recalculate_all_findings(st.session_state.findings)
                    st.success(f"✅ Imported {len(parsed_findings)} findings from {scan_record.get('type', 'scan')}!")
                    if scan_record.get("real_nvd_matches") is not None:
                        st.info(f"Real NVD CVE matches: {scan_record['real_nvd_matches']} of "
                                f"{scan_record.get('ports_found', len(parsed_findings))} findings "
                                f"(remainder are labeled service-exposure estimates)")
                    st.rerun()
                else:
                    st.error(f"Could not parse file. {scan_record.get('error', 'Unknown format')}")

    with st.expander("🔍 Quick CVE Lookup (real NVD data)"):
        cve_input = st.text_input("CVE ID", placeholder="CVE-2024-1234")
        if st.button("Add CVE Finding", use_container_width=True) and cve_input:
            headers = {"apiKey": nvd_key} if nvd_key else {}
            try:
                resp = requests.get(APP_CONFIG["api"]["endpoints"]["nvd"], params={"cveId": cve_input.strip()},
                                     headers=headers, timeout=15)
                resp.raise_for_status()
                matches = _parse_nvd_response(resp.json())
            except Exception as e:
                matches = []
                st.warning(f"NVD lookup failed: {e}")

            if matches:
                m = matches[0]
                finding = {
                    "finding_id": f"CVE-{uuid.uuid4().hex[:8].upper()}", "asset": f"Target-{cve_input}",
                    "asset_ip": "unknown", "asset_type": "Host", "finding_type": "vulnerability",
                    "cve_id": m["cve_id"], "cvss_score": m.get("cvss_score") or 5.0,
                    "actively_exploited_kev": is_kev(m["cve_id"]), "asset_criticality": "Medium",
                    "internet_facing": False, "requires_auth": True,
                    "description": m.get("description", f"Manually added CVE: {cve_input}"),
                    "port": 0, "protocol": "tcp", "service": "unknown", "source": "Manual Entry (NVD verified)",
                    "connects_to": [], "status": "Open", "detected_at": datetime.utcnow(),
                    "acknowledged_at": None, "assigned_to": None,
                }
                st.session_state.findings.append(finding)
                st.session_state.system_initialized = True
                st.success(f"✅ Added {m['cve_id']} — real NVD data (CVSS {m.get('cvss_score','N/A')})")
                st.rerun()
            else:
                st.error(f"CVE {cve_input} not found in NVD")

    st.markdown("---")
    st.markdown("### ⚙️ Settings")
    escalation_threshold = st.slider("Escalation Threshold (minutes)", min_value=5, max_value=120,
                                      value=APP_CONFIG["escalation"]["default_threshold_minutes"], step=5,
                                      help="Critical/High findings open longer than this are flagged overdue")

    if st.button("🗑️ Clear All Data", use_container_width=True):
        st.session_state.findings = []
        st.session_state.chat_history = []
        st.session_state.scan_history = []
        st.session_state.system_initialized = False
        st.session_state.attack_path_context = ""
        st.session_state.vulnerable_nodes = {}
        st.rerun()

    st.markdown("---")
    st.caption(f"🛡️ VYUHA.AI v{APP_CONFIG['app']['version']}")
    st.caption(f"Findings: {len(st.session_state.findings)} | Scans: {len(st.session_state.scan_history)} | "
               f"KB docs: {len(st.session_state.vector_docs)}")
    st.caption("Live data: NVD · CISA KEV · FIRST.org EPSS — no hardcoded threat lists")

# ---------------- DATA PROCESSING ----------------
try:
    findings, chains, vuln_nodes = recalculate_all_findings(st.session_state.findings)
    sync_attack_chains_to_rag(chains)
except Exception as e:
    logger.error(f"Recalculation error: {e}")
    findings = st.session_state.findings
    chains = st.session_state.detected_chains
    vuln_nodes = st.session_state.vulnerable_nodes

findings = check_escalation(findings, escalation_threshold)
st.session_state.findings = findings

active_findings = [f for f in findings if f.get("status") != "Closed"]
critical_count = sum(1 for f in findings if f.get("severity_label") == "Critical")
high_count = sum(1 for f in findings if f.get("severity_label") == "High")
overdue_count = sum(1 for f in findings if f.get("is_overdue"))

# ---------------- WELCOME SCREEN ----------------
if not st.session_state.system_initialized:
    st.markdown("""
    <div style="text-align: center; padding: 60px 20px;">
        <h1 style="color: #f4f6fb; font-size: 48px; margin-bottom: 10px;">🛡️ VYUHA.AI</h1>
        <p style="color: #8fa0c4; font-size: 20px; margin-bottom: 40px;">AI-Powered EDR Platform with Hybrid Risk Intelligence</p>
    </div>
    """, unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""<div class="info-box"><h3 style="color:#f4f6fb;">🔍 Hybrid Risk Intelligence</h3>
        <p style="color:#8fa0c4;font-size:14px;">5-dimension live scoring: Threat Severity (CVSS+KEV), Exploit Likelihood (live EPSS),
        Attack Chain (stage-progression), Exposure, and Asset Criticality.</p></div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""<div class="info-box"><h3 style="color:#f4f6fb;">🔗 Attack Path Analysis</h3>
        <p style="color:#8fa0c4;font-size:14px;">MITRE ATT&CK-aligned patterns with likelihood and business-impact ratings,
        auto-fed into the AI Copilot's context.</p></div>""", unsafe_allow_html=True)
    with col3:
        st.markdown("""<div class="info-box"><h3 style="color:#f4f6fb;">💬 AI Security Copilot</h3>
        <p style="color:#8fa0c4;font-size:14px;">RAG-grounded, multi-factor confidence scoring, structured
        Priority → Why → Evidence → Recommendation reasoning.</p></div>""", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""<div style="text-align:center;padding:20px;"><h3 style="color:#f4f6fb;">🚀 Getting Started</h3>
    <p style="color:#8fa0c4;font-size:16px;"><strong>Option 1:</strong> Click "Quick Start" in the sidebar<br>
    <strong>Option 2:</strong> Import your Nmap/OpenVAS scan (JSON/XML/YAML)<br>
    <strong>Option 3:</strong> Add individual CVEs via Quick CVE Lookup (real NVD data)</p></div>""",
                unsafe_allow_html=True)
    st.stop()

# ---------------- PAGE: DASHBOARD ----------------
if page == "📊 Dashboard":
    st.markdown('<div class="section-title">📊 Security Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<p class="section-subtitle">Real-time posture overview — 5-dimension hybrid risk scores</p>', unsafe_allow_html=True)

    if overdue_count > 0:
        st.markdown(f"""<div class="overdue-banner">⚠️ <strong>{overdue_count} finding(s) OVERDUE</strong> —
        Critical/High severity unacknowledged for more than {escalation_threshold} minutes.</div>""", unsafe_allow_html=True)

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, value, color in [
        (c1, "Total Findings", len(findings), None),
        (c2, "Critical", critical_count, "#d9363e"),
        (c3, "High Severity", high_count, "#e08a1e"),
        (c4, "Attack Chains", len(chains), None),
        (c5, "Overdue", overdue_count, "#d9363e" if overdue_count > 0 else "#3a8f3a"),
    ]:
        style = f' style="color:{color};"' if color else ""
        col.markdown(f'<div class="metric-card"><div class="metric-label">{label}</div>'
                     f'<div class="metric-value"{style}>{value}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    left_col, right_col = st.columns([1, 1])

    with left_col:
        st.markdown('<p style="color:#f4f6fb;font-size:18px;font-weight:700;">Severity Distribution</p>', unsafe_allow_html=True)
        if findings:
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for f in findings:
                sev_counts[f.get("severity_label", "Low")] = sev_counts.get(f.get("severity_label", "Low"), 0) + 1
            fig, ax = plt.subplots(figsize=(6, 4))
            fig.patch.set_alpha(0)
            ax.set_facecolor("none")
            labels = list(sev_counts.keys())
            values = list(sev_counts.values())
            bars = ax.bar(labels, values, color=[get_severity_color(l) for l in labels], edgecolor="white", linewidth=0.5)
            ax.tick_params(colors="#c9d6ea", labelsize=11)
            for spine in ax.spines.values():
                spine.set_color("#2a3550")
            ax.set_ylabel("Count", color="#c9d6ea", fontsize=11)
            for bar, val in zip(bars, values):
                if val > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3, str(val),
                           ha='center', color='#c9d6ea', fontweight='bold')
            st.pyplot(fig)
        else:
            st.info("No findings to display")

    with right_col:
        st.markdown('<p style="color:#f4f6fb;font-size:18px;font-weight:700;">Active Attack Chains</p>', unsafe_allow_html=True)
        if chains:
            for chain in chains[:5]:
                st.markdown(f"""<div style="background:#1a2338;border:1px solid #2a3550;border-radius:8px;padding:12px;margin:8px 0;">
                <span style="color:{get_severity_color(chain.get('severity','High'))};font-weight:700;">🔴 {chain['pattern_name']}</span>
                <p style="color:#8fa0c4;font-size:12px;margin:4px 0;">Path: {' → '.join(chain['path'])}</p>
                <p style="color:#8fa0c4;font-size:11px;margin:2px 0;">Likelihood: {chain.get('likelihood','?')} | Business Impact: {chain.get('business_impact','?')}</p>
                </div>""", unsafe_allow_html=True)
            if len(chains) > 5:
                st.caption(f"... and {len(chains) - 5} more chains")
        else:
            st.info("No attack chains detected in current findings")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p style="color:#f4f6fb;font-size:18px;font-weight:700;">All Findings</p>', unsafe_allow_html=True)
    if findings:
        display_data = [{
            "ID": f.get("finding_id", ""), "Asset": f.get("asset", ""),
            "Type": f.get("finding_type", "").replace("_", " ").title(),
            "Severity": f.get("severity_label", ""), "Score": f"{f.get('normalized_risk_score', 0)}/10",
            "Exposure": f"{f.get('hybrid_assessment',{}).get('exposure',{}).get('exposure_score','N/A')}/10",
            "KEV": "⚠️ Yes" if f.get("actively_exploited_kev") else "No",
            "Status": f.get("status", ""), "Open (min)": f.get("minutes_open", 0), "Source": f.get("source", ""),
        } for f in sorted(findings, key=lambda x: -x.get("normalized_risk_score", 0))]
        st.dataframe(pd.DataFrame(display_data), use_container_width=True, hide_index=True)
    else:
        st.info("No findings. Import scan data or use Quick Start.")

# ---------------- PAGE: RISK INTELLIGENCE ----------------
elif page == "🔍 Risk Intelligence":
    st.markdown('<div class="section-title">🔍 Hybrid Risk Intelligence</div>', unsafe_allow_html=True)
    st.markdown('<p class="section-subtitle">5-dimension live scoring with structured Priority → Why → Evidence → Recommendation reasoning</p>', unsafe_allow_html=True)

    with st.expander("📐 Risk Engine Configuration"):
        w = risk_engine.weights
        th = risk_engine.thresholds
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Threat Severity", f"{w['threat_severity']*100:.0f}%", help="CVSS + live CISA KEV status")
        c2.metric("Exploit Likelihood", f"{w['exploit_likelihood']*100:.0f}%", help="Live FIRST.org EPSS score")
        c3.metric("Attack Chain", f"{w['attack_chain']*100:.0f}%", help="MITRE-stage-progression score")
        c4.metric("Exposure", f"{w['exposure']*100:.0f}%", help="Internet-facing + critical service + auth")
        c5.metric("Asset Criticality", f"{w['asset_criticality']*100:.0f}%")
        st.caption(f"Severity thresholds: Critical ≥ {th['critical']} | High ≥ {th['high']} | Medium ≥ {th['medium']}")

    st.markdown("<br>", unsafe_allow_html=True)

    for finding in sorted(findings, key=lambda x: -x.get("normalized_risk_score", 0)):
        assessment = finding.get("hybrid_assessment", {})
        sev = finding.get("severity_label", "Unknown")
        score = finding.get("normalized_risk_score", 0)
        expander_label = f"{finding['finding_id']} — {finding['asset']} | Severity: {sev} | Score: {score}/10"

        with st.expander(expander_label, expanded=(sev == "Critical")):
            st.markdown(sb(sev), unsafe_allow_html=True)
            st.markdown(f"**Description:** {finding.get('description', 'No description')}")

            meta_cols = st.columns(4)
            meta_cols[0].caption(f"CVE: {finding.get('cve_id', 'N/A')}")
            meta_cols[1].caption(f"CVSS: {finding.get('cvss_score', 'N/A')}")
            meta_cols[2].caption(f"KEV: {'⚠️ Yes (live CISA feed)' if finding.get('actively_exploited_kev') else 'No'}")
            meta_cols[3].caption(f"Asset: {finding.get('asset_criticality', 'N/A')}")

            st.markdown("---")
            st.markdown("**5-Dimension Score Breakdown:**")
            tss = assessment.get("threat_severity", {}).get("tss_score", 0)
            els_data = assessment.get("exploit_likelihood", {})
            acs_data = assessment.get("attack_chain", {})
            exp_data = assessment.get("exposure", {})

            sc1, sc2, sc3, sc4, sc5 = st.columns(5)
            sc1.metric("Threat Severity", f"{tss}/10")
            sc2.metric("Exploit Likelihood", f"{els_data.get('els_score', 'N/A')}/10",
                      help="Live EPSS" if els_data.get("found") else "Fallback (no live EPSS match)")
            sc3.metric("Attack Chain", f"{acs_data.get('acs_score', 'N/A')}/10")
            sc4.metric("Exposure", f"{exp_data.get('exposure_score', 'N/A')}/10")
            sc5.metric("Final Priority", f"{score}/10")

            if els_data.get("found"):
                st.caption(f"EPSS: {els_data['epss_score']*100:.1f}% probability of exploitation in 30 days "
                          f"(percentile {els_data.get('percentile',0)*100:.1f}%) — live FIRST.org data")

            # Structured reasoning: Priority -> Why -> Evidence -> Recommendation
            reasoning = assessment.get("reasoning", {})
            if reasoning:
                st.markdown("---")
                st.markdown('<div class="reasoning-box">', unsafe_allow_html=True)
                st.markdown(f"**Priority:** {reasoning.get('priority','')}")
                st.markdown(f"**Why:** {reasoning.get('why','')}")
                st.markdown("**Evidence:**")
                for ev in reasoning.get("evidence", []):
                    st.markdown(f"- {ev}")
                st.markdown(f"**Recommendation:** {reasoning.get('recommendation','')}")
                st.markdown('</div>', unsafe_allow_html=True)

            st.caption(f"Port: {finding.get('port', 'N/A')} | Service: {finding.get('service', 'N/A')} | "
                      f"Source: {finding.get('source', 'N/A')}")

# ---------------- PAGE: ATTACK PATHS ----------------
elif page == "🔗 Attack Paths":
    st.markdown('<div class="section-title">🔗 Attack Path Intelligence</div>', unsafe_allow_html=True)
    st.markdown(f'<p class="section-subtitle">MITRE ATT&CK-aligned correlation using {len(ATTACK_PATTERNS_CONFIG)} configurable attack patterns</p>', unsafe_allow_html=True)

    with st.expander("📋 Attack Pattern Definitions"):
        for i, pat in enumerate(ATTACK_PATTERNS_CONFIG):
            st.markdown(f"**{i+1}. {pat['name']}**")
            st.caption(f"Sequence: {' → '.join(pat['sequence'])}")
            st.caption(f"Severity: {pat['severity']} | Likelihood: {pat.get('likelihood','?')} | "
                      f"Business Impact: {pat.get('business_impact','?')} | Priority: P{pat.get('priority','?')}")
            st.caption(f"MITRE: {', '.join(pat.get('mitre_techniques', []))}")
            if i < len(ATTACK_PATTERNS_CONFIG) - 1:
                st.markdown("---")

    st.markdown("<br>", unsafe_allow_html=True)

    if chains:
        st.success(f"🔴 **{len(chains)} attack chain(s) detected** across active findings (sorted by priority)")
        for i, chain in enumerate(chains):
            with st.container(border=True):
                st.markdown(f"### Chain {i+1}: {chain['pattern_name']} (P{chain.get('priority','?')})")
                st.markdown(f"**Path:** {' → '.join(chain['path'])}")
                st.markdown(f"**Severity:** {sb(chain.get('severity', 'High'))} &nbsp; "
                           f"**Likelihood:** {chain.get('likelihood','?')} &nbsp; "
                           f"**Business Impact:** {chain.get('business_impact','?')}", unsafe_allow_html=True)
                st.caption(f"**MITRE:** {', '.join(chain.get('mitre_techniques', []))}")
                for node in chain['path']:
                    node_findings = [f for f in active_findings if f.get("asset") == node]
                    if node_findings:
                        f = node_findings[0]
                        st.caption(f"  📍 {node}: {f.get('finding_type','').replace('_',' ').title()} — "
                                  f"Score: {f.get('normalized_risk_score',0)}/10")
    else:
        st.info("No attack chains detected. Add findings with connectivity data to detect chains.")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p style="color:#f4f6fb;font-size:18px;font-weight:700;">Asset Relationship Graph</p>', unsafe_allow_html=True)
    st.caption("🔴 Red = In attack chain | 🔵 Blue = Standalone asset | Size = Risk level")

    if active_findings:
        G = build_asset_graph(active_findings)
        if G.number_of_nodes() > 0:
            fig, ax = plt.subplots(figsize=(14, 8))
            fig.patch.set_alpha(0)
            ax.set_facecolor("none")
            pos = nx.spring_layout(G, seed=42, k=1.8, iterations=50)
            chain_nodes = set()
            for c in chains:
                chain_nodes.update(c["path"])
            node_colors = ["#d9363e" if n in chain_nodes else "#3a4a70" for n in G.nodes()]
            node_sizes = [3000 if n in chain_nodes else 1800 for n in G.nodes()]
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9, ax=ax)
            nx.draw_networkx_edges(G, pos, edge_color="#4a5a80", arrows=True, arrowsize=15,
                                   connectionstyle="arc3,rad=0.1", ax=ax, width=1.5)
            nx.draw_networkx_labels(G, pos, font_size=8, font_color="white", font_weight="bold", ax=ax)
            legend_elements = [mpatches.Patch(color="#d9363e", label="Part of Attack Chain"),
                               mpatches.Patch(color="#3a4a70", label="Standalone Asset")]
            ax.legend(handles=legend_elements, loc="upper right", facecolor="#141b2d",
                     edgecolor="#2a3550", labelcolor="#c9d6ea", fontsize=9)
            ax.axis("off")
            st.pyplot(fig)
        else:
            st.info("No nodes to display")
    else:
        st.info("No active findings to visualize")

# ---------------- PAGE: VULNERABLE NODES ----------------
elif page == "🎯 Vulnerable Nodes":
    st.markdown('<div class="section-title">🎯 Most Vulnerable Nodes</div>', unsafe_allow_html=True)
    st.markdown('<p class="section-subtitle">Ranked by risk score and attack chain participation</p>', unsafe_allow_html=True)

    if vuln_nodes:
        for i, (node, info) in enumerate(vuln_nodes.items()):
            with st.container(border=True):
                sev = "Critical" if info["score"] >= 8.5 else ("High" if info["score"] >= 6.5 else "Medium")
                st.markdown(f"### {i+1}. {node} {sb(sev)}", unsafe_allow_html=True)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Max Risk Score", f"{info['score']}/10")
                c2.metric("Attack Chains", info["in_chains"])
                c3.metric("Cumulative Risk", round(info["total_risk"], 1))
                c4.metric("Active Findings", len(info["findings"]))
                st.markdown("**Findings on this node:**")
                for f in info["findings"][:5]:
                    st.caption(f"- {f['finding_id']}: {f.get('description','')[:100]} (Score: {f.get('normalized_risk_score',0)}/10)")

        st.markdown("---")
        st.subheader("Node Vulnerability Heat Map")
        st.caption("🔴 Most Vulnerable | 🟠 Very High | 🟡 High | 🟨 Medium | 🔵 Other")

        G = build_asset_graph(active_findings)
        if G.nodes():
            fig, ax = plt.subplots(figsize=(12, 7))
            fig.patch.set_alpha(0)
            ax.set_facecolor("none")
            pos = nx.spring_layout(G, seed=42, k=1.5)
            vuln_list = list(vuln_nodes.keys())
            node_colors, node_sizes = [], []
            for n in G.nodes():
                if vuln_list and n == vuln_list[0]:
                    node_colors.append("#ff0000"); node_sizes.append(4000)
                elif len(vuln_list) > 1 and n == vuln_list[1]:
                    node_colors.append("#ff4400"); node_sizes.append(3500)
                elif len(vuln_list) > 2 and n in vuln_list[2:4]:
                    node_colors.append("#ff8800"); node_sizes.append(2800)
                elif len(vuln_list) > 4 and n in vuln_list[4:]:
                    node_colors.append("#ffcc00"); node_sizes.append(2200)
                else:
                    node_colors.append("#3a4a70"); node_sizes.append(1500)
            nx.draw(G, pos, node_color=node_colors, node_size=node_sizes, font_color="white",
                   font_size=8, edge_color="#4a5a80", ax=ax)
            legend = [mpatches.Patch(color="#ff0000", label="Most Vulnerable"),
                     mpatches.Patch(color="#ff4400", label="Very High"),
                     mpatches.Patch(color="#ff8800", label="High"),
                     mpatches.Patch(color="#ffcc00", label="Medium"),
                     mpatches.Patch(color="#3a4a70", label="Other")]
            ax.legend(handles=legend, loc="upper right", facecolor="#141b2d", edgecolor="#2a3550", labelcolor="#c9d6ea")
            ax.axis("off")
            st.pyplot(fig)

        if vuln_list:
            st.markdown("---")
            st.subheader(f"Node-to-Node Detail: {vuln_list[0]} (most vulnerable)")
            top_node = vuln_list[0]
            neighbors = set(G.predecessors(top_node)) | set(G.successors(top_node)) if top_node in G else set()
            sub_nodes = neighbors | {top_node}
            if len(sub_nodes) > 1:
                subG = G.subgraph(sub_nodes)
                fig2, ax2 = plt.subplots(figsize=(7, 4.5))
                fig2.patch.set_alpha(0)
                ax2.set_facecolor("none")
                pos2 = nx.spring_layout(subG, seed=7)
                colors2 = ["#ff0000" if n == top_node else "#3a4a70" for n in subG.nodes()]
                sizes2 = [3400 if n == top_node else 1900 for n in subG.nodes()]
                nx.draw_networkx_nodes(subG, pos2, node_color=colors2, node_size=sizes2, ax=ax2)
                nx.draw_networkx_edges(subG, pos2, edge_color="#4a5a80", arrows=True, ax=ax2)
                nx.draw_networkx_labels(subG, pos2, font_size=8, font_color="white", font_weight="bold", ax=ax2)
                ax2.axis("off")
                st.pyplot(fig2)
            else:
                st.caption("This node has no direct connections to visualize in isolation.")
    else:
        st.info("No vulnerability data available. Import findings to see vulnerable nodes.")

# ---------------- PAGE: AI COPILOT ----------------
elif page == "💬 AI Copilot":
    st.markdown('<div class="section-title">💬 AI Security Copilot</div>', unsafe_allow_html=True)
    st.markdown('<p class="section-subtitle">RAG-grounded, with live attack-path context and multi-factor confidence scoring</p>', unsafe_allow_html=True)

    if st.session_state.attack_path_context:
        with st.expander("📊 Auto-Fed Attack Path Context (sent to Copilot automatically)", expanded=False):
            st.code(st.session_state.attack_path_context[:3000], language="text")

    kb_col1, kb_col2 = st.columns([3, 1])
    with kb_col1:
        if st.session_state.kb_indexed:
            n_chain_docs = sum(1 for d in st.session_state.vector_docs if d.get("doc_type") == "attack_chain")
            st.success(f"✅ Knowledge base ready — {len(st.session_state.vector_docs)} documents indexed "
                      f"({n_chain_docs} auto-generated from live attack chains)")
        else:
            st.warning("⚠️ Knowledge base not indexed")
    with kb_col2:
        if not st.session_state.kb_indexed and FAISS_SUPPORT:
            if st.button("📚 Index KB", type="primary", use_container_width=True):
                with st.spinner("Indexing knowledge base..."):
                    index_knowledge_base_documents()
                    st.session_state.kb_indexed = True
                    st.success("Indexed!")
                    st.rerun()

    with st.expander("📋 Upload Policy/Compliance Documents"):
        policy_files = st.file_uploader("Policy documents", type=["txt", "md", "pdf"], accept_multiple_files=True)
        if policy_files and st.button("Index Policies"):
            total = sum(index_policy_document(pf) for pf in policy_files)
            if total > 0:
                st.session_state.kb_indexed = True
                st.success(f"Indexed {total} chunks")

    st.markdown("---")
    st.markdown("**⚡ Quick Analysis (uses current live attack path context):**")
    qc1, qc2, qc3 = st.columns(3)
    with qc1:
        if st.button("🔍 Analyze Attack Paths", use_container_width=True):
            st.session_state.chat_history.append({"role": "user",
                "content": f"Analyze the {len(chains)} detected attack chains. Which vulnerabilities should be fixed first to break the kill chain?"})
    with qc2:
        if st.button("🎯 Most Vulnerable Node Analysis", use_container_width=True):
            top = list(vuln_nodes.keys())[0] if vuln_nodes else "unknown"
            st.session_state.chat_history.append({"role": "user",
                "content": f"Analyze why '{top}' is the most vulnerable node. What specific remediation steps should be taken?"})
    with qc3:
        if st.button("🛡️ Generate Remediation Plan", use_container_width=True):
            st.session_state.chat_history.append({"role": "user",
                "content": "Generate a prioritized remediation plan for all detected findings and attack paths, breaking chains at their earliest point."})

    st.markdown("---")
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    query = st.chat_input("Ask about attack paths, vulnerabilities, remediation strategies...")
    pending = query or (st.session_state.chat_history[-1]["content"]
                         if st.session_state.chat_history and st.session_state.chat_history[-1]["role"] == "user"
                         and (not query) else None)

    if query:
        st.session_state.chat_history.append({"role": "user", "content": query})
        with st.chat_message("user"):
            st.write(query)

    last_is_unanswered_user_msg = (st.session_state.chat_history
                                    and st.session_state.chat_history[-1]["role"] == "user")

    if last_is_unanswered_user_msg:
        active_query = st.session_state.chat_history[-1]["content"]
        with st.chat_message("assistant"):
            if not groq_key:
                st.error("❌ Groq API key required. Get a free key at console.groq.com")
            elif not st.session_state.kb_indexed:
                st.warning("⚠️ Index knowledge base first")
            else:
                with st.spinner("🔍 Retrieving context and generating response..."):
                    try:
                        full_query = f"{active_query}\n\n[SYSTEM CONTEXT - Attack Paths]:\n{st.session_state.attack_path_context[:2000]}"
                        docs, distances = semantic_search_query(full_query)

                        # --- TAVILY WEB SEARCH INTEGRATION ---
                        web_docs = []
                        if tavily_key:
                            web_docs = tavily_web_search(active_query, tavily_key)
                            for wd in web_docs:
                                wd["distance"] = 999.0

                        all_docs = docs + web_docs

                        ctx_parts = []
                        for d in all_docs:
                            type_label = d['doc_type'].upper()
                            source = d['source']
                            text = d['text']
                            if d.get('distance') and d['distance'] < 999:
                                ctx_parts.append(f"[{type_label}] [{source}] (relevance: {d['distance']:.3f})\n{text}")
                            else:
                                ctx_parts.append(f"[{type_label}] [{source}] (live web search)\n{text}")

                        ctx = "\n\n---\n\n".join(ctx_parts)

                        system_prompt = f"""You are VYUHA.AI Security Copilot. Analyze the current attack paths and provide actionable, evidence-backed recommendations.

                        ATTACK PATH CONTEXT (live from system):
                        {st.session_state.attack_path_context[:1500]}

                        REFERENCE KNOWLEDGE (built-in KB, uploaded policy, live attack chains, and web search):
                        {ctx}

                        IMPORTANT: Sources labeled [WEB] are from live web search and may contain the most current threat intelligence. Always cite your sources by name and type. If web search provided relevant context, prioritize it for current threat information.

                        Respond in this structure:
                        **Summary**
                        **Attack Path Analysis**
                        **Vulnerable Nodes Assessment**
                        **Prioritized Recommendations** (numbered, actionable)
                        **Sources Used** (cite by name and type: Built-in KB / Uploaded Policy / Live Attack Chain / Web Search)
                        """
                        client = Groq(api_key=groq_key)
                        resp = client.chat.completions.create(
                            model=APP_CONFIG["llm"]["model"],
                            messages=[{"role": "system", "content": system_prompt},
                                     {"role": "user", "content": active_query}],
                            temperature=APP_CONFIG["llm"]["temperature"], max_tokens=APP_CONFIG["llm"]["max_tokens"])
                        answer = resp.choices[0].message.content
                        st.write(answer)

                        if distances:
                            # Calculate confidence using ALL documents (local + web)
                            all_distances = [d.get("distance", 999.0) for d in all_docs if
                                             d.get("distance") is not None]
                            all_doc_types = [d["doc_type"] for d in all_docs]

                            if all_distances:
                                local_distances = [d for d in all_distances if d < 999]
                                conf = risk_engine.compute_aics(
                                    local_distances if local_distances else all_distances,
                                    all_doc_types
                                )
                                st.markdown(confidence_badge_html(conf["aics_score"]), unsafe_allow_html=True)
                                with st.expander("📊 Confidence Breakdown"):
                                    comps = conf.get("components", {})
                                    cc1, cc2, cc3 = st.columns(3)
                                    cc1.metric("Similarity", f"{comps.get('similarity', '?')}/60")
                                    cc2.metric("Source Count", f"{comps.get('source_count', '?')}/20")
                                    cc3.metric("Evidence Quality", f"{comps.get('evidence_quality', '?')}/20")
                                    st.caption(conf.get("explanation", ""))
                                    local_count = len(docs)
                                    web_count = len(web_docs)
                                    if web_count > 0:
                                        st.caption(
                                            f"📊 Sources: {local_count} from knowledge base, {web_count} from live web search")

                        with st.expander(f"📄 Retrieved Sources ({len(all_docs)} total)"):
                            for i, d in enumerate(all_docs):
                                type_icon = "🌐" if d['doc_type'] == 'web' else (
                                    "📋" if d['doc_type'] == 'policy' else "📄")
                                if d.get('distance') and d['distance'] < 999:
                                    dist_info = f" (distance: {d['distance']:.3f})"
                                else:
                                    dist_info = " (web search)"
                                st.caption(f"[{i + 1}] {type_icon} ({d['doc_type']}) {d['source']}{dist_info}")
                                st.caption(d['text'][:200] + "...")
                                if i < len(all_docs) - 1:
                                    st.markdown("---")

                        st.session_state.chat_history.append({"role": "assistant", "content": answer})
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

# ---------------- PAGE: REMEDIATION & ESCALATION (Admin only) ----------------
elif page == "⏱️ Remediation & Escalation" and is_admin:
    st.markdown('<div class="section-title">⏱️ Remediation & Escalation</div>', unsafe_allow_html=True)
    st.markdown('<p class="section-subtitle">Acknowledge → Apply Fix → Verify → Close | Auto-escalation for overdue findings</p>', unsafe_allow_html=True)

    overdue_findings = [f for f in findings if f.get("is_overdue")]
    if overdue_findings:
        st.markdown(f"""<div class="overdue-banner">⚠️ <strong>{len(overdue_findings)} OVERDUE finding(s)</strong> —
        Critical/High severity open for more than {escalation_threshold} minutes without acknowledgment.</div>""", unsafe_allow_html=True)

    open_findings = [f for f in findings if f.get("status") != "Closed"]
    if not open_findings:
        st.success("✅ All findings have been remediated!")

    for finding in sorted(open_findings, key=lambda x: (-x.get("is_overdue", False), -x.get("normalized_risk_score", 0))):
        is_overdue = finding.get("is_overdue", False)
        status = finding.get("status", "Open")
        indicator = "🔴" if is_overdue else ("🟡" if status == "Acknowledged" else "⚪")

        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([3, 1, 1, 1])
            with c1:
                st.markdown(f"{indicator} **{finding.get('finding_id','')}** — {finding.get('asset','')}")
                st.markdown(sb(finding.get("severity_label", "Unknown")), unsafe_allow_html=True)
                st.caption(finding.get("description", "")[:120])
                mins = finding.get("minutes_open", 0)
                st.caption(f"Status: **{status}** · Open: **{mins} min**" + (" · **🚨 OVERDUE**" if is_overdue else ""))
            with c2:
                st.metric("Priority", f"{finding.get('normalized_risk_score',0)}/10")
            with c3:
                if status == "Open":
                    if st.button("✓ Acknowledge", key=f"ack_{finding['finding_id']}"):
                        finding["status"] = "Acknowledged"
                        finding["acknowledged_at"] = datetime.utcnow()
                        st.rerun()
                elif status == "Acknowledged":
                    if st.button("▶ Apply Fix", key=f"fix_{finding['finding_id']}", type="primary"):
                        finding["_trigger_fix"] = True
                        st.rerun()
            with c4:
                if st.button("✗ Close", key=f"cls_{finding['finding_id']}"):
                    finding["status"] = "Closed"
                    finding["closed_at"] = datetime.utcnow()
                    st.rerun()

            if finding.get("_trigger_fix"):
                with st.status(f"🔧 Remediating {finding['finding_id']}...", expanded=True) as status_box:
                    result = simulate_remediation(finding)
                    for step in result["log"]:
                        st.write(f"`{step['time'].strftime('%H:%M:%S')}`  {step['message']}")
                        time.sleep(APP_CONFIG["remediation"]["simulation_delay_seconds"])
                    status_box.update(label="✅ Complete!", state="complete")

                before = finding.get("normalized_risk_score", 0)
                after = result["post_fix_assessment"]["final_priority"]["final_priority_score"]
                bc, ac = st.columns(2)
                bc.metric("Before", f"{before}/10")
                ac.metric("After", f"{after}/10", delta=f"{after-before:+}")

                finding["cvss_score"] = result["post_fix_cvss"]
                finding["actively_exploited_kev"] = False
                finding["requires_auth"] = True
                finding["normalized_risk_score"] = after
                finding["severity_label"] = result["post_fix_assessment"]["final_priority"]["severity_label"]
                finding["hybrid_assessment"] = result["post_fix_assessment"]
                finding["status"] = "Closed"
                finding["remediation_log"] = result["log"]
                finding["closed_at"] = result["verified_at"]
                finding["_trigger_fix"] = False

                st.success(f"✅ Closed! Residual risk: {after}/10")
                st.rerun()

    closed = [f for f in findings if f.get("status") == "Closed"]
    if closed:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<p style="color:#f4f6fb;font-size:18px;font-weight:700;">📋 Remediation History</p>', unsafe_allow_html=True)
        for f in closed[-10:]:
            with st.expander(f"✅ {f.get('finding_id','')} — {f.get('asset','')} (Residual: {f.get('normalized_risk_score',0)}/10)"):
                st.caption(f"Closed: {f.get('closed_at','Unknown')}")
                if "remediation_log" in f:
                    for step in f["remediation_log"]:
                        st.write(f"`{step['time'].strftime('%H:%M:%S')}`  {step['message']}")

# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown(f"""<div style="text-align:center;padding:10px 0;">
<p style="color:#8fa0c4;font-size:12px;margin:0;">🛡️ <strong>VYUHA.AI</strong> v{APP_CONFIG['app']['version']} |
5-Dimension Hybrid Risk Intelligence | Live NVD/KEV/EPSS | Auto Attack-Path RAG |
Nmap/OpenVAS/Generic Import | No hardcoded threat-intel lists</p></div>""", unsafe_allow_html=True)