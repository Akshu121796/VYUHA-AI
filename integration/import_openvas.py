"""
VYUHA.AI — OpenVAS / Greenbone (GVM) XML report importer.

Mirrors import_nmap.py's structure and env vars exactly, so it drops into
the same integration module with no new setup:

    OpenVAS XML  -->  parse  -->  match/verify against NVD + CISA KEV  -->  Supabase (assets, findings)

Standard GVM "Full and fast" XML report export shape (the common case):

    <report>
      <results>
        <result>
          <host>10.0.0.5</host>
          <port>443/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.xxxxx">
            <name>...</name>
            <cvss_base>7.5</cvss_base>
            <cve>CVE-2021-41773</cve>
            <family>...</family>
          </nvt>
          <threat>High</threat>
          <severity>7.5</severity>
          <description>...</description>
        </result>
      </results>
    </report>

Real-world exports vary a lot (different GVM versions, omp -X vs gvm-cli,
custom filters), so this parser is deliberately lenient:
  - <cve> may hold multiple comma/space-separated IDs, "NOCVE", or be empty
  - <cvss_base> / <severity> may both exist, be 0.0, or be absent
  - <host> is sometimes a plain string, sometimes has an @asset id attribute
Run it directly against a raw file export from the GVM web UI or `gvm-cli`
without any manual cleanup first.
"""

import os
import sys
import time
import xml.etree.ElementTree as ET
from supabase import create_client
from dotenv import load_dotenv
import requests
from classifier import classify_vuln

load_dotenv()

supabase = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SECRET_ROLE_KEY"]
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

THREAT_TO_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Log": "low",
}


def get_kev_ids():
    print("Fetching CISA KEV list...")
    r = requests.get(KEV_URL)
    ids = {v["cveID"] for v in r.json()["vulnerabilities"]}
    print(f"Loaded {len(ids)} KEV entries")
    return ids


def fetch_nvd(cve_id, kev_ids):
    """Same shape/behaviour as import_nmap.py's fetch_nvd — kept identical
    on purpose so both importers write consistent finding records."""
    url = NVD_URL
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    r = requests.get(url, params={"cveId": cve_id}, headers=headers)
    if r.status_code != 200:
        print(f"  ✗ Failed {cve_id} (status {r.status_code})")
        return None

    data = r.json()
    if not data.get("vulnerabilities"):
        print(f"  ✗ No NVD data for {cve_id}")
        return None

    vuln = data["vulnerabilities"][0]["cve"]
    metrics = vuln.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    cvss_score = cvss_list[0]["cvssData"]["baseScore"] if cvss_list else 5.0

    if cvss_score >= 9.0:   severity = "critical"
    elif cvss_score >= 7.0: severity = "high"
    elif cvss_score >= 4.0: severity = "medium"
    else:                   severity = "low"

    is_kev = cve_id in kev_ids
    risk_score = round(cvss_score + (2.0 if is_kev else 0), 2)

    return {
        "cve_id":      cve_id,
        "cvss_score":  cvss_score,
        "severity":    severity,
        "is_kev":      is_kev,
        "risk_score":  risk_score,
        "description": vuln["descriptions"][0]["value"]
    }


def _clean_cve_field(raw: str):
    """<cve> can be 'CVE-2021-41773', 'CVE-2021-41773, CVE-2021-42013',
    'NOCVE', or empty. Return a clean list of real CVE IDs only."""
    if not raw:
        return []
    ids = []
    for tok in raw.replace(",", " ").split():
        tok = tok.strip().upper()
        if tok.startswith("CVE-"):
            ids.append(tok)
    return ids


def parse_openvas_xml(filepath):
    print(f"\nParsing {filepath}...")
    tree = ET.parse(filepath)
    root = tree.getroot()

    # Some exports wrap results in <report><report>...(nested)...</report></report>
    # (this is a known GVM quirk depending on export path) — handle both.
    results = root.findall(".//results/result")
    print(f"  Found {len(results)} result entries")

    hosts = {}  # ip -> {hostname, findings: [...]}

    for result in results:
        host_el = result.find("host")
        ip = (host_el.text or "unknown").strip() if host_el is not None else "unknown"
        hostname_attr = host_el.get("hostname") if host_el is not None else None
        hostname = hostname_attr or ip

        threat_el = result.find("threat")
        threat = threat_el.text.strip() if threat_el is not None and threat_el.text else "Log"

        # Skip informational "Log" entries with no real severity — same
        # convention as import_nmap.py only recording open/actionable ports.
        if threat == "Log":
            continue

        severity_el = result.find("severity")
        cvss_from_report = None
        if severity_el is not None and severity_el.text:
            try:
                cvss_from_report = float(severity_el.text)
            except ValueError:
                pass

        nvt_el = result.find("nvt")
        nvt_name = "unknown"
        cve_ids = []
        if nvt_el is not None:
            name_el = nvt_el.find("name")
            nvt_name = (name_el.text or "unknown").strip() if name_el is not None else "unknown"

            cve_el = nvt_el.find("cve")
            if cve_el is not None and cve_el.text:
                cve_ids = _clean_cve_field(cve_el.text)

            if not cvss_from_report:
                cvss_el = nvt_el.find("cvss_base")
                if cvss_el is not None and cvss_el.text:
                    try:
                        cvss_from_report = float(cvss_el.text)
                    except ValueError:
                        pass

        port_el = result.find("port")
        port = port_el.text.strip() if port_el is not None and port_el.text else "general/tcp"

        desc_el = result.find("description")
        description = (desc_el.text or "").strip() if desc_el is not None else ""

        if ip not in hosts:
            hosts[ip] = {"ip": ip, "hostname": hostname, "findings": []}

        hosts[ip]["findings"].append({
            "nvt_name": nvt_name,
            "cve_ids": cve_ids,
            "cvss_from_report": cvss_from_report,
            "threat": threat,
            "port": port,
            "description": description,
        })
        label = ", ".join(cve_ids) if cve_ids else "no CVE listed"
        print(f"  [{ip}] {threat} — {nvt_name} ({label})")

    return list(hosts.values())


def run_import(xml_path):
    kev_ids = get_kev_ids()
    hosts = parse_openvas_xml(xml_path)

    if not hosts:
        print("No actionable results found in XML.")
        return

    total = 0

    for host in hosts:
        print(f"\nProcessing host: {host['hostname']} ({host['ip']})")

        existing = supabase.table("assets") \
            .select("id") \
            .eq("ip_address", host["ip"]) \
            .execute()

        if existing.data:
            asset_id = existing.data[0]["id"]
            print(f"  Asset already exists — reusing id: {asset_id}")
        else:
            result = supabase.table("assets").insert({
                "hostname":    host["hostname"],
                "ip_address":  host["ip"],
                "os_type":     "Unknown",
                "criticality": "high"
            }).execute()
            asset_id = result.data[0]["id"]
            print(f"  Asset created — id: {asset_id}")

        for finding in host["findings"]:
            if finding["cve_ids"]:
                # Real CVE(s) reported by OpenVAS — verify + enrich via NVD/KEV,
                # same as import_nmap.py's flow.
                for cve_id in finding["cve_ids"]:
                    dup = supabase.table("findings") \
                        .select("id") \
                        .eq("cve_id", cve_id) \
                        .eq("asset_id", asset_id) \
                        .execute()
                    if dup.data:
                        print(f"  [WARN] Duplicate - skipping {cve_id}")
                        continue

                    print(f"  Fetching {cve_id} from NVD...")
                    cve_data = fetch_nvd(cve_id, kev_ids)
                    if not cve_data:
                        # NVD lookup failed — still record the finding using
                        # OpenVAS's own CVSS so we don't silently drop it.
                        cve_data = {
                            "cve_id": cve_id,
                            "cvss_score": finding["cvss_from_report"] or 5.0,
                            "severity": THREAT_TO_SEVERITY.get(finding["threat"], "medium"),
                            "is_kev": cve_id in kev_ids,
                            "risk_score": finding["cvss_from_report"] or 5.0,
                            "description": finding["description"][:500] or finding["nvt_name"],
                        }

                    vuln_category = classify_vuln(
                        supabase,
                        description=cve_data.get("description"),
                        service_name=finding.get("port"),
                        title=finding.get("nvt_name") or cve_id
                    )
                    supabase.table("findings").insert({
                        "asset_id": asset_id,
                        "vuln_category": vuln_category,
                        **cve_data
                    }).execute()
                    print(f"  [OK] {cve_id} | {cve_data['severity'].upper()} | "
                          f"CVSS: {cve_data['cvss_score']} | KEV: {cve_data['is_kev']}")
                    total += 1
                    time.sleep(0.6)  # NVD rate limit — do not remove
            else:
                # No CVE attached (misconfig / weak-cred / generic NVT finding).
                # Still worth recording — vuln_category_rules keyword-matches
                # nvt_name/description downstream, no CVE required.
                cvss = finding["cvss_from_report"] or {
                    "Critical": 9.0, "High": 7.5, "Medium": 5.0, "Low": 2.0
                }.get(finding["threat"], 5.0)

                desc = f"{finding['nvt_name']}: {finding['description'][:400]}"
                vuln_category = classify_vuln(
                    supabase,
                    description=finding.get("description"),
                    service_name=finding.get("port"),
                    title=finding.get("nvt_name")
                )
                supabase.table("findings").insert({
                    "asset_id": asset_id,
                    "cve_id": None,
                    "cvss_score": cvss,
                    "severity": THREAT_TO_SEVERITY.get(finding["threat"], "medium"),
                    "is_kev": False,
                    "risk_score": cvss,
                    "description": desc,
                    "vuln_category": vuln_category,
                }).execute()
                print(f"  [OK] {finding['nvt_name']} | {finding['threat'].upper()} | no CVE (NVT finding)")
                total += 1

    print(f"\n[INFO] Done - {total} findings inserted")
    print("Go to Supabase -> Table Editor -> findings to verify")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_openvas.py <path_to_openvas_report.xml>")
        sys.exit(1)
    run_import(sys.argv[1])
