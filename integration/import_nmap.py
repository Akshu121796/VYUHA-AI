import xml.etree.ElementTree as ET
import requests
import os
import sys
from supabase import create_client
from dotenv import load_dotenv
import time
from classifier import classify_vuln

load_dotenv()

supabase_key = os.environ.get("SUPABASE_SECRET_ROLE_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
if not supabase_key:
    raise ValueError("Missing Supabase Service/Secret Role Key in environment variables.")

supabase = create_client(
    os.environ["SUPABASE_URL"],
    supabase_key
)

VERSION_CVE_MAP = {
    "Apache httpd 2.4.49":  ["CVE-2021-41773", "CVE-2021-42013"],
    "OpenSSH 7.4":          ["CVE-2023-38408", "CVE-2018-15473"],
    "MySQL 5.7.32":         ["CVE-2021-2307",  "CVE-2020-14765"],
    "SimpleHTTPServer 0.6": ["CVE-2024-21762", "CVE-2023-44487"],  
}

def get_kev_ids():
    print("Fetching CISA KEV list...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=7)
        ids = {v["cveID"] for v in r.json()["vulnerabilities"]}
        print(f"Loaded {len(ids)} KEV entries")
        return ids
    except Exception as e:
        print(f"  [WARN] Failed to fetch CISA KEV list: {e}. Fallback to empty list.")
        return set()

def fetch_nvd(cve_id, kev_ids):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    try:
        r = requests.get(url, headers=headers, timeout=7)
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
    except Exception as e:
        print(f"  [WARN] Failed to fetch NVD details for {cve_id}: {e}. Using fallback defaults.")
        is_kev = cve_id in kev_ids
        cvss_score = 7.5
        risk_score = round(cvss_score + (2.0 if is_kev else 0), 2)
        return {
            "cve_id":      cve_id,
            "cvss_score":  cvss_score,
            "severity":    "high",
            "is_kev":      is_kev,
            "risk_score":  risk_score,
            "description": f"Security vulnerability {cve_id}."
        }

def parse_nmap_xml(filepath):
    print(f"\nParsing {filepath}...")
    tree = ET.parse(filepath)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        # get IP
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"

        # get hostname
        hostname_el = host.find(".//hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ip

        # get open services only
        services = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                svc = port.find("service")
                if svc is not None:
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    service_str = f"{product} {version}".strip()
                    port_num = port.get("portid")
                    if service_str:
                        services.append(service_str)
                        print(f"  Open port {port_num}: {service_str}")

        hosts.append({"ip": ip, "hostname": hostname, "services": services})

    return hosts

def run_import(xml_path):
    kev_ids = get_kev_ids()
    hosts = parse_nmap_xml(xml_path)

    if not hosts:
        print("No hosts found in XML.")
        return

    total = 0

    for host in hosts:
        print(f"\nProcessing host: {host['hostname']} ({host['ip']})")

        # avoid duplicate assets
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
                "os_type":     "Linux",     
                "criticality": "high"
            }).execute()
            asset_id = result.data[0]["id"]
            print(f"  Asset created — id: {asset_id}")

        if not host["services"]:
            print("  No open services found on this host")
            continue

        for service in host["services"]:
            inserted_any = False
            matched_cves = []

            for version_string, cves in VERSION_CVE_MAP.items():
                if version_string.lower() == service.lower():
                    matched_cves.extend(cves)
                    print(f"  Matched '{version_string}' -> {cves}")

            if matched_cves:
                for cve_id in matched_cves:
                    print(f"  Fetching {cve_id} from NVD...")
                    cve_data = fetch_nvd(cve_id, kev_ids)

                    if cve_data:
                        dup = supabase.table("findings") \
                            .select("id") \
                            .eq("cve_id", cve_id) \
                            .eq("asset_id", asset_id) \
                            .execute()
                        if dup.data:
                            print(f"  [WARN] Duplicate - skipping {cve_id}")
                            # Consider a duplicate as a "successful" lookup so we don't duplicate via fallback
                            inserted_any = True
                        else:
                            vuln_category = classify_vuln(
                                supabase,
                                description=cve_data.get("description"),
                                service_name=service,
                                title=cve_id
                            )
                            supabase.table("findings").insert({
                                "asset_id": asset_id,
                                "vuln_category": vuln_category,
                                **cve_data
                            }).execute()
                            print(f"  [OK] {cve_id} | "
                                  f"{cve_data['severity'].upper()} | "
                                  f"CVSS: {cve_data['cvss_score']} | "
                                  f"KEV: {cve_data['is_kev']} | "
                                  f"Risk: {cve_data['risk_score']}")
                            total += 1
                            inserted_any = True

                    time.sleep(0.6)  # NVD rate limit — do not remove

            if not inserted_any:
                # Vulnerability data is absent — check local mappings
                svc_lower = service.lower()
                inferred_finding = None

                if "apache httpd 2.4.49" in svc_lower:
                    inferred_finding = {
                        "cve_id": "CVE-2021-41773",
                        "cvss_score": 9.8,
                        "severity": "high",
                        "is_kev": True,
                        "risk_score": 11.8,
                        "description": "Apache httpd 2.4.49: Path Traversal and File Disclosure vulnerability.",
                        "vuln_category": "unpatched_service"
                    }
                elif "mysql 5.7" in svc_lower:
                    inferred_finding = {
                        "cve_id": None,
                        "cvss_score": 7.5,
                        "severity": "high",
                        "is_kev": False,
                        "risk_score": 7.5,
                        "description": "Outdated Database: MySQL 5.7.x detected. The database software has reached End of Life (EOL) and contains multiple unpatched security issues.",
                        "vuln_category": "outdated_database"
                    }
                elif "openssh 7." in svc_lower:
                    inferred_finding = {
                        "cve_id": None,
                        "cvss_score": 5.0,
                        "severity": "medium",
                        "is_kev": False,
                        "risk_score": 5.0,
                        "description": "Weak SSH Version: OpenSSH 7.x detected. Outdated SSH server package with known security risks.",
                        "vuln_category": "weak_service"
                    }

                if inferred_finding:
                    # Check duplicate
                    if inferred_finding["cve_id"]:
                        dup = supabase.table("findings") \
                            .select("id") \
                            .eq("cve_id", inferred_finding["cve_id"]) \
                            .eq("asset_id", asset_id) \
                            .execute()
                    else:
                        dup = supabase.table("findings") \
                            .select("id") \
                            .eq("vuln_category", inferred_finding["vuln_category"]) \
                            .eq("asset_id", asset_id) \
                            .execute()

                    if dup.data:
                        label = inferred_finding["cve_id"] or inferred_finding["description"][:30]
                        print(f"  [WARN] Duplicate - skipping inferred finding: {label}")
                    else:
                        supabase.table("findings").insert({
                            "asset_id": asset_id,
                            **inferred_finding
                        }).execute()
                        label = inferred_finding["cve_id"] or inferred_finding["vuln_category"]
                        print(f"  [OK] {label} | "
                              f"{inferred_finding['severity'].upper()} | "
                              f"CVSS: {inferred_finding['cvss_score']} | "
                              f"KEV: {inferred_finding['is_kev']} | "
                              f"Risk: {inferred_finding['risk_score']}")
                        total += 1

    print(f"\n[INFO] Done - {total} findings inserted")
    print("Go to Supabase -> Table Editor -> findings to verify")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_nmap.py <path_to_nmap_report.xml>")
        sys.exit(1)
    run_import(sys.argv[1])