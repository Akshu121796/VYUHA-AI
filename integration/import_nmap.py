import xml.etree.ElementTree as ET
import requests
import os
from supabase import create_client
from dotenv import load_dotenv
import time

load_dotenv()

supabase = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SECRET_KEY"]   # matches your .env
)

VERSION_CVE_MAP = {
    "Apache httpd 2.4.49":  ["CVE-2021-41773", "CVE-2021-42013"],
    "OpenSSH 7.4":          ["CVE-2023-38408", "CVE-2018-15473"],
    "MySQL 5.7.32":         ["CVE-2021-2307",  "CVE-2020-14765"],
    "SimpleHTTPServer 0.6": ["CVE-2024-21762", "CVE-2023-44487"],  # your real scan
}

def get_kev_ids():
    print("Fetching CISA KEV list...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url)
    ids = {v["cveID"] for v in r.json()["vulnerabilities"]}
    print(f"Loaded {len(ids)} KEV entries")
    return ids

def fetch_nvd(cve_id, kev_ids):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    r = requests.get(url, headers=headers)
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
                "os_type":     "Linux",     # Kali = Linux
                "criticality": "high"
            }).execute()
            asset_id = result.data[0]["id"]
            print(f"  Asset created — id: {asset_id}")

        if not host["services"]:
            print("  No open services found on this host")
            continue

        for service in host["services"]:
            matched_cves = []

            for version_string, cves in VERSION_CVE_MAP.items():
                # match any word from version string against service string
                words = version_string.split()
                if version_string.lower() == service.lower():
                    matched_cves.extend(cves)
                    print(f"  Matched '{version_string}' → {cves}")

            if not matched_cves:
                print(f"  No CVE match for service: {service}")
                continue

            for cve_id in matched_cves:
                print(f"  Fetching {cve_id} from NVD...")
                cve_data = fetch_nvd(cve_id, kev_ids)

                if cve_data:
                    # skip duplicates
                    dup = supabase.table("findings") \
                        .select("id") \
                        .eq("cve_id", cve_id) \
                        .eq("asset_id", asset_id) \
                        .execute()

                    if dup.data:
                        print(f"  ⚠ Duplicate — skipping {cve_id}")
                    else:
                        supabase.table("findings").insert({
                            "asset_id": asset_id,
                            **cve_data
                        }).execute()
                        print(f"  ✓ {cve_id} | "
                              f"{cve_data['severity'].upper()} | "
                              f"CVSS: {cve_data['cvss_score']} | "
                              f"KEV: {cve_data['is_kev']} | "
                              f"Risk: {cve_data['risk_score']}")
                        total += 1

                time.sleep(0.6)  # NVD rate limit — do not remove

    print(f"\n✅ Done — {total} findings inserted")
    print("Go to Supabase → Table Editor → findings to verify")

if __name__ == "__main__":
    # Run on your real Kali scan
    run_import("scan_output.xml")
   # run_import("sample_nmap.xml")