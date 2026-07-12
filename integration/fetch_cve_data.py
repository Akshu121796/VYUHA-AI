import requests
import os
from supabase import create_client
from dotenv import load_dotenv 

load_dotenv()

supabase = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SECRET_KEY"]
)

# Step 1 — fetch all actively exploited CVEs from CISA KEV
def get_kev_ids():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    data = response.json()
    return {v["cveID"] for v in data["vulnerabilities"]}

# Step 2 — fetch details for one CVE from NVD
def fetch_cve_details(cve_id: str, kev_ids: set):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": os.environ["NVD_API_KEY"]}
    response = requests.get(url, headers=headers)

    
    if response.status_code != 200:
        print(f"Failed to fetch {cve_id}")
        return None
    
    data = response.json()
    vuln = data["vulnerabilities"][0]["cve"]
    
    # Get CVSS score safely
    metrics = vuln.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    cvss_score = cvss_list[0]["cvssData"]["baseScore"] if cvss_list else 0
    
    # Map score to severity label
    if cvss_score >= 9.0:
        severity = "critical"
    elif cvss_score >= 7.0:
        severity = "high"
    elif cvss_score >= 4.0:
        severity = "medium"
    else:
        severity = "low"

    is_kev = cve_id in kev_ids                          
    risk_score = cvss_score + (2.0 if is_kev else 0)   
    
    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "is_kev": is_kev,                              
        "risk_score": round(risk_score, 2),            
        "description": vuln["descriptions"][0]["value"]
    }

# Step 3 — save to Supabase
def save_finding(asset_id: str, cve_data: dict):
    supabase.table("findings").insert({
        "asset_id": asset_id,
        **cve_data
    }).execute()
    print(f"Saved {cve_data['cve_id']} — severity: {cve_data['severity']}, KEV: {cve_data['is_kev']}")

# Run it
if __name__ == "__main__":
    kev_ids = get_kev_ids()
    print(f"Loaded {len(kev_ids)} KEV entries")
    
    # Test with a known CVE — replace with CVEs from your OpenVAS scan output
    test_cves = ["CVE-2024-21762", "CVE-2023-44487"]
    
    # You'll need a real asset_id from your assets table
    # For now, insert a test asset first
    asset = supabase.table("assets").insert({
        "hostname": "test-endpoint-01",
        "ip_address": "192.168.1.10",
        "os_type": "Windows",
        "criticality": "high"
    }).execute()
    
    asset_id = asset.data[0]["id"]
    
    for cve_id in test_cves:
        cve_data = fetch_cve_details(cve_id, kev_ids)
        if cve_data:
            save_finding(asset_id, cve_data)