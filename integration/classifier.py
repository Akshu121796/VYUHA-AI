import os

DEFAULT_RULES = [
    {
        "category": "weak_credential",
        "keywords": ["default password", "weak password", "default credential", "hardcoded credential", "weak credential", "credentials", "login", "auth", "password", "username", "credential dump", "lsass"]
    },
    {
        "category": "privilege_escalation_vuln",
        "keywords": ["privilege escalation", "sudo", "elevate privilege", "local privilege", "privilege_escalation_vuln", "root shell", "elevation of privilege", "bypass validation"]
    },
    {
        "category": "lateral_movement_vector",
        "keywords": ["smb", "rdp", "remote desktop", "shared credential", "lateral movement", "lateral_movement_vector", "active directory", "ntlm"]
    },
    {
        "category": "misconfiguration",
        "keywords": ["misconfigur", "open port", "excessive permission", "exposed admin", "denial of service", "misconfiguration", "clickjacking", "cors", "x-frame-options"]
    },
    {
        "category": "unpatched_service",
        "keywords": ["out-of-bounds", "buffer overflow", "remote code execution", "unauthorized code", "arbitrary code", "execute unauthorized", "unpatched_service", "cve-", "supply-chain", "backdoor", "remote execution"]
    }
]

def classify_vuln(supabase_client, description, service_name=None, title=None):
    """
    Classifies a vulnerability into the project's vuln_category taxonomy based on description, service name, and title.
    Categories returned: 'weak_credential', 'privilege_escalation_vuln', 'lateral_movement_vector', 'unpatched_service', 'misconfiguration'.
    """
    text_to_check = []
    if title:
        text_to_check.append(str(title).lower())
    if service_name:
        text_to_check.append(str(service_name).lower())
    if description:
        text_to_check.append(str(description).lower())
        
    combined_text = " ".join(text_to_check)
    
    # Try fetching rules from Supabase vuln_category_rules table
    rules = []
    try:
        res = supabase_client.table("vuln_category_rules").select("category, keywords").execute()
        if res.data:
            rules = res.data
    except Exception as e:
        # Fallback to local hardcoded rules if database is offline/unreachable
        pass
        
    if not rules:
        rules = DEFAULT_RULES
        
    # Check keyword matches based on priority order
    for rule in rules:
        category = rule.get("category")
        keywords = rule.get("keywords", [])
        for kw in keywords:
            if kw.lower() in combined_text:
                return category
                
    # Direct heuristics fallbacks if keywords did not match
    if any(k in combined_text for k in ["ssh", "password", "login", "auth", "username", "credential", "lsass"]):
        return "weak_credential"
    if any(k in combined_text for k in ["smb", "rdp", "remote desktop", "lateral", "movement"]):
        return "lateral_movement_vector"
    if any(k in combined_text for k in ["privilege", "sudo", "escalat", "elevat"]):
        return "privilege_escalation_vuln"
    if any(k in combined_text for k in ["cve-", "exploit", "rce", "remote code execution", "overflow", "vulnerability", "out-of-bounds", "unpatched"]):
        return "unpatched_service"
        
    return "misconfiguration"
