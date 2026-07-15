export interface AssetCreate {
  hostname: string;
  ip_address?: string;
  os_type?: string;
  criticality: "low" | "medium" | "high" | "critical";
}

export interface FindingCreate {
  asset_id: string;
  cve_id?: string;
  cvss_score?: number;
  severity?: string;
  is_kev?: boolean;
  description?: string;
  remediation?: string;
  status?: string;
  vuln_category?: string; // weak_credential | unpatched_service | misconfiguration | privilege_escalation_vuln | lateral_movement_vector
}
export interface ApprovalCreate {
  finding_id: string;
  recommended_fix: string;
}

export interface ApprovalDecision {
  decision: "approved" | "rejected";
}