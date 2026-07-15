export type Severity = "critical" | "high" | "medium" | "low" | "safe";

export type IncidentStatus = "active" | "investigating" | "resolved" | "suppressed";

export interface Incident {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  status: IncidentStatus;
  hostname: string;
  ip: string;
  timestamp: string;
  description: string;
  detector: string;
}

export interface SystemProcess {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  path: string;
  status: "running" | "suspicious" | "terminated";
}

export interface CVEInfo {
  id: string; // e.g. CVE-2024-3094
  severity: Severity;
  score: number;
  description: string;
  publishDate: string;
}

export interface Endpoint {
  id: string;
  hostname: string;
  os: "Windows Server" | "Ubuntu Server" | "macOS" | "RedHat Linux";
  osVersion: string;
  ip: string;
  mac: string;
  status: "online" | "offline" | "isolated";
  cves: CVEInfo[];
  processes: SystemProcess[];
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  criticalAlertsCount: number;
  highAlertsCount: number;
  lastSeen: string;
  policyGroup: string;
}

export interface CopilotMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  suggestedActions?: {
    label: string;
    action: string;
    payload?: any;
  }[];
  codeBlock?: {
    language: string;
    code: string;
  };
}

export interface ApprovalTask {
  id: string;
  action: "isolate_host" | "terminate_process" | "block_ip" | "quarantine_file";
  target: string;
  requester: string;
  reason: string;
  status: "pending" | "approved" | "rejected";
  timestamp: string;
  details: string;
}

export interface ComplianceScore {
  name: string;
  score: number;
  passedRules: number;
  totalRules: number;
  status: "pass" | "warn" | "fail";
}
