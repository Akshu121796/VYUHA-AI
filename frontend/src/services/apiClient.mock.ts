import axios from "axios";
import { 
  mockIncidents, 
  mockEndpoints, 
  mockApprovalTasks, 
  liveLogStream, 
  mockCompliance 
} from "./mockData";

// Setup custom axios instance
export const apiClient = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json"
  }
});

// Helper to simulate network latency delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Active simulation databases in local session scope
let localIncidents = [...mockIncidents];
let localEndpoints = [...mockEndpoints];
let localApprovals = [...mockApprovalTasks];
let localCompliance = [...mockCompliance];
let localReports = [
  { id: "REP-2026-001", title: "Executive SOC2 Audit Compliance Report", timestamp: "03:42:00 Z", size: "4.2 MB", format: "PDF" as const, downloadCount: 14 },
  { id: "REP-2026-002", title: "Boundary Palo Alto Firewall Log Feed", timestamp: "03:02:00 Z", size: "18.5 MB", format: "CSV" as const, downloadCount: 22 },
  { id: "REP-2026-003", title: "ISO27001 Access Management Audit Log", timestamp: "02:15:00 Z", size: "2.1 MB", format: "PDF" as const, downloadCount: 8 }
];
let localSettings = {
  profile: { name: "Kaveesh", email: "kaveesh@vyuha.ai", title: "Senior SOC Analyst" },
  theme: { contrast: "standard" },
  notifications: { slack: "https://hooks.slack.com/services/T00/B00/X00", syslog: "10.120.50.44:514" },
  preferences: { autoIsolate: true, blockLateral: false },
  security: { enable2Fa: true }
};

// Add simulated request adapter interceptor
apiClient.interceptors.request.use(async (config) => {
  const url = config.url || "";
  const method = config.method?.toLowerCase() || "get";
  
  // Apply random latency (300ms - 500ms)
  await delay(300 + Math.random() * 200);

  // Intercept mock responses
  throw {
    config,
    response: {
      status: 200,
      statusText: "OK",
      headers: {},
      config,
      data: handleMockRoutes(url, method, config.data)
    }
  };
}, (error) => {
  return Promise.reject(error);
});

// Routing mock response mapper
function handleMockRoutes(url: string, method: string, requestData: any) {
  const parsedData = requestData ? JSON.parse(requestData) : null;

  // 1. Dashboard
  if (url === "/dashboard" && method === "get") {
    return {
      incidents: localIncidents,
      endpoints: localEndpoints,
      approvals: localApprovals,
      liveLogs: liveLogStream
    };
  }

  // 2. Findings
  if (url === "/findings" && method === "get") {
    return localIncidents;
  }
  if (url.startsWith("/findings/") && method === "put") {
    const id = url.split("/")[2];
    localIncidents = localIncidents.map(inc => inc.id === id ? { ...inc, ...parsedData } : inc);
    return localIncidents.find(inc => inc.id === id);
  }

  // 3. Endpoints
  if (url === "/endpoints" && method === "get") {
    return localEndpoints;
  }
  if (url.startsWith("/endpoints/") && method === "get") {
    const id = url.split("/")[2];
    return localEndpoints.find(e => e.id === id) || localEndpoints[0];
  }
  if (url.startsWith("/endpoints/") && url.endsWith("/isolate") && method === "put") {
    const id = url.split("/")[2];
    localEndpoints = localEndpoints.map(e => e.id === id ? { ...e, status: e.status === "isolated" ? "online" : "isolated" } : e);
    return localEndpoints.find(e => e.id === id);
  }
  if (url.startsWith("/endpoints/") && url.endsWith("/terminate-process") && method === "put") {
    const id = url.split("/")[2];
    const { pid } = parsedData;
    localEndpoints = localEndpoints.map(e => {
      if (e.id === id) {
        return {
          ...e,
          processes: e.processes.map(p => p.pid === pid ? { ...p, status: "terminated" as const } : p)
        };
      }
      return e;
    });
    return localEndpoints.find(e => e.id === id);
  }

  // 4. Attack Paths
  if (url === "/attack-graph" && method === "get") {
    return {
      nodes: [
        { id: "weak-credentials", label: "Weak Credentials", severity: "high" },
        { id: "privilege-escalation", label: "Privilege Escalation", severity: "critical" },
        { id: "credential-dumping", label: "Credential Dumping", severity: "critical" },
        { id: "lateral-movement", label: "Lateral Movement", severity: "high" },
        { id: "domain-admin", label: "Domain Admin", severity: "critical" }
      ]
    };
  }

  // 5. Copilot
  if (url === "/copilot" && method === "post") {
    const { prompt } = parsedData;
    const p = prompt.toLowerCase();
    
    if (p.includes("xz-utils") || p.includes("xz")) {
      return {
        role: "assistant",
        content: "### VYUHA.AI SOC Triage Report\nActive exploit traces of **CVE-2024-3094** detected on host **web-prod-ubuntu-01**.\n\n*   **Vulnerability status**: CRITICAL (CVSS Score 10.0)\n*   **Mitigation Playbook**: I recommend immediate network isolation of the VLAN segment.",
        codeBlock: {
          language: "bash",
          code: "# Quarantine host at active gateway\niptables -A INPUT -s 10.120.40.8 -j DROP"
        },
        referenceCard: {
          hostname: "web-prod-ubuntu-01",
          ip: "10.120.40.8",
          cve: "CVE-2024-3094",
          severity: "critical"
        }
      };
    }

    return {
      role: "assistant",
      content: `I've analyzed your custom prompt: "${prompt}". I suggest verifying host telemetry settings or deploying automated mitigations.`
    };
  }

  // 6. Approval Queue
  if (url === "/approvals" && method === "get") {
    return localApprovals;
  }
  if (url.startsWith("/approvals/") && method === "put") {
    const id = url.split("/")[2];
    const { status } = parsedData;
    localApprovals = localApprovals.map(t => t.id === id ? { ...t, status } : t);
    return localApprovals.find(t => t.id === id);
  }

  // 7. Reports
  if (url === "/reports" && method === "get") {
    return {
      compliance: localCompliance,
      reports: localReports
    };
  }
  if (url === "/reports" && method === "post") {
    const newId = `REP-2026-00${localReports.length + 1}`;
    const newReport = {
      id: newId,
      title: "Executive CISO Threat Audit Summary",
      timestamp: "Just Now",
      size: "3.1 MB",
      format: "PDF" as const,
      downloadCount: 0
    };
    localReports = [newReport, ...localReports];
    return newReport;
  }

  // 8. Settings
  if (url === "/settings" && method === "get") {
    return localSettings;
  }
  if (url === "/settings" && method === "put") {
    localSettings = { ...localSettings, ...parsedData };
    return localSettings;
  }

  // Fallback
  return { success: true };
}

// Add global error interceptor fallback to react queries
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // If it's our simulated throw response, resolve it as data!
    if (error.response && error.response.status === 200) {
      return Promise.resolve(error.response);
    }
    return Promise.reject(error);
  }
);
