import { db } from "../core/db";

// Attack Patterns configuration from Python vyuha.py
export const ATTACK_PATTERNS_CONFIG = [
  {
    name: "Web Exploit Chain: Public App -> RCE -> Database Access",
    sequence: ["web_service", "outdated_software", "database_exposure"],
    mitre_techniques: ["T1190 - Exploit Public-Facing App", "T1210 - Exploitation of Remote Services", "T1530 - Data from Cloud Storage"],
    severity: "Critical",
    likelihood: "High",
    business_impact: "Severe",
    priority: 1,
    description: "Attacker exploits vulnerable web application, achieves remote code execution, pivots to database containing sensitive data."
  },
  {
    name: "Credential Attack Chain: Weak Passwords -> Lateral Movement -> Domain Admin",
    sequence: ["weak_credential", "lateral_movement", "privilege_escalation"],
    mitre_techniques: ["T1110 - Brute Force", "T1021 - Remote Services", "T1068 - Exploitation for Privilege Escalation"],
    severity: "Critical",
    likelihood: "Medium",
    business_impact: "Severe",
    priority: 1,
    description: "Weak credentials allow initial access, lateral movement via remote services leads to domain controller compromise."
  },
  {
    name: "Service Exposure Chain: Open Port -> Exploitation -> Data Access",
    sequence: ["exposed_service", "insecure_service", "data_exposure"],
    mitre_techniques: ["T1046 - Network Service Scanning", "T1190 - Exploit Public-Facing App", "T1530 - Data from Cloud Storage"],
    severity: "High",
    likelihood: "Medium",
    business_impact: "High",
    priority: 2,
    description: "Exposed insecure service is discovered, exploited, and used to access sensitive data."
  },
  {
    name: "Remote Access Chain: RDP/SSH -> Lateral Movement",
    sequence: ["remote_access", "lateral_movement"],
    mitre_techniques: ["T1021 - Remote Services", "T1210 - Exploitation of Remote Services"],
    severity: "High",
    likelihood: "Medium",
    business_impact: "High",
    priority: 2,
    description: "Compromised remote access credentials used to move laterally across the network."
  }
];

// Remediation actions configuration from Python vyuha.py
export const REMEDIATION_ACTIONS_MAP: Record<string, string[]> = {
  "web_service": [
    "Enforce HTTPS with HSTS preloading",
    "Deploy Web Application Firewall (WAF) in blocking mode",
    "Implement Content Security Policy (CSP) headers",
    "Conduct regular vulnerability scanning",
    "Enable detailed access logging"
  ],
  "database_exposure": [
    "Restrict network access with firewall rules (allow only app servers)",
    "Enable strong authentication (disable default accounts)",
    "Implement TLS encryption for all connections",
    "Enable audit logging for all queries",
    "Apply latest security patches"
  ],
  "remote_access": [
    "Implement VPN requirement for all remote access",
    "Enable Multi-Factor Authentication (MFA)",
    "Use key-based authentication only (disable password auth for SSH)",
    "Deploy fail2ban or similar rate-limiting",
    "Monitor for brute force attempts"
  ],
  "lateral_movement": [
    "Implement network segmentation between VLANs",
    "Disable SMBv1 protocol on all systems",
    "Enforce SMB signing and encryption",
    "Deploy network traffic monitoring",
    "Restrict service account permissions"
  ],
  "privilege_escalation": [
    "Apply security patches immediately (emergency change)",
    "Implement least privilege principle across all systems",
    "Enable Windows Credential Guard where supported",
    "Monitor for token manipulation and privilege escalation",
    "Conduct regular privilege audits"
  ],
  "outdated_software": [
    "Upgrade to latest stable/patched version",
    "Implement automated dependency scanning in CI/CD",
    "Subscribe to vendor security advisories",
    "Deploy compensating controls (WAF/IDS) until patched",
    "Verify patch application via authenticated scanning"
  ],
  "unpatched_rce": [
    "Deploy emergency security patch immediately",
    "Isolate affected system if exploitation is suspected",
    "Implement network containment to limit blast radius",
    "Review system and network logs for IoCs",
    "Re-scan after patching to verify remediation"
  ],
  "weak_credential": [
    "Enforce strong password policy (minimum 14 characters)",
    "Enable MFA for all user accounts",
    "Implement account lockout after 5 failed attempts",
    "Rotate all compromised credentials immediately",
    "Conduct organization-wide password audit"
  ],
  "insecure_service": [
    "Upgrade to secure protocol version or replacement",
    "Apply transport layer encryption (TLS 1.3)",
    "Restrict access to authorized IP addresses only",
    "Implement service-level authentication",
    "Schedule regular security assessments"
  ],
  "exposed_service": [
    "Verify business justification for the exposed service",
    "Implement firewall rules restricting source IPs",
    "Move service behind VPN if external access not required",
    "Enable detailed access and error logging",
    "Conduct quarterly port auditing"
  ],
  "api_misconfiguration": [
    "Implement authentication on all API endpoints",
    "Apply rate limiting (100 requests/minute per client)",
    "Deploy API gateway for centralized security",
    "Enable API request/response logging",
    "Conduct API penetration testing"
  ],
  "broken_authz": [
    "Implement object-level authorization checks on all endpoints",
    "Add automated authorization tests to CI/CD pipeline",
    "Conduct manual penetration testing of authorization",
    "Implement Attribute-Based Access Control (ABAC)",
    "Log and monitor all authorization failures"
  ],
  "data_exposure": [
    "Restrict data access to authorized services only",
    "Encrypt sensitive data at rest (AES-256) and in transit (TLS)",
    "Implement Data Loss Prevention (DLP) controls"
  ]
};

// Map database vuln_categories to Python's pattern types
export function normalizeFindingType(cat: string | null | undefined): string[] {
  if (!cat) return [];
  const c = cat.toLowerCase();
  
  if (c === "unpatched_service") {
    return ["web_service", "outdated_software", "insecure_service", "unpatched_rce"];
  }
  if (c === "privilege_escalation_vuln") {
    return ["privilege_escalation"];
  }
  if (c === "lateral_movement_vector") {
    return ["lateral_movement"];
  }
  if (c === "misconfiguration") {
    return ["exposed_service", "database_exposure", "api_misconfiguration"];
  }
  if (c === "weak_credential") {
    return ["weak_credential"];
  }
  
  return [c];
}

// Determine clean asset types for inference and UI representation
export function getAssetType(hostname: string, osType: string | null | undefined): string {
  const name = hostname.toLowerCase();
  if (name.includes("web") || name.includes("portal")) return "Web Server";
  if (name.includes("app") || name.includes("payment") || name.includes("auth")) return "Application Server";
  if (name.includes("db") || name.includes("postgres") || name.includes("mysql") || name.includes("sql")) return "Database Server";
  if (name.includes("dc") || name.includes("controller") || name.includes("admin")) return "Domain Controller";
  if (name.includes("workstation") || name.includes("host") || name.includes("endpoint")) return "Workstation";
  if (osType) return osType;
  return "Ubuntu Server";
}

// Establish connections based on network topology logic or dynamic connects_to relationships
export function getConnectsTo(sourceAsset: any, allAssets: any[], findings: any[]): string[] {
  const assetFindings = findings.filter(f => f.asset_id === sourceAsset.id || f.asset === sourceAsset.hostname);
  
  // 1. If any finding contains connects_to, use it
  for (const f of assetFindings) {
    if (f.connects_to && Array.isArray(f.connects_to) && f.connects_to.length > 0) {
      return f.connects_to;
    }
  }

  // 2. If the asset row contains connects_to, use it
  if (sourceAsset.connects_to && Array.isArray(sourceAsset.connects_to) && sourceAsset.connects_to.length > 0) {
    return sourceAsset.connects_to;
  }

  // 3. Otherwise, infer relationships based on hostname, subnet, asset type, and network hierarchy
  const sourceName = sourceAsset.hostname.toUpperCase();
  const sourceType = getAssetType(sourceAsset.hostname, sourceAsset.os_type).toUpperCase();
  const sourceIp = sourceAsset.ip_address || "0.0.0.0";
  
  const connections: string[] = [];

  for (const target of allAssets) {
    if (target.id === sourceAsset.id) continue;
    
    const targetName = target.hostname.toUpperCase();
    const targetType = getAssetType(target.hostname, target.os_type).toUpperCase();
    const targetIp = target.ip_address || "0.0.0.0";
    
    const getSubnet = (ip: string) => ip.split(".").slice(0, 2).join(".");
    const sameSubnet = getSubnet(sourceIp) === getSubnet(targetIp) && sourceIp !== "0.0.0.0" && sourceIp !== "127.0.0.1";

    // Workstations connect to Web/App Servers
    if (sourceType === "WORKSTATION" && (targetType === "WEB SERVER" || targetType === "APPLICATION SERVER")) {
      connections.push(target.hostname);
    }
    // Web Servers connect to App Servers / Database Servers
    else if (sourceType === "WEB SERVER" && (targetType === "APPLICATION SERVER" || targetType === "DATABASE SERVER")) {
      connections.push(target.hostname);
    }
    // App Servers connect to Database / Domain Controllers
    else if (sourceType === "APPLICATION SERVER" && (targetType === "DATABASE SERVER" || targetType === "DOMAIN CONTROLLER")) {
      connections.push(target.hostname);
    }
    // Subnet hierarchy: low criticality connects to high criticality in same subnet
    else if (sameSubnet && sourceAsset.criticality === "low" && target.criticality === "high") {
      connections.push(target.hostname);
    }
  }

  return connections;
}

export interface GraphNode {
  id: string; // hostname
  findings: string[];
  score: number;
  ip: string;
  asset_type: string;
  severity: string;
  findingsCount: number;
}

// 1. Build asset graph
export function buildAssetGraph(findings: any[], allAssets: any[]) {
  const nodes = new Map<string, GraphNode>();
  const adjList = new Map<string, Set<string>>();

  // Create nodes
  for (const f of findings) {
    const assetName = f.asset || "unknown";
    if (!nodes.has(assetName)) {
      nodes.set(assetName, {
        id: assetName,
        findings: [],
        score: 0,
        ip: f.asset_ip || "",
        asset_type: f.asset_type || "Ubuntu Server",
        severity: "low",
        findingsCount: 0
      });
    }
    
    const node = nodes.get(assetName)!;
    
    // Normalize finding type into potential sequence matching categories
    const normalizedTypes = normalizeFindingType(f.finding_type);
    node.findings.push(...normalizedTypes);
    
    node.score = Math.max(node.score, f.cvss || 0);
    if (f.asset_ip) {
      node.ip = f.asset_ip;
    }
    node.findingsCount++;
    
    // Severity priority check
    const severities = ["low", "medium", "high", "critical"];
    const currentSevIdx = severities.indexOf(node.severity.toLowerCase());
    const newSevIdx = severities.indexOf((f.severity || "low").toLowerCase());
    if (newSevIdx > currentSevIdx) {
      node.severity = f.severity.toLowerCase();
    }
  }

  // Create edges
  for (const f of findings) {
    const assetName = f.asset || "unknown";
    const matchedAsset = allAssets.find(a => a.hostname === assetName);
    const assetObj = matchedAsset || { id: `node-${assetName}`, hostname: assetName, ip_address: f.asset_ip, os_type: f.asset_type, criticality: "medium" };
    const connectsTo = getConnectsTo(assetObj, allAssets, findings);
    for (const target of connectsTo) {
      if (target && target !== assetName) {
        if (!adjList.has(assetName)) {
          adjList.set(assetName, new Set());
        }
        adjList.get(assetName)!.add(target);
      }
    }
  }

  return { nodes, adjList };
}

function sequenceInOrder(patternSeq: string[], foundTypes: string[]): boolean {
  let idx = 0;
  for (const step of patternSeq) {
    let found = false;
    for (let i = idx; i < foundTypes.length; i++) {
      if (foundTypes[i] === step) {
        idx = i + 1;
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

// 2. Detect attack chains
export function detectAttackChains(findings: any[], allAssets: any[]): any[] {
  if (findings.length === 0) return [];
  const { nodes, adjList } = buildAssetGraph(findings, allAssets);
  const matches: any[] = [];

  for (const pattern of ATTACK_PATTERNS_CONFIG) {
    const seq = pattern.sequence;
    for (const startNode of nodes.keys()) {
      const queue: string[][] = [[startNode]];
      while (queue.length > 0) {
        const path = queue.shift()!;
        if (path.length > seq.length + 2) {
          continue;
        }
        const typesOnPath: string[] = [];
        for (const nodeName of path) {
          const node = nodes.get(nodeName);
          if (node) {
            typesOnPath.push(...node.findings);
          }
        }
        if (sequenceInOrder(seq, typesOnPath)) {
          matches.push({
            pattern_name: pattern.name,
            path: [...path],
            mitre_techniques: pattern.mitre_techniques || [],
            severity: pattern.severity || "High",
            likelihood: pattern.likelihood || "Medium",
            business_impact: pattern.business_impact || "Moderate",
            priority: pattern.priority || 3,
            description: pattern.description || "",
          });
        }
        const lastNodeName = path[path.length - 1];
        const neighbors = adjList.get(lastNodeName) || new Set<string>();
        for (const neighbor of neighbors) {
          if (!path.includes(neighbor)) {
            queue.push([...path, neighbor]);
          }
        }
      }
    }
  }

  // Filter unique matches (pattern_name + path)
  const seen = new Set<string>();
  const unique: any[] = [];
  for (const m of matches) {
    const key = `${m.pattern_name}|${m.path.join(",")}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(m);
    }
  }

  unique.sort((a, b) => (a.priority || 3) - (b.priority || 3));
  return unique;
}

// 3. Identify most vulnerable nodes
export function identifyMostVulnerableNodes(findings: any[], chains: any[]): any {
  const nodeScores: Record<string, { score: number; findings: any[]; in_chains: number; total_risk: number }> = {};

  for (const f of findings) {
    const asset = f.asset || "unknown";
    if (!nodeScores[asset]) {
      nodeScores[asset] = { score: 0, findings: [], in_chains: 0, total_risk: 0 };
    }
    nodeScores[asset].findings.push(f);
    const risk = f.normalized_risk_score || 0;
    nodeScores[asset].total_risk += risk;
    nodeScores[asset].score = Math.max(nodeScores[asset].score, risk);
  }

  for (const chain of chains) {
    const path = chain.path || [];
    for (const node of path) {
      if (!nodeScores[node]) {
        nodeScores[node] = { score: 0, findings: [], in_chains: 0, total_risk: 0 };
      }
      nodeScores[node].in_chains += 1;
    }
  }

  const entries = Object.entries(nodeScores);
  entries.sort((a, b) => {
    const scoreA = a[1].in_chains * 10 + a[1].total_risk;
    const scoreB = b[1].in_chains * 10 + b[1].total_risk;
    return scoreB - scoreA;
  });

  const result: Record<string, any> = {};
  for (const [key, value] of entries.slice(0, 5)) {
    result[key] = value;
  }
  return result;
}

// 4. Generate attack path context
export function generateAttackPathContext(chains: any[], vulnNodes: any, findings: any[]): string {
  const parts = ["=== ACTIVE ATTACK PATHS ==="];
  if (chains && chains.length > 0) {
    chains.slice(0, 5).forEach((c, i) => {
      parts.push(`Attack Path ${i+1}: ${c.pattern_name} (Severity: ${c.severity}, Likelihood: ${c.likelihood || '?'}, Business Impact: ${c.business_impact || '?'})`);
      parts.push(`Path: ${c.path.join(" -> ")}`);
      parts.push(`MITRE Techniques: ${(c.mitre_techniques || []).join(", ")}`);
      parts.push("");
    });
  } else {
    parts.push("No attack chains detected.");
    parts.push("");
  }

  parts.push("=== MOST VULNERABLE NODES ===");
  Object.entries(vulnNodes).forEach(([node, info]: [string, any]) => {
    parts.push(`- ${node}: Max Score=${info.score}/10, Chains=${info.in_chains}, Total Risk=${info.total_risk}, Findings=${info.findings.length}`);
  });
  parts.push("");

  parts.push("=== TOP FINDINGS BY RISK ===");
  const sortedFindings = [...findings].sort((a, b) => (b.normalized_risk_score || 0) - (a.normalized_risk_score || 0));
  sortedFindings.slice(0, 10).forEach((f) => {
    parts.push(`- ${f.asset}: ${f.cve_id || f.finding_type} (Risk: ${f.normalized_risk_score})`);
  });

  return parts.join("\n");
}

// Backwards compatibility function
export async function generateAttackPaths(scanId: string) {
  return [];
}

export interface InferredEdge {
  source: string;
  target: string;
  sourceName: string;
  targetName: string;
  reason: string;
  rule: string;
  cves: string[];
  findings: string[];
}

export function inferEdgesFromScanData(assets: any[], findings: any[]): InferredEdge[] {
  const edges: InferredEdge[] = [];
  const visited = new Set<string>();

  // 1. Identify public-facing assets and create edges from the Internet
  for (const target of assets) {
    const targetFindings = findings.filter(f => f.asset_id === target.id || f.asset === target.hostname);
    const targetIp = target.ip_address || "0.0.0.0";
    
    // Find if target runs any public-facing vulnerable services
    const publicServiceFindings = targetFindings.filter(f => {
      const desc = f.description.toLowerCase();
      const cat = (f.vuln_category || f.finding_type || "").toLowerCase();
      
      const isPublicServiceType = 
        desc.includes("apache") || 
        desc.includes("http") || 
        desc.includes("web") || 
        desc.includes("fortios") || 
        desc.includes("fortiproxy") || 
        desc.includes("vpn") || 
        desc.includes("gateway") ||
        desc.includes("nginx") ||
        desc.includes("iis");

      return isPublicServiceType && 
             (cat === "unpatched_service" || cat === "misconfiguration" || cat === "exposed_service") &&
             ["high", "critical"].includes((f.severity || "").toLowerCase());
    });

    if (publicServiceFindings.length > 0) {
      const cves = publicServiceFindings.map(f => f.cve_id || f.finding_id).filter(Boolean) as string[];
      const findingIds = publicServiceFindings.map(f => f.id || f.finding_id);
      
      const edge: InferredEdge = {
        source: "internet-node",
        target: target.id,
        sourceName: "Internet",
        targetName: target.hostname,
        rule: "External Public Exposure",
        reason: `Vulnerable public-facing service (${publicServiceFindings[0].cve_id || "HTTP/Gateway"}) on ${target.hostname} (${targetIp}) is exposed to the external Internet, allowing initial access foothold.`,
        cves: [...new Set(cves)],
        findings: findingIds
      };
      
      const edgeKey = `${edge.source}->${edge.target}`;
      if (!visited.has(edgeKey)) {
        visited.add(edgeKey);
        edges.push(edge);
        
        console.log(`[EDGE CREATED]
Source: ${edge.sourceName} (${edge.source})
Destination: ${edge.targetName} (${edge.target})
Relationship Type: ${edge.rule}
Evidence Used: ${edge.reason}
--------------------------------------------------`);
      }
    }
  }

  // 2. Map internal network pivots
  for (const source of assets) {
    const sourceName = source.hostname.toUpperCase();
    const sourceFindings = findings.filter(f => f.asset_id === source.id || f.asset === source.hostname);
    const sourceIp = source.ip_address || "0.0.0.0";
    
    const sourceHasWeb = sourceFindings.some(f => 
      f.description.toLowerCase().includes("apache") || 
      f.description.toLowerCase().includes("http") || 
      f.description.toLowerCase().includes("web") ||
      (f.asset_type && f.asset_type.toLowerCase().includes("web"))
    );
    const sourceHasSSH = sourceFindings.some(f => 
      f.description.toLowerCase().includes("ssh") || 
      f.description.toLowerCase().includes("openssh")
    );
    const sourceHasCreds = sourceFindings.some(f => 
      f.finding_type === "weak_credential" || 
      f.vuln_category === "weak_credential"
    );

    for (const target of assets) {
      if (target.id === source.id) continue;
      if (target.hostname.toLowerCase().includes("localhost")) continue; // local loopback is isolated
      
      const targetName = target.hostname.toUpperCase();
      const targetFindings = findings.filter(f => f.asset_id === target.id || f.asset === target.hostname);
      const targetIp = target.ip_address || "0.0.0.0";
      
      const targetHasSSH = targetFindings.some(f => 
        f.description.toLowerCase().includes("ssh") || 
        f.description.toLowerCase().includes("openssh")
      );
      const targetHasDB = targetFindings.some(f => 
        f.description.toLowerCase().includes("mysql") || 
        f.description.toLowerCase().includes("sql") || 
        f.description.toLowerCase().includes("postgres") || 
        f.description.toLowerCase().includes("database")
      );

      const getSubnet = (ip: string) => ip.split(".").slice(0, 2).join(".");
      const sameSubnet = getSubnet(sourceIp) === getSubnet(targetIp) && sourceIp !== "0.0.0.0" && sourceIp !== "127.0.0.1";

      const sourceCves = sourceFindings.map(f => f.cve_id || f.finding_id).filter(Boolean) as string[];
      const sourceFindingIds = sourceFindings.map(f => f.id || f.finding_id);

      let edge: InferredEdge | null = null;

      if (sourceHasWeb && targetHasSSH) {
        edge = {
          source: source.id,
          target: target.id,
          sourceName: source.hostname,
          targetName: target.hostname,
          rule: "Web App -> Application Server Pivot",
          reason: `Vulnerable web service on ${source.hostname} (${sourceIp}) exposes it to external ingress; attackers can use it as a foothold to probe SSH service on ${target.hostname} (${targetIp}).`,
          cves: [...new Set(sourceCves)],
          findings: sourceFindingIds
        };
      }
      else if (sourceHasSSH && targetHasDB) {
        edge = {
          source: source.id,
          target: target.id,
          sourceName: source.hostname,
          targetName: target.hostname,
          rule: "Jump Host -> Database Connection",
          reason: `SSH remote management on ${source.hostname} possesses credentials/connections targeting internal database server ${target.hostname} (${targetIp}).`,
          cves: [...new Set(sourceCves)],
          findings: sourceFindingIds
        };
      }
      else if (sameSubnet && (sourceHasSSH || sourceHasCreds)) {
        edge = {
          source: source.id,
          target: target.id,
          sourceName: source.hostname,
          targetName: target.hostname,
          rule: "Subnet Network Accessibility",
          reason: `Hosts share network segment ${getSubnet(sourceIp)}.x.x. Compromising ${source.hostname} grants direct lateral layer-2 visibility to ${target.hostname}.`,
          cves: [...new Set(sourceCves)],
          findings: sourceFindingIds
        };
      }
      else if (source.hostname.toLowerCase().includes("endpoint") && 
               target.hostname.toLowerCase().includes("host") &&
               (sourceHasCreds || sourceFindings.some(f => f.finding_type === "lateral_movement_vector" || f.vuln_category === "lateral_movement_vector"))) {
        edge = {
          source: source.id,
          target: target.id,
          sourceName: source.hostname,
          targetName: target.hostname,
          rule: "Workstation -> App Server Trust",
          reason: `Workstation ${source.hostname} possesses credentials/movement capabilities targeting server ${target.hostname}.`,
          cves: [...new Set(sourceCves)],
          findings: sourceFindingIds
        };
      }

      if (edge) {
        const edgeKey = `${edge.source}->${edge.target}`;
        if (!visited.has(edgeKey)) {
          visited.add(edgeKey);
          edges.push(edge);
          
          console.log(`[EDGE CREATED]
Source: ${edge.sourceName} (${edge.source})
Destination: ${edge.targetName} (${edge.target})
Relationship Type: ${edge.rule}
Evidence Used: ${edge.reason}
--------------------------------------------------`);
        }
      }
    }
  }

  return edges;
}

export function findChainsFromEdges(edges: InferredEdge[], assets: any[]): any[] {
  const adj = new Map<string, string[]>();
  edges.forEach(e => {
    if (!adj.has(e.source)) adj.set(e.source, []);
    adj.get(e.source)!.push(e.target);
  });

  const paths: string[][] = [];
  
  // Dynamic root discovery: collect all unique nodes in the edges/assets and find those with no incoming edges
  const allNodeIds = new Set<string>();
  edges.forEach(e => {
    allNodeIds.add(e.source);
    allNodeIds.add(e.target);
  });
  assets.forEach(a => allNodeIds.add(a.id));

  const incoming = new Set(edges.map(e => e.target));
  const starts = Array.from(allNodeIds).filter(id => !incoming.has(id));

  const dfs = (curr: string, path: string[]) => {
    if (path.length > 4) {
      paths.push([...path]);
      return;
    }
    const nexts = adj.get(curr) || [];
    if (nexts.length === 0) {
      if (path.length >= 2) {
        paths.push([...path]);
      }
      return;
    }
    for (const next of nexts) {
      if (!path.includes(next)) {
        path.push(next);
        dfs(next, path);
        path.pop();
      }
    }
  };

  starts.forEach(start => {
    dfs(start, [start]);
  });

  return paths;
}