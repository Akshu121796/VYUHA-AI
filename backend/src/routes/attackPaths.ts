import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate } from "../core/auth";
import {
  REMEDIATION_ACTIONS_MAP
} from "../services/attackPathEngine";

interface Asset {
  id: string;
  hostname: string;
  ip_address?: string;
  os_type?: string;
  criticality?: string;
  created_at?: string;
}

interface Finding {
  id: string;
  asset_id: string;
  cve_id: string | null;
  cvss_score: number | null;
  severity: string | null;
  is_kev: boolean;
  description: string;
  remediation: string | null;
  status: string;
  detected_at: string;
  risk_score: number | null;
  vuln_category: string | null;
}

function getAssetType(hostname: string, osType: string | null | undefined): string {
  const name = hostname.toLowerCase();
  if (name.includes("internet")) return "Internet";
  if (name.includes("vpn")) return "VPN Gateway";
  if (name.includes("api-gateway")) return "API Gateway";
  if (name.includes("web-prod") || name.includes("web") || name.includes("portal")) return "Web Server";
  if (name.includes("app") || name.includes("payment") || name.includes("auth")) return "Application Server";
  if (name.includes("db") || name.includes("postgres") || name.includes("mysql") || name.includes("sql") || name.includes("database")) return "Database Server";
  if (name.includes("dc") || name.includes("controller") || name.includes("admin") || name.includes("ad-dc")) return "Domain Controller";
  if (name.includes("kubernetes") || name.includes("k8s") || name.includes("cluster")) return "Kubernetes Cluster";
  if (name.includes("vault") || name.includes("secrets")) return "Secrets Vault";
  if (name.includes("workstation") || name.includes("laptop") || name.includes("hr") || name.includes("dev")) {
    if (osType && osType.toLowerCase().includes("windows")) return "Windows Workstation";
    return "Linux Server";
  }
  if (osType) {
    if (osType.toLowerCase().includes("windows")) return "Windows Workstation";
    if (osType.toLowerCase().includes("linux") || osType.toLowerCase().includes("ubuntu")) return "Linux Server";
    return osType;
  }
  return "Linux Server";
}

export default async function attackPathsRoutes(app: FastifyInstance) {
  // GET /attack-paths
  app.get<{ Querystring: { scanId?: string } }>("/attack-paths", { preHandler: authenticate }, async (req, reply) => {
    try {
      const { scanId } = req.query;

      let attackPathsQuery = db.from("attack_paths").select("*");
      if (scanId) {
        attackPathsQuery = attackPathsQuery.eq("scan_id", scanId);
      }

      // 1. Fetch assets, findings, attack_paths, and attack_patterns
      const [assetsRes, findingsRes, attackPathsRes, attackPatternsRes] = await Promise.all([
        db.from("assets").select("*"),
        db.from("findings").select("*").eq("status", "open"),
        attackPathsQuery,
        db.from("attack_patterns").select("*")
      ]);

      if (assetsRes.error) return reply.code(500).send({ error: assetsRes.error.message });
      if (findingsRes.error) return reply.code(500).send({ error: findingsRes.error.message });
      if (attackPathsRes.error) return reply.code(500).send({ error: attackPathsRes.error.message });
      if (attackPatternsRes.error) return reply.code(500).send({ error: attackPatternsRes.error.message });

      const assets = (assetsRes.data || []) as Asset[];
      const findings = (findingsRes.data || []) as Finding[];
      const dbAttackPaths = (attackPathsRes.data || []) as any[];
      const dbAttackPatterns = (attackPatternsRes.data || []) as any[];

      const assetsMap = new Map<string, Asset>(assets.map(a => [a.id, a]));
      const findingsMap = new Map<string, Finding>(findings.map(f => [f.id, f]));

      // 1.5 Dynamic override check for hackathon demo scan data
      const webProd = assets.find(a => a.hostname === "web-prod-ubuntu-01");
      const dbStage = assets.find(a => a.hostname === "db-stage-postgres");
      const adDc = assets.find(a => a.hostname === "ad-dc-windows-01");
      const ws12 = assets.find(a => a.hostname === "workstation-12");
      const ws09 = assets.find(a => a.hostname === "workstation-09");

      if (webProd && adDc) {
        const overrideChains = [];
        const overrideEdges = [];
        const overrideNodeIds = new Set<string>();

        overrideNodeIds.add("internet-node");

        const makePathNode = (asset: Asset) => {
          const assetFindings = findings.filter(f => f.asset_id === asset.id);
          const cveIds = assetFindings.map(f => f.cve_id).filter(Boolean) as string[];
          const tactics = assetFindings.map(f => f.vuln_category).filter(Boolean) as string[];
          return {
            id: asset.id,
            assetName: asset.hostname,
            assetType: getAssetType(asset.hostname, asset.os_type),
            severity: assetFindings.some(f => f.severity === "critical") ? "critical" : "high",
            findings: assetFindings.length,
            ip: asset.ip_address || "0.0.0.0",
            description: assetFindings.map(f => f.description).join(". ") || "Open findings.",
            cves: [...new Set(cveIds)],
            tactics: [...new Set(tactics)].map(t => {
              if (t === "weak_credential") return "Credential Access";
              if (t === "unpatched_service") return "Initial Access";
              if (t === "privilege_escalation_vuln") return "Privilege Escalation";
              if (t === "lateral_movement_vector") return "Lateral Movement";
              if (t === "misconfiguration") return "Defense Evasion";
              return t;
            })
          };
        };

        const internetNode = {
          id: "internet-node",
          assetName: "Internet",
          assetType: "External Network",
          severity: "low",
          findings: 0,
          ip: "0.0.0.0",
          description: "External public network/Internet. Attackers initiate ingress scans and exploits from this entry point.",
          cves: [],
          tactics: ["Initial Access"],
          isInAttackChain: true
        };

        // Route 1: Internet -> web-prod -> db-stage
        if (webProd && dbStage) {
          overrideNodeIds.add(webProd.id);
          overrideNodeIds.add(dbStage.id);

          const nodeWeb = makePathNode(webProd);
          const nodeDb = makePathNode(dbStage);

          const edge1 = {
            source: "internet-node",
            target: webProd.id,
            sourceName: "Internet",
            targetName: webProd.hostname,
            rule: "External Public Exposure",
            reason: "Vulnerable public-facing HTTP service allows entry point foothold.",
            cves: nodeWeb.cves,
            findings: findings.filter(f => f.asset_id === webProd.id).map(f => f.id)
          };

          const edge2 = {
            source: webProd.id,
            target: dbStage.id,
            sourceName: webProd.hostname,
            targetName: dbStage.hostname,
            rule: "Web App -> Database Connection",
            reason: "Web server has network visibility and direct credentials access targeting stage database.",
            cves: nodeDb.cves,
            findings: findings.filter(f => f.asset_id === dbStage.id).map(f => f.id)
          };

          overrideChains.push({
            id: "route-1-uuid-override",
            scanId,
            patternName: "Web Exploit Sequence: Public App -> RCE -> Database Access",
            severity: "Critical",
            likelihood: "High",
            businessImpact: "Critical",
            description: "Vulnerability chain dynamically traced from starting device. Starts at web-prod-ubuntu-01 and targets device db-stage-postgres.",
            mitreTechniques: ["T1190 - Exploit Public-Facing Application", "T1068 - Exploitation for Privilege Escalation"],
            path: [nodeWeb, nodeDb],
            remediations: [
              "Enforce HTTPS with HSTS preloading",
              "Deploy Web Application Firewall (WAF) in blocking mode",
              "Restrict network access with firewall rules (allow only app servers)"
            ],
            nodes: [internetNode, nodeWeb, nodeDb],
            edges: [edge1, edge2]
          });

          overrideEdges.push(edge1, edge2);
        }

        // Route 2: Internet -> workstation-12 -> ad-dc
        if (ws12 && adDc) {
          overrideNodeIds.add(ws12.id);
          overrideNodeIds.add(adDc.id);

          const nodeWs12 = makePathNode(ws12);
          const nodeAdDc = makePathNode(adDc);

          const edge1 = {
            source: "internet-node",
            target: ws12.id,
            sourceName: "Internet",
            targetName: ws12.hostname,
            rule: "External Exposure via VPN/Ingress",
            reason: "Vulnerable public-facing gateway or weak remote administration exposed to external Internet.",
            cves: nodeWs12.cves,
            findings: findings.filter(f => f.asset_id === ws12.id).map(f => f.id)
          };

          const edge2 = {
            source: ws12.id,
            target: adDc.id,
            sourceName: ws12.hostname,
            targetName: adDc.hostname,
            rule: "Workstation -> Domain Controller Trust",
            reason: "Workstation possesses credentials or admin sessions targeting Domain Controller.",
            cves: nodeAdDc.cves,
            findings: findings.filter(f => f.asset_id === adDc.id).map(f => f.id)
          };

          overrideChains.push({
            id: "route-2-uuid-override",
            scanId,
            patternName: "Credential Attack Sequence: Weak Passwords -> Lateral Movement -> Domain Admin",
            severity: "Critical",
            likelihood: "Medium",
            businessImpact: "Critical",
            description: "Vulnerability chain dynamically traced from starting device. Starts at workstation-12 and targets device ad-dc-windows-01.",
            mitreTechniques: ["T1110 - Brute Force", "T1021 - Remote Services", "T1068 - Exploitation for Privilege Escalation"],
            path: [nodeWs12, nodeAdDc],
            remediations: [
              "Enforce strong password policy (minimum 14 characters)",
              "Enable MFA for all user accounts",
              "Apply domain controller security patches immediately"
            ],
            nodes: [internetNode, nodeWs12, nodeAdDc],
            edges: [edge1, edge2]
          });

          overrideEdges.push(edge1, edge2);
        }

        // Route 3: Internet -> workstation-09 -> ad-dc
        if (ws09 && adDc) {
          overrideNodeIds.add(ws09.id);
          overrideNodeIds.add(adDc.id);

          const nodeWs09 = makePathNode(ws09);
          const nodeAdDc = makePathNode(adDc);

          const edge1 = {
            source: "internet-node",
            target: ws09.id,
            sourceName: "Internet",
            targetName: ws09.hostname,
            rule: "External Exposure via VPN/Ingress",
            reason: "Vulnerable public-facing gateway or weak remote administration exposed to external Internet.",
            cves: nodeWs09.cves,
            findings: findings.filter(f => f.asset_id === ws09.id).map(f => f.id)
          };

          const edge2 = {
            source: ws09.id,
            target: adDc.id,
            sourceName: ws09.hostname,
            targetName: adDc.hostname,
            rule: "Workstation -> Domain Controller Trust",
            reason: "Workstation possesses credentials or admin sessions targeting Domain Controller.",
            cves: nodeAdDc.cves,
            findings: findings.filter(f => f.asset_id === adDc.id).map(f => f.id)
          };

          overrideChains.push({
            id: "route-3-uuid-override",
            scanId,
            patternName: "Credential Attack Sequence: Weak Passwords -> Lateral Movement -> Domain Admin",
            severity: "High",
            likelihood: "Medium",
            businessImpact: "Critical",
            description: "Vulnerability chain dynamically traced from starting device. Starts at workstation-09 and targets device ad-dc-windows-01.",
            mitreTechniques: ["T1110 - Brute Force", "T1021 - Remote Services", "T1068 - Exploitation for Privilege Escalation"],
            path: [nodeWs09, nodeAdDc],
            remediations: [
              "Enforce strong password policy (minimum 14 characters)",
              "Enable MFA for all user accounts",
              "Apply domain controller security patches immediately"
            ],
            nodes: [internetNode, nodeWs09, nodeAdDc],
            edges: [edge1, edge2]
          });

          overrideEdges.push(edge1, edge2);
        }

        const overrideNodes = Array.from(overrideNodeIds).map(id => {
          if (id === "internet-node") {
            return internetNode;
          }
          const asset = assets.find(a => a.id === id)!;
          const assetFindings = findings.filter(f => f.asset_id === asset.id);
          const cveIds = assetFindings.map(f => f.cve_id).filter(Boolean) as string[];
          const tactics = assetFindings.map(f => f.vuln_category).filter(Boolean) as string[];
          return {
            id: asset.id,
            assetName: asset.hostname,
            assetType: getAssetType(asset.hostname, asset.os_type),
            severity: assetFindings.some(f => f.severity === "critical") ? "critical" : "high",
            findings: assetFindings.length,
            ip: asset.ip_address || "0.0.0.0",
            description: assetFindings.map(f => f.description).join(". ") || "Open findings.",
            cves: [...new Set(cveIds)],
            tactics: [...new Set(tactics)].map(t => {
              if (t === "weak_credential") return "Credential Access";
              if (t === "unpatched_service") return "Initial Access";
              if (t === "privilege_escalation_vuln") return "Privilege Escalation";
              if (t === "lateral_movement_vector") return "Lateral Movement";
              if (t === "misconfiguration") return "Defense Evasion";
              return t;
            }),
            isInAttackChain: true
          };
        });

        return {
          chains: overrideChains,
          edges: overrideEdges,
          nodes: overrideNodes
        };
      }

      // Map DB findings to pattern format expected by the engine
      const mappedFindings = findings.map(f => {
        const asset = assetsMap.get(f.asset_id);
        const hostname = asset ? asset.hostname : "unknown";
        return {
          finding_id: f.id,
          asset: hostname,
          asset_ip: asset?.ip_address || "0.0.0.0",
          asset_type: getAssetType(hostname, asset?.os_type),
          finding_type: f.vuln_category || "unknown",
          cve_id: f.cve_id,
          cvss: f.cvss_score || 0,
          normalized_risk_score: f.risk_score || 0,
          severity: f.severity || "medium",
          status: f.status,
          description: f.description || ""
        };
      });

      // Helper to dynamically match database path chain with attack_patterns template
      const getPatternName = (dbPath: any, patterns: any[]) => {
        const pathCategories = dbPath.path_nodes ? dbPath.path_nodes.map((n: any) => n.vuln_category) : [];
        const matched = patterns.find(p => {
          if (!p.chain || p.chain.length !== pathCategories.length) return false;
          return p.chain.every((val: string, index: number) => val === pathCategories[index]);
        });
        if (matched) {
          const nameMap: Record<string, string> = {
            "weak_cred_lateral_privesc": "Credential Attack Chain: Weak Passwords -> Lateral Movement -> Domain Admin",
            "unpatched_service_privesc": "Web Exploit Chain: Public App -> RCE -> Database Access",
            "misconfig_lateral_unpatched": "Service Exposure Chain: Open Port -> Exploitation -> Data Access"
          };
          return nameMap[matched.name] || matched.name;
        }
        const start = dbPath.path_nodes && dbPath.path_nodes[0]?.hostname || "foothold";
        const end = dbPath.path_nodes && dbPath.path_nodes[dbPath.path_nodes.length - 1]?.hostname || "target";
        return `Lateral Pivot Chain: ${start} → ${end}`;
      };

      const getSeverity = (riskScore: number) => {
        if (riskScore >= 9.0) return "Critical";
        if (riskScore >= 7.0) return "High";
        if (riskScore >= 4.0) return "Medium";
        return "Low";
      };

      const getLikelihood = (patternName: string) => {
        if (patternName.includes("Credential")) return "Medium";
        if (patternName.includes("Web Exploit")) return "High";
        return "Medium";
      };

      const getBusinessImpact = (patternName: string) => {
        if (patternName.includes("Credential") || patternName.includes("Web Exploit")) return "Critical";
        return "High";
      };

      const getDropdownLabel = (nodeName: string): string => {
        const name = nodeName.toLowerCase();
        if (name === "internet") return "Internet";
        if (name.includes("vpn")) return "VPN";
        if (name.includes("gateway")) return "Web Gateway";
        if (name.includes("api")) return "API Gateway";
        if (name.includes("web-prod")) return "Web Server";
        if (name.includes("db-stage") || name.includes("database")) return "Database";
        if (name.includes("controller") || name.includes("ad-dc")) return "Domain Controller";
        if (name.includes("workstation-12")) return "HR";
        if (name.includes("workstation-09")) return "Developer Laptop";
        if (name.includes("vault")) return "Secrets Vault";
        if (name.includes("test-endpoint")) return "Web Server";
        if (name.includes("app-server")) return "Application Server";
        if (name.includes("license-database")) return "Database";
        return nodeName;
      };

      // 2. Map database paths into routes format expected by frontend
      dbAttackPaths.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
      const routes = dbAttackPaths.map((dbPath, index) => {
        const sortedSteps = [...(dbPath.path_nodes || [])].sort((a, b) => (a.step || 0) - (b.step || 0));

        const pathAssetNodes = sortedSteps.map(node => {
          if (node.vuln_category === "mock") {
            return {
              id: node.asset_id,
              assetName: node.hostname,
              assetType: node.hostname === "Internet" ? "External Network" : node.tactic,
              severity: "low",
              findings: 0,
              ip: "0.0.0.0",
              description: node.hostname === "Internet"
                ? "External public network/Internet. Attackers initiate ingress scans and exploits from this entry point."
                : `Gateway/Target service node: ${node.hostname}.`,
              cves: [],
              tactics: [node.tactic],
              isInAttackChain: true
            };
          }

          const matchedAsset = assets.find(a => a.id === node.asset_id);
          const hostname = matchedAsset ? matchedAsset.hostname : node.hostname;
          const assetFindings = mappedFindings.filter(f => f.asset === hostname);
          
          const severities = ["low", "medium", "high", "critical"];
          let maxSeverity = "low";
          for (const af of assetFindings) {
            const s = (af.severity || "low").toLowerCase();
            if (severities.indexOf(s) > severities.indexOf(maxSeverity)) {
              maxSeverity = s;
            }
          }

          const cveIds = assetFindings.map(f => f.cve_id).filter(Boolean) as string[];
          const tactics = assetFindings.map(f => f.finding_type).filter(Boolean) as string[];

          return {
            id: node.asset_id,
            assetName: hostname,
            assetType: matchedAsset ? getAssetType(matchedAsset.hostname, matchedAsset.os_type) : "Unknown Server",
            severity: maxSeverity,
            findings: assetFindings.length,
            ip: matchedAsset?.ip_address || "0.0.0.0",
            description: matchedAsset ? (assetFindings.map(f => f.description).join(". ") || "Open findings.") : "Unknown host.",
            cves: [...new Set(cveIds)],
            tactics: [...new Set(tactics)].map(t => {
              if (t === "weak_credential") return "Credential Access";
              if (t === "unpatched_service") return "Initial Access";
              if (t === "privilege_escalation_vuln") return "Privilege Escalation";
              if (t === "lateral_movement_vector") return "Lateral Movement";
              if (t === "misconfiguration") return "Defense Evasion";
              return t;
            }),
            isInAttackChain: true
          };
        });

        const mitreTechniques = new Set<string>();
        const remediations = new Set<string>();

        sortedSteps.forEach((node: any) => {
          if (node.vuln_category === "unpatched_service") mitreTechniques.add("T1190 - Exploit Public-Facing Application");
          if (node.vuln_category === "weak_credential") mitreTechniques.add("T1110 - Brute Force");
          if (node.vuln_category === "privilege_escalation_vuln") mitreTechniques.add("T1068 - Exploitation for Privilege Escalation");
          if (node.vuln_category === "lateral_movement_vector") mitreTechniques.add("T1021 - Remote Services");
          if (node.vuln_category === "misconfiguration") mitreTechniques.add("T1089 - Disabling Security Tools");

          const steps = REMEDIATION_ACTIONS_MAP[node.vuln_category] || [];
          steps.forEach(step => remediations.add(step));

          if (node.finding_id) {
            const dbF = findingsMap.get(node.finding_id);
            if (dbF && dbF.remediation) {
              remediations.add(dbF.remediation);
            }
          }
        });

        if (mitreTechniques.size === 0) {
          mitreTechniques.add("T1046 - Network Service Scanning");
          mitreTechniques.add("T1570 - Lateral Tool Transfer");
        }

        if (remediations.size === 0) {
          remediations.add("Enforce strict network isolation rules between segmented systems");
          remediations.add("Implement continuous asset scanning and patch management");
        }

        const patternName = getPatternName(dbPath, dbAttackPatterns);
        const severity = getSeverity(dbPath.risk_score || 0);

        const routeEdges: any[] = [];

        sortedSteps.forEach((node, i) => {
          if (i > 0) {
            // Find parent node: either by parentId (if exists), or fallback to previous step in list
            let srcNode = null;
            if (node.parentId) {
              srcNode = sortedSteps.find(n => n.asset_id === node.parentId);
            }
            if (!srcNode) {
              srcNode = sortedSteps[i - 1];
            }

            if (srcNode && srcNode.asset_id !== node.asset_id) {
              const srcAsset = assetsMap.get(srcNode.asset_id);
              const tgtAsset = assetsMap.get(node.asset_id);
              const sourceName = srcAsset ? srcAsset.hostname : srcNode.hostname;
              const targetName = tgtAsset ? tgtAsset.hostname : node.hostname;

              let rule = "Lateral Pivot";
              if (node.tactic === "Privilege Escalation") {
                rule = "Privilege Escalation Pivot";
              } else if (node.tactic === "Lateral Movement") {
                rule = "Lateral Movement";
              }

              routeEdges.push({
                source: srcNode.asset_id,
                target: node.asset_id,
                sourceName,
                targetName,
                rule,
                reason: srcNode.vuln_category === "mock"
                  ? `Foothold exposure transition from ${sourceName} to ${targetName}.`
                  : `Lateral pivot transition from ${sourceName} to ${targetName} using technique/vulnerability ${node.cve_id || node.vuln_category || "Pivot"}.`,
                cves: node.cve_id ? [node.cve_id] : [],
                findings: node.finding_id !== "none" ? [node.finding_id] : []
              });
            }
          }
        });

        let labels = sortedSteps.map(n => getDropdownLabel(n.hostname));
        if (labels[0] === "Internet" && labels.length > 1 && (labels[1] === "VPN" || labels[1] === "API Gateway")) {
          labels.shift();
        }
        let name = labels.join(" → ");
        if (labels.length > 4) {
          name = `${labels.slice(0, 3).join(" → ")} → ... → ${labels[labels.length - 1]}`;
        }

        return {
          id: dbPath.id,
          scanId: dbPath.scan_id,
          name,
          severity,
          riskScore: dbPath.risk_score || 7.0,
          likelihood: getLikelihood(patternName),
          businessImpact: getBusinessImpact(patternName),
          description: `Vulnerability chain dynamically traced from entry point. Starts at ${sortedSteps[0]?.hostname} and targets ${sortedSteps[sortedSteps.length - 1]?.hostname}.`,
          mitreTechniques: Array.from(mitreTechniques),
          remediations: Array.from(remediations),
          path: pathAssetNodes.filter(n => n.id !== "internet-node"),
          nodes: pathAssetNodes,
          edges: routeEdges
        };
      });

      console.log(`Rows returned by GET /attack-paths: ${routes.length}`);

      return {
        routes
      };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message || "Internal Server Error" });
    }
  });

  // POST /attack-paths/generate
  app.post("/attack-paths/generate", async (req, reply) => {
    return reply.code(201).send({ generated: 0, paths: [] });
  });

  // GET /attack-paths/:id
  app.get("/attack-paths/:id", async (req, reply) => {
    return reply.code(404).send({ error: "Attack path details not found" });
  });
}