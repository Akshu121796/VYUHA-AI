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
  if (name.includes("web") || name.includes("portal")) return "Web Server";
  if (name.includes("app") || name.includes("payment") || name.includes("auth")) return "Application Server";
  if (name.includes("db") || name.includes("postgres") || name.includes("mysql") || name.includes("sql")) return "Database Server";
  if (name.includes("dc") || name.includes("controller") || name.includes("admin")) return "Domain Controller";
  if (name.includes("workstation") || name.includes("host") || name.includes("endpoint")) return "Workstation";
  if (osType) return osType;
  return "Ubuntu Server";
}

export default async function attackPathsRoutes(app: FastifyInstance) {
  // GET /attack-paths
  app.get("/attack-paths", { preHandler: authenticate }, async (req, reply) => {
    try {
      // 1. Fetch assets, findings, attack_paths, and attack_patterns
      const [assetsRes, findingsRes, attackPathsRes, attackPatternsRes] = await Promise.all([
        db.from("assets").select("*"),
        db.from("findings").select("*").eq("status", "open"),
        db.from("attack_paths").select("*"),
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

      // 2. Map database paths into Chains format expected by frontend
      const chains = dbAttackPaths.map((dbPath, index) => {
        const uniqueAssetIdsOnPath: string[] = [];
        dbPath.path_nodes?.forEach((node: any) => {
          if (node.asset_id && !uniqueAssetIdsOnPath.includes(node.asset_id)) {
            uniqueAssetIdsOnPath.push(node.asset_id);
          }
        });

        const pathAssetNodes = uniqueAssetIdsOnPath.map(assetId => {
          const matchedAsset = assets.find(a => a.id === assetId);
          const hostname = matchedAsset ? matchedAsset.hostname : "unknown";
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
            id: assetId,
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
            })
          };
        });

        const mitreTechniques = new Set<string>();
        const remediations = new Set<string>();

        dbPath.path_nodes?.forEach((node: any) => {
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

        return {
          id: dbPath.id,
          patternName,
          severity,
          likelihood: getLikelihood(patternName),
          businessImpact: getBusinessImpact(patternName),
          description: `Vulnerability chain dynamically traced from entry point. Starts at ${pathAssetNodes[0]?.assetName || "unknown"} and targets ${pathAssetNodes[pathAssetNodes.length - 1]?.assetName || "unknown"}.`,
          mitreTechniques: Array.from(mitreTechniques),
          path: pathAssetNodes,
          remediations: Array.from(remediations)
        };
      });

      // 3. Build unique nodes list (one node per asset mapped across all paths)
      const uniqueAssetIds = new Set<string>();
      dbAttackPaths.forEach(dbPath => {
        dbPath.path_nodes?.forEach((node: any) => {
          if (node.asset_id) {
            uniqueAssetIds.add(node.asset_id);
          }
        });
      });

      const allAssetNodes = Array.from(uniqueAssetIds).map(assetId => {
        const asset = assetsMap.get(assetId);
        const hostname = asset ? asset.hostname : "unknown";
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
          id: assetId,
          assetName: hostname,
          assetType: asset ? getAssetType(asset.hostname, asset.os_type) : "Unknown Server",
          severity: maxSeverity,
          findings: assetFindings.length,
          ip: asset?.ip_address || "0.0.0.0",
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

      if (allAssetNodes.length > 0) {
        allAssetNodes.unshift({
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
        });
      }

      // 4. Build unified edges list merging transitions across all paths to support a branching tree
      const edgeMap = new Map<string, {
        source: string;
        target: string;
        sourceName: string;
        targetName: string;
        rule: string;
        reason: string;
        cves: Set<string>;
        findings: Set<string>;
      }>();

      dbAttackPaths.forEach(dbPath => {
        const nodes = dbPath.path_nodes || [];
        if (nodes.length === 0) return;

        // Initial entry point edge
        const firstNode = nodes[0];
        if (firstNode && firstNode.asset_id) {
          const key = `internet-node->${firstNode.asset_id}`;
          if (!edgeMap.has(key)) {
            const targetAsset = assetsMap.get(firstNode.asset_id);
            const targetName = targetAsset ? targetAsset.hostname : "unknown";
            edgeMap.set(key, {
              source: "internet-node",
              target: firstNode.asset_id,
              sourceName: "Internet",
              targetName,
              rule: "External Public Exposure",
              reason: `Vulnerable public-facing service (${firstNode.cve_id || "HTTP/Gateway"}) allows entry point foothold on ${targetName}.`,
              cves: new Set(firstNode.cve_id ? [firstNode.cve_id] : []),
              findings: new Set(firstNode.finding_id ? [firstNode.finding_id] : [])
            });
          } else {
            const edge = edgeMap.get(key)!;
            if (firstNode.cve_id) edge.cves.add(firstNode.cve_id);
            if (firstNode.finding_id) edge.findings.add(firstNode.finding_id);
          }
        }

        // Branching path transitions
        for (let i = 0; i < nodes.length - 1; i++) {
          const srcNode = nodes[i];
          const tgtNode = nodes[i+1];

          if (srcNode.asset_id && tgtNode.asset_id && srcNode.asset_id !== tgtNode.asset_id) {
            const key = `${srcNode.asset_id}->${tgtNode.asset_id}`;
            const srcAsset = assetsMap.get(srcNode.asset_id);
            const tgtAsset = assetsMap.get(tgtNode.asset_id);
            const sourceName = srcAsset ? srcAsset.hostname : "unknown";
            const targetName = tgtAsset ? tgtAsset.hostname : "unknown";

            let rule = "Lateral Pivot";
            if (tgtNode.tactic === "Privilege Escalation") {
              rule = "Privilege Escalation Pivot";
            } else if (tgtNode.tactic === "Lateral Movement") {
              rule = "Lateral Movement";
            }

            const reason = `Lateral pivot transition from ${sourceName} to ${targetName} using technique/vulnerability ${tgtNode.cve_id || tgtNode.vuln_category || "Pivot"}.`;

            if (!edgeMap.has(key)) {
              edgeMap.set(key, {
                source: srcNode.asset_id,
                target: tgtNode.asset_id,
                sourceName,
                targetName,
                rule,
                reason,
                cves: new Set(tgtNode.cve_id ? [tgtNode.cve_id] : []),
                findings: new Set(tgtNode.finding_id ? [tgtNode.finding_id] : [])
              });
            } else {
              const edge = edgeMap.get(key)!;
              if (tgtNode.cve_id) edge.cves.add(tgtNode.cve_id);
              if (tgtNode.finding_id) edge.findings.add(tgtNode.finding_id);
            }
          }
        }
      });

      const inferredEdges = Array.from(edgeMap.values()).map(edge => ({
        source: edge.source,
        target: edge.target,
        sourceName: edge.sourceName,
        targetName: edge.targetName,
        rule: edge.rule,
        reason: edge.reason,
        cves: Array.from(edge.cves),
        findings: Array.from(edge.findings)
      }));

      return {
        chains,
        edges: inferredEdges,
        nodes: allAssetNodes
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