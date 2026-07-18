import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { generateAttackPaths } from "../services/attackPathEngine";

function getLabelForTactic(tactic: string, category: string | null): string {
  if (tactic === "Initial Access") return "Compromised Access";
  if (tactic === "Privilege Escalation") return "Privilege Escalation";
  if (tactic === "Credential Access" || tactic === "Credential Dumping") return "Credential Dump";
  if (tactic === "Lateral Movement") return "Lateral Movement";
  if (tactic === "Persistence") return "Persistence Guard";
  if (tactic === "Exfiltration & Impact") return "Exfiltration Path";
  return category || tactic;
}

function getIconForTactic(tactic: string): string {
  const t = tactic.toLowerCase();
  if (t.includes("initial") || t.includes("credentials")) return "key";
  if (t.includes("escalation") || t.includes("privilege")) return "terminal";
  if (t.includes("credential")) return "shield-alert";
  if (t.includes("lateral") || t.includes("network")) return "network";
  return "shield-check";
}

function getPositionForTactic(tactic: string, step: number): { x: number; y: number } {
  const t = tactic.toLowerCase();
  if (t.includes("initial")) return { x: 40, y: 150 };
  if (t.includes("escalation")) return { x: 280, y: 150 };
  if (t.includes("credential")) return { x: 520, y: 40 };
  if (t.includes("lateral")) return { x: 520, y: 260 };
  if (t.includes("persistence") || t.includes("exfiltration") || t.includes("domain")) return { x: 760, y: 150 };
  return { x: 40 + (step - 1) * 240, y: 150 };
}

// Full mock attack path fallback for safety/demo stability
const defaultNodes = [
  {
    id: "weak-credentials",
    type: "attackNode",
    data: {
      id: "weak-credentials",
      subtitle: "Initial Access",
      label: "Weak Credentials",
      severity: "high",
      icon: "key",
      tooltip: "External SSH login logged on web-prod-ubuntu-01 matching public dictionaries.",
      ip: "185.220.101.44 (WAN)",
      description: "Threat actor performed credential brute-forcing targeting active directory external accounts. Credentials matching administrative wordlists were successfully authenticated.",
      mitigations: [
        "Deploy Palo Alto IP firewall block",
        "Enforce active multi-factor verification",
        "Force domain credentials rollback"
      ]
    },
    position: { x: 40, y: 150 }
  },
  {
    id: "privilege-escalation",
    type: "attackNode",
    data: {
      id: "privilege-escalation",
      subtitle: "Privilege Escalation",
      label: "Privilege Escalation",
      severity: "critical",
      icon: "terminal",
      tooltip: "Exploitation of CVE-2024-3094 to execute bash root shells on web-prod-ubuntu-01.",
      ip: "web-prod-ubuntu-01 (10.120.40.8)",
      description: "Attacker exploited a supply-chain backdoor (CVE-2024-3094) inside xz-utils compilation. Backdoor hooks enabled remote root terminal commands execution without security checks.",
      mitigations: [
        "Quarantine host web-prod-ubuntu-01",
        "Roll back library dependencies to 5.4.1",
        "Terminate active bash console processes"
      ]
    },
    position: { x: 280, y: 150 }
  },
  {
    id: "credential-dumping",
    type: "attackNode",
    data: {
      id: "credential-dumping",
      subtitle: "Credential Access",
      label: "Credential Dumping",
      severity: "critical",
      icon: "shield-alert",
      tooltip: "LSASS process memory read handles queried on ad-dc-windows-01 domain server.",
      ip: "ad-dc-windows-01 (10.120.40.2)",
      description: "Attacker executed administrative LSASS memory dumps on the Active Directory domain controller workstation. Process credentials retrieved to obtain domain keys.",
      mitigations: [
        "Enable LSA protection registry keys",
        "Invalidate DC Kerberos auth keys",
        "Quarantine host ad-dc-windows-01"
      ]
    },
    position: { x: 520, y: 40 }
  },
  {
    id: "lateral-movement",
    type: "attackNode",
    data: {
      id: "lateral-movement",
      subtitle: "Lateral Movement",
      label: "Lateral Movement",
      severity: "high",
      icon: "network",
      tooltip: "Secured RDP connections logged between web server groups and domain controller hosts.",
      ip: "VLAN-Segment (10.120.40.0/24)",
      description: "Attacker leveraged compromised credentials to establish internal RDP sessions from web production segments into domain management segments.",
      mitigations: [
        "Sever RDP session routes",
        "Enforce localized firewall segment blocks",
        "Trigger credentials rollbacks"
      ]
    },
    position: { x: 520, y: 260 }
  },
  {
    id: "domain-admin",
    type: "attackNode",
    data: {
      id: "domain-admin",
      subtitle: "Exfiltration & Impact",
      label: "Domain Admin",
      severity: "critical",
      icon: "shield-check",
      tooltip: "Threat actor captures Domain Admin registry credentials. Full domain compromise imminent.",
      ip: "ad-dc-windows-01 (Active Directory Forest)",
      description: "Threat actor achieves full Domain Controller authorization, gaining unrestricted administrative read/write access controls over local directory assets.",
      mitigations: [
        "Execute disaster recovery schemas",
        "Trigger global SOC incident responses",
        "Invalidate active directory trust forest"
      ]
    },
    position: { x: 760, y: 150 }
  }
];

const defaultEdges = [
  { 
    id: "e-weak-priv", 
    source: "weak-credentials", 
    target: "privilege-escalation", 
    animated: true,
    style: { stroke: "#f59e0b", strokeWidth: 2 },
    markerEnd: { type: "arrowclosed", color: "#f59e0b" }
  },
  { 
    id: "e-priv-dump", 
    source: "privilege-escalation", 
    target: "credential-dumping", 
    animated: true,
    style: { stroke: "#ef4444", strokeWidth: 2 },
    markerEnd: { type: "arrowclosed", color: "#ef4444" }
  },
  { 
    id: "e-priv-lat", 
    source: "privilege-escalation", 
    target: "lateral-movement", 
    animated: true,
    style: { stroke: "#f59e0b", strokeWidth: 2 },
    markerEnd: { type: "arrowclosed", color: "#f59e0b" }
  },
  { 
    id: "e-dump-admin", 
    source: "credential-dumping", 
    target: "domain-admin", 
    animated: true,
    style: { stroke: "#ef4444", strokeWidth: 2 },
    markerEnd: { type: "arrowclosed", color: "#ef4444" }
  },
  { 
    id: "e-lat-admin", 
    source: "lateral-movement", 
    target: "domain-admin", 
    animated: true,
    style: { stroke: "#ef4444", strokeWidth: 2 },
    markerEnd: { type: "arrowclosed", color: "#ef4444" }
  }
];

export default async function attackPathsRoutes(app: FastifyInstance) {
  // Trigger generation
  app.post<{ Body: { scan_id?: string } }>(
    "/attack-paths/generate",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const scanId = req.body?.scan_id ?? `scan-${Date.now()}`;
      try {
        const paths = await generateAttackPaths(scanId);
        return reply.code(201).send({ generated: paths.length, paths });
      } catch (err: any) {
        return reply.code(500).send({ error: err.message });
      }
    }
  );

  // Get active graph nodes/edges
  app.get("/attack-paths", { preHandler: authenticate }, async (req, reply) => {
    try {
      const { data: paths, error } = await db
        .from("attack_paths")
        .select("*")
        .order("created_at", { ascending: false });

      if (error) return reply.code(500).send({ error: error.message });

      if (!paths || paths.length === 0) {
        return { nodes: defaultNodes, edges: defaultEdges };
      }

      // Format the latest generated attack path
      const activePath = paths[0];
      const pathNodes = activePath.path_nodes || [];

      const findingIds = pathNodes.map((n: any) => n.finding_id).filter(Boolean);
      const assetIds = pathNodes.map((n: any) => n.asset_id).filter(Boolean);

      const [findingsRes, assetsRes] = await Promise.all([
        db.from("findings").select("*").in("id", findingIds),
        db.from("assets").select("id, ip_address").in("id", assetIds)
      ]);

      const findingsMap = new Map((findingsRes.data || []).map(f => [f.id, f]));
      const assetsMap = new Map((assetsRes.data || []).map(a => [a.id, a]));

      // Convert path_nodes to React Flow nodes
      const nodes = pathNodes.map((step: any) => {
        const finding = findingsMap.get(step.finding_id);
        const asset = assetsMap.get(step.asset_id);

        const id = `node-${step.step}`;
        const subtitle = step.tactic || "Threat Vector";
        const label = getLabelForTactic(step.tactic, step.vuln_category);
        const severity = (finding?.severity || "medium").toLowerCase();
        const icon = getIconForTactic(step.tactic);
        
        const ip = asset?.ip_address || "0.0.0.0";
        const tooltip = finding?.description || `${step.tactic} detected on ${step.hostname}`;
        const description = finding?.description || `A security issue of category ${step.vuln_category} was detected.`;
        
        const mitigations = finding?.remediation
          ? [finding.remediation]
          : ["Isolate network interface", "Remediate threat vector"];

        return {
          id,
          type: "attackNode",
          data: {
            id,
            subtitle,
            label,
            severity,
            icon,
            tooltip,
            ip: `${step.hostname} (${ip})`,
            description,
            mitigations
          },
          position: getPositionForTactic(step.tactic, step.step)
        };
      });

      // Construct edges sequentially
      const edges = [];
      for (let i = 0; i < nodes.length - 1; i++) {
        const source = nodes[i].id;
        const target = nodes[i + 1].id;
        const severity = nodes[i + 1].data.severity;
        const strokeColor = severity === "critical" ? "#ef4444" : severity === "high" ? "#f59e0b" : "#2563eb";
        
        edges.push({
          id: `edge-${source}-${target}`,
          source,
          target,
          animated: true,
          style: { stroke: strokeColor, strokeWidth: 2 },
          markerEnd: { type: "arrowclosed", color: strokeColor }
        });
      }

      return { nodes, edges };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message || "Internal Server Error" });
    }
  });

  // Get specific attack path
  app.get<{ Params: { id: string } }>(
    "/attack-paths/:id",
    { preHandler: authenticate },
    async (req, reply) => {
      const { data, error } = await db
        .from("attack_paths")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (error) return reply.code(404).send({ error: "Attack path not found" });
      return data;
    }
  );
}