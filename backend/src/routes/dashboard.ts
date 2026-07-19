import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { mapAssetToEndpoint, mapCategory } from "../utils/assetMapper";

function deduceAction(recommendedFix: string | null | undefined, vulnCategory: string | null | undefined): "isolate_host" | "terminate_process" | "block_ip" | "quarantine_file" {
  const fixText = (recommendedFix || "").toLowerCase();
  if (fixText.includes("isolate") || fixText.includes("quarantine host")) {
    return "isolate_host";
  }
  if (fixText.includes("process") || fixText.includes("terminate") || fixText.includes("kill")) {
    return "terminate_process";
  }
  if (fixText.includes("block") || fixText.includes("ip") || fixText.includes("firewall")) {
    return "block_ip";
  }
  if (fixText.includes("quarantine") || fixText.includes("file") || fixText.includes("remove")) {
    return "quarantine_file";
  }
  if (vulnCategory === "privilege_escalation_vuln" || vulnCategory === "weak_credential") {
    return "isolate_host";
  }
  return "quarantine_file";
}

export default async function dashboardRoutes(app: FastifyInstance) {
  app.get("/dashboard", async (req, reply) => {
    try {
      const [findingsRes, assetsRes, approvalsRes, auditLogsRes] = await Promise.all([
        db.from("findings").select("*"),
        db.from("assets").select("*"),
        db.from("approvals").select("*"),
        db.from("audit_log").select("*").order("created_at", { ascending: false }).limit(20)
      ]);

      if (findingsRes.error) return reply.code(500).send({ error: findingsRes.error.message });
      if (assetsRes.error) return reply.code(500).send({ error: assetsRes.error.message });
      if (approvalsRes.error) return reply.code(500).send({ error: approvalsRes.error.message });

      const dbFindings = findingsRes.data || [];
      const dbAssets = assetsRes.data || [];
      const dbApprovals = approvalsRes.data || [];
      const dbAuditLogs = auditLogsRes.error ? [] : auditLogsRes.data || [];

      // Create mapping lookups
      const assetsMap = new Map(dbAssets.map((asset) => [asset.id, asset]));
      const findingsMap = new Map(dbFindings.map((finding) => [finding.id, finding]));

      // 1. Map incidents
      const incidents = dbFindings.map((f) => {
        const asset = f.asset_id ? assetsMap.get(f.asset_id) : null;
        return {
          id: f.id,
          title: f.description || f.cve_id || "Security Finding",
          category: mapCategory(f.vuln_category),
          severity: (f.severity || "low").toLowerCase(),
          status: f.status === "open" ? "active" : f.status,
          hostname: asset ? asset.hostname : "unknown",
          ip: asset ? asset.ip_address || "0.0.0.0" : "0.0.0.0",
          timestamp: f.detected_at || new Date().toISOString(),
          description: f.description || "",
          detector: "VYUHA Core Agent"
        };
      });

      // 2. Map endpoints (reusing mapAssetToEndpoint utility)
      const endpoints = dbAssets.map((asset) => mapAssetToEndpoint(asset, dbFindings));

      // 3. Map approvals
      const approvals = dbApprovals.map((appr) => {
        const finding = appr.finding_id ? findingsMap.get(appr.finding_id) : null;
        const asset = finding?.asset_id ? assetsMap.get(finding.asset_id) : null;
        
        return {
          id: appr.id,
          action: deduceAction(appr.recommended_fix, finding?.vuln_category),
          target: asset ? asset.hostname : "unknown",
          requester: "VYUHA Core Agent",
          reason: finding ? finding.description || "Suspicious event" : "Security threat mitigation required",
          status: appr.status || "pending",
          timestamp: appr.created_at || new Date().toISOString(),
          details: appr.recommended_fix || ""
        };
      });

      return {
        incidents,
        endpoints,
        approvals,
        auditLogs: dbAuditLogs
      };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message || "Internal Server Error" });
    }
  });
}