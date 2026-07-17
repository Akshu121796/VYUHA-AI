import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { FindingCreate } from "../types/schemas";
import { calculateRiskScore } from "../services/riskScoring";
import { classifyVulnCategory } from "../services/vulnClassifier";

function mapCategory(vulnCategory: string | null | undefined): string {
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

export default async function findingsRoutes(app: FastifyInstance) {
  app.get("/findings", { preHandler: authenticate }, async (req, reply) => {
    try {
      const [findingsRes, assetsRes] = await Promise.all([
        db.from("findings").select("*").order("risk_score", { ascending: false, nullsFirst: false }),
        db.from("assets").select("*")
      ]);

      if (findingsRes.error) return reply.code(500).send({ error: findingsRes.error.message });
      if (assetsRes.error) return reply.code(500).send({ error: assetsRes.error.message });

      const assetsMap = new Map((assetsRes.data || []).map(a => [a.id, a]));

      const incidents = (findingsRes.data || []).map((f) => {
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

      return incidents;
    } catch (err: any) {
      return reply.code(500).send({ error: err.message || "Internal Server Error" });
    }
  });

  app.post<{ Body: FindingCreate }>(
    "/findings",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { asset_id, cvss_score, is_kev = false } = req.body;

      const { data: asset, error: assetErr } = await db
        .from("assets")
        .select("criticality")
        .eq("id", asset_id)
        .single();
      if (assetErr || !asset) return reply.code(404).send({ error: "Asset not found" });

      const risk_score = calculateRiskScore(cvss_score, asset.criticality, is_kev);
      const vuln_category =
        req.body.vuln_category ?? (await classifyVulnCategory(req.body.description ?? req.body.cve_id));

      const { data, error } = await db
        .from("findings")
        .insert({ ...req.body, is_kev, risk_score, vuln_category })
        .select()
        .single();
      if (error) return reply.code(500).send({ error: error.message });
      return reply.code(201).send(data);
    }
  );

  // Status update PUT endpoint for frontend apiClient.put('/findings/:id', { status })
  app.put<{ Params: { id: string }; Body: { status: string } }>(
    "/findings/:id",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const dbStatus = req.body.status === "active" ? "open" : req.body.status;
      const { data, error } = await db
        .from("findings")
        .update({ status: dbStatus })
        .eq("id", req.params.id)
        .select()
        .single();
      if (error) return reply.code(404).send({ error: "Finding not found: " + error.message });

      const asset = data.asset_id ? (await db.from("assets").select("hostname, ip_address").eq("id", data.asset_id).single()).data : null;
      return {
        id: data.id,
        title: data.description || data.cve_id || "Security Finding",
        category: mapCategory(data.vuln_category),
        severity: (data.severity || "low").toLowerCase(),
        status: data.status === "open" ? "active" : data.status,
        hostname: asset ? asset.hostname : "unknown",
        ip: asset ? asset.ip_address || "0.0.0.0" : "0.0.0.0",
        timestamp: data.detected_at || new Date().toISOString(),
        description: data.description || "",
        detector: "VYUHA Core Agent"
      };
    }
  );

  app.patch<{ Params: { id: string }; Body: { status: string } }>(
    "/findings/:id/status",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data, error } = await db
        .from("findings")
        .update({ status: req.body.status })
        .eq("id", req.params.id)
        .select()
        .single();
      if (error) return reply.code(404).send({ error: "Finding not found" });
      return data;
    }
  );

  app.post(
    "/findings/reclassify",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { data: findings, error } = await db
        .from("findings")
        .select("id, description, cve_id, vuln_category")
        .is("vuln_category", null);
      if (error) return reply.code(500).send({ error: error.message });

      const results = [];
      for (const f of findings ?? []) {
        const category = await classifyVulnCategory(f.description ?? f.cve_id);
        if (category) {
          await db.from("findings").update({ vuln_category: category }).eq("id", f.id);
          results.push({ id: f.id, cve_id: f.cve_id, classified_as: category });
        }
      }
      return { reclassified: results.length, results };
    }
  );
}
