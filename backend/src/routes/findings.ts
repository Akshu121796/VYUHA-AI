import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { FindingCreate } from "../types/schemas";
import { calculateRiskScore } from "../services/riskScoring";
import { classifyVulnCategory } from "../services/vulnClassifier";


export default async function findingsRoutes(app: FastifyInstance) {
  app.get("/findings", { preHandler: authenticate }, async (req, reply) => {
    const { data, error } = await db
      .from("findings")
      .select("*")
      .order("risk_score", { ascending: false, nullsFirst: false });
    if (error) return reply.code(500).send({ error: error.message });
    return data;
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


