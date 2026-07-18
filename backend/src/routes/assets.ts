import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { AssetCreate } from "../types/schemas";
import { toggleIsolation, terminateProcess } from "../services/assetState";
import { mapAssetToEndpoint } from "../utils/assetMapper";

export default async function assetsRoutes(app: FastifyInstance) {
  // Get all assets mapped to Endpoint shape
  app.get("/assets", { preHandler: authenticate }, async (req, reply) => {
    const [assetsRes, findingsRes] = await Promise.all([
      db.from("assets").select("*").order("created_at", { ascending: false }),
      db.from("findings").select("*")
    ]);
    if (assetsRes.error) return reply.code(500).send({ error: assetsRes.error.message });
    if (findingsRes.error) return reply.code(500).send({ error: findingsRes.error.message });

    const dbAssets = assetsRes.data || [];
    const dbFindings = findingsRes.data || [];

    return dbAssets.map(asset => mapAssetToEndpoint(asset, dbFindings));
  });

  // Create an asset
  app.post<{ Body: AssetCreate }>(
    "/assets",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data, error } = await db.from("assets").insert(req.body).select().single();
      if (error) return reply.code(500).send({ error: error.message });
      return reply.code(201).send(data);
    }
  );

  // Get specific asset mapped to Endpoint shape
  app.get<{ Params: { id: string } }>(
    "/assets/:id",
    { preHandler: authenticate },
    async (req, reply) => {
      const [assetRes, findingsRes] = await Promise.all([
        db.from("assets").select("*").eq("id", req.params.id).single(),
        db.from("findings").select("*").eq("asset_id", req.params.id)
      ]);
      if (assetRes.error || !assetRes.data) return reply.code(404).send({ error: "Asset not found" });
      if (findingsRes.error) return reply.code(500).send({ error: findingsRes.error.message });

      return mapAssetToEndpoint(assetRes.data, findingsRes.data || []);
    }
  );

  // Toggle network isolation for an asset
  app.put<{ Params: { id: string } }>(
    "/assets/:id/isolate",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data: asset, error: assetErr } = await db
        .from("assets")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (assetErr || !asset) return reply.code(404).send({ error: "Asset not found" });

      const newIsolateState = toggleIsolation(asset.id, asset.hostname);

      // Audit log the isolation change
      await db.from("audit_log").insert({
        action: newIsolateState ? "asset_isolated" : "asset_reconnected",
        performed_by: req.user!.id,
        details: { asset_id: asset.id, hostname: asset.hostname },
      });

      const { data: findings, error: findingsErr } = await db
        .from("findings")
        .select("*")
        .eq("asset_id", asset.id);

      return mapAssetToEndpoint(asset, findings || []);
    }
  );

  // Terminate a process on an asset
  app.put<{ Params: { id: string }; Body: { pid: number } }>(
    "/assets/:id/terminate-process",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { pid } = req.body;
      if (typeof pid !== "number") {
        return reply.code(400).send({ error: "Invalid pid parameter" });
      }

      const { data: asset, error: assetErr } = await db
        .from("assets")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (assetErr || !asset) return reply.code(404).send({ error: "Asset not found" });

      terminateProcess(asset.id, pid);

      // Audit log the process termination
      await db.from("audit_log").insert({
        action: "process_terminated",
        performed_by: req.user!.id,
        details: { asset_id: asset.id, hostname: asset.hostname, pid },
      });

      const { data: findings, error: findingsErr } = await db
        .from("findings")
        .select("*")
        .eq("asset_id", asset.id);

      return mapAssetToEndpoint(asset, findings || []);
    }
  );
}