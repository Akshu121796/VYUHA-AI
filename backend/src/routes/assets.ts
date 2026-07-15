import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { AssetCreate } from "../types/schemas";

export default async function assetsRoutes(app: FastifyInstance) {
  app.get("/assets", { preHandler: authenticate }, async (req, reply) => {
    const { data, error } = await db
      .from("assets")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) return reply.code(500).send({ error: error.message });
    return data;
  });

  app.post<{ Body: AssetCreate }>(
    "/assets",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data, error } = await db.from("assets").insert(req.body).select().single();
      if (error) return reply.code(500).send({ error: error.message });
      return reply.code(201).send(data);
    }
  );

  app.get<{ Params: { id: string } }>(
    "/assets/:id",
    { preHandler: authenticate },
    async (req, reply) => {
      const { data, error } = await db
        .from("assets")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (error) return reply.code(404).send({ error: "Asset not found" });
      return data;
    }
  );
}