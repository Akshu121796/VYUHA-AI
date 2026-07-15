import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { generateAttackPaths } from "../services/attackPathEngine";

export default async function attackPathsRoutes(app: FastifyInstance) {
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

  app.get("/attack-paths", { preHandler: authenticate }, async (req, reply) => {
    const { data, error } = await db
      .from("attack_paths")
      .select("*")
      .order("risk_score", { ascending: false, nullsFirst: false });
    if (error) return reply.code(500).send({ error: error.message });
    return data;
  });

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