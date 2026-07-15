import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate } from "../core/auth";

export default async function auditLogRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { action?: string; limit?: string } }>(
    "/audit-log",
    { preHandler: authenticate },
    async (req, reply) => {
      const limit = req.query.limit ? parseInt(req.query.limit) : 50;

      let query = db
        .from("audit_log")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(limit);

      if (req.query.action) {
        query = query.eq("action", req.query.action);
      }

      const { data, error } = await query;
      if (error) return reply.code(500).send({ error: error.message });
      return data;
    }
  );
}