import { FastifyInstance } from "fastify";
import { authenticate } from "../core/auth";
import { askCopilot } from "../services/ragPipeline";

export default async function copilotRoutes(app: FastifyInstance) {
  app.post<{ Body: { question: string; finding_id?: string } }>(
    "/copilot/ask",
    { preHandler: authenticate },
    async (req, reply) => {
      const { question, finding_id } = req.body;
      if (!question || question.trim().length === 0) {
        return reply.code(400).send({ error: "question is required" });
      }
      try {
        const result = await askCopilot(question, finding_id);
        return result;
      } catch (err: any) {
        req.log.error(err);
        return reply.code(500).send({ error: err.message });
      }
    }
  );
}