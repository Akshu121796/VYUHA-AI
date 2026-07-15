import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { ApprovalCreate, ApprovalDecision } from "../types/schemas";
import { applySimulatedFix, verifyRemediation } from "../services/remediation";

export default async function approvalsRoutes(app: FastifyInstance) {
  // Analyst requests a fix
  app.post<{ Body: ApprovalCreate }>(
    "/approvals",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data, error } = await db
        .from("approvals")
        .insert({ ...req.body, status: "pending" })
        .select()
        .single();
      if (error) return reply.code(500).send({ error: error.message });

      await db.from("audit_log").insert({
        action: "approval_requested",
        performed_by: req.user!.id,
        details: { approval_id: data.id, finding_id: req.body.finding_id },
      });

      return reply.code(201).send(data);
    }
  );

  app.get<{ Querystring: { status?: string } }>(
    "/approvals",
    { preHandler: authenticate },
    async (req, reply) => {
      let query = db.from("approvals").select("*").order("created_at", { ascending: false });
      if (req.query.status) query = query.eq("status", req.query.status);
      const { data, error } = await query;
      if (error) return reply.code(500).send({ error: error.message });
      return data;
    }
  );

  // Admin-only: approve or reject
  app.patch<{ Params: { id: string }; Body: ApprovalDecision }>(
    "/approvals/:id/decide",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { data, error } = await db
        .from("approvals")
        .update({ status: req.body.decision, approved_by: req.user!.id })
        .eq("id", req.params.id)
        .select()
        .single();
      if (error) return reply.code(404).send({ error: "Approval not found" });

      await db.from("audit_log").insert({
        action: `approval_${req.body.decision}`,
        performed_by: req.user!.id,
        details: { approval_id: req.params.id },
      });

      return data;
    }
  );

  // Apply simulated fix — only valid once approved
  app.post<{ Params: { id: string } }>(
    "/approvals/:id/apply",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data: approval, error } = await db
        .from("approvals")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (error || !approval) return reply.code(404).send({ error: "Approval not found" });
      if (approval.status !== "approved") {
        return reply.code(400).send({ error: "Approval must be in 'approved' state before applying a fix" });
      }

      await applySimulatedFix(approval.id, approval.finding_id, req.user!.id);
      return { status: "applied" };
    }
  );

  // Verify — re-check and close, or flag failed
  app.post<{ Params: { id: string } }>(
    "/approvals/:id/verify",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data: approval, error } = await db
        .from("approvals")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (error || !approval) return reply.code(404).send({ error: "Approval not found" });
      if (approval.status !== "applied") {
        return reply.code(400).send({ error: "Fix must be applied before verification" });
      }

      await verifyRemediation(approval.id, approval.finding_id, req.user!.id);
      return { status: "resolved" };
    }
  );
}