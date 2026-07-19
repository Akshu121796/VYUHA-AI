import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate } from "../core/auth";
import { localReports } from "./reports";

export default async function notificationsRoutes(app: FastifyInstance) {
  app.get(
    "/notifications",
    { preHandler: authenticate },
    async (req, reply) => {
      try {
        const [findingsRes, approvalsRes, auditRes] = await Promise.all([
          db.from("findings").select("id, description, detected_at, severity").order("detected_at", { ascending: false }).limit(10),
          db.from("approvals").select("id, recommended_fix, status, created_at").order("created_at", { ascending: false }).limit(10),
          db.from("audit_log")
            .select("id, action, details, created_at")
            .in("action", ["asset_isolated", "asset_reconnected", "process_terminated"])
            .order("created_at", { ascending: false })
            .limit(10)
        ]);

        const notifications: any[] = [];

        // 1. Findings
        if (findingsRes.data) {
          findingsRes.data.forEach((f: any) => {
            notifications.push({
              id: `finding-${f.id}`,
              type: "finding",
              title: "New Finding Detected",
              message: `${f.description || "Security anomaly"} (${f.severity?.toUpperCase()})`,
              timestamp: f.detected_at,
              read: false
            });
          });
        }

        // 2. Approvals (Decisions made)
        if (approvalsRes.data) {
          approvalsRes.data.forEach((a: any) => {
            if (a.status !== "pending") {
              notifications.push({
                id: `approval-${a.id}`,
                type: "approval",
                title: `Mitigation ${a.status.charAt(0).toUpperCase() + a.status.slice(1)}`,
                message: `Remediation action: ${a.recommended_fix || "Approved task"}`,
                timestamp: a.created_at,
                read: false
              });
            }
          });
        }

        // 3. Reports Generated
        localReports.forEach((r: any) => {
          notifications.push({
            id: `report-${r.id}`,
            type: "report",
            title: "Report Exported",
            message: `Document compiled: ${r.title} (${r.format})`,
            timestamp: r.timestamp === "Just Now" ? new Date().toISOString() : new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
            read: false
          });
        });

        // 4. Endpoint Actions
        if (auditRes.data) {
          auditRes.data.forEach((au: any) => {
            let msg = "";
            if (au.action === "asset_isolated") {
              msg = `Host ${au.details?.hostname || "endpoint"} has been isolated from network.`;
            } else if (au.action === "asset_reconnected") {
              msg = `Host ${au.details?.hostname || "endpoint"} has been reconnected to network.`;
            } else if (au.action === "process_terminated") {
              msg = `Process PID ${au.details?.pid} terminated on ${au.details?.hostname || "endpoint"}.`;
            }
            notifications.push({
              id: `endpoint-${au.id}`,
              type: "endpoint",
              title: "Endpoint Action Executed",
              message: msg,
              timestamp: au.created_at,
              read: false
            });
          });
        }

        // Sort by timestamp descending
        notifications.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        return notifications.slice(0, 15);
      } catch (err: any) {
        app.log.error(err);
        return reply.code(500).send({ error: err.message || "Internal Server Error" });
      }
    }
  );
}
