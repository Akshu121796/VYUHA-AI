import { FastifyInstance } from "fastify";
import { authenticate } from "../core/auth";

let localReports = [
  { id: "REP-2026-001", title: "Executive SOC2 Audit Compliance Report", timestamp: "03:42:00 Z", size: "4.2 MB", format: "PDF", downloadCount: 14 },
  { id: "REP-2026-002", title: "Boundary Palo Alto Firewall Log Feed", timestamp: "03:02:00 Z", size: "18.5 MB", format: "CSV", downloadCount: 22 },
  { id: "REP-2026-003", title: "ISO27001 Access Management Audit Log", timestamp: "02:15:00 Z", size: "2.1 MB", format: "PDF", downloadCount: 8 }
];

export default async function reportsRoutes(app: FastifyInstance) {
  app.get(
    "/reports",
    { preHandler: authenticate },
    async (req, reply) => {
      return {
        compliance: [
          { id: "COMP-001", name: "ISO 27001", status: "compliant", score: 91 },
          { id: "COMP-002", name: "SOC2 Type II", status: "compliant", score: 95 },
          { id: "COMP-003", name: "GDPR Access", status: "compliant", score: 88 }
        ],
        reports: localReports
      };
    }
  );

  app.post(
    "/reports",
    { preHandler: authenticate },
    async (req, reply) => {
      const newId = `REP-2026-00${localReports.length + 1}`;
      const newReport = {
        id: newId,
        title: "Executive CISO Threat Audit Summary",
        timestamp: "Just Now",
        size: "3.1 MB",
        format: "PDF",
        downloadCount: 0
      };
      localReports = [newReport, ...localReports];
      return newReport;
    }
  );
}
