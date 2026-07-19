import Fastify from "fastify";
import cors from "@fastify/cors";
import { config } from "./core/config";
import assetsRoutes from "./routes/assets";
import findingsRoutes from "./routes/findings";
import attackPathsRoutes from "./routes/attackPaths";
import approvalsRoutes from "./routes/approvals";
import copilotRoutes from "./routes/copilot";
import auditLogRoutes from "./routes/auditLog";
import dashboardRoutes from "./routes/dashboard";
import reportsRoutes from "./routes/reports";
import settingsRoutes from "./routes/settings";
import notificationsRoutes from "./routes/notifications";

const app = Fastify({ logger: true });

async function main() {
  await app.register(cors, {
    origin: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  });

  app.get("/health", async () => ({ status: "ok" }));

  await app.register(assetsRoutes);
  await app.register(findingsRoutes);
  await app.register(attackPathsRoutes);
  await app.register(approvalsRoutes);
  await app.register(copilotRoutes);
  await app.register(auditLogRoutes);
  await app.register(dashboardRoutes);
  await app.register(reportsRoutes);
  await app.register(settingsRoutes);
  await app.register(notificationsRoutes);
  await app.listen({ port: config.port, host: "0.0.0.0" });
}

main().catch((err) => {
  app.log.error(err);
  process.exit(1);
});