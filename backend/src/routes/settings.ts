import { FastifyInstance } from "fastify";
import { authenticate } from "../core/auth";

let localSettings = {
  profile: { name: "Kaveesh", email: "kaveesh@vyuha.ai", title: "Senior SOC Analyst" },
  theme: { contrast: "standard" },
  notifications: { slack: "https://hooks.slack.com/services/T00/B00/X00", syslog: "10.120.50.44:514" },
  preferences: { autoIsolate: true, blockLateral: false },
  security: { enable2Fa: true }
};

export default async function settingsRoutes(app: FastifyInstance) {
  app.get(
    "/settings",
    { preHandler: authenticate },
    async (req, reply) => {
      return localSettings;
    }
  );

  app.put(
    "/settings",
    { preHandler: authenticate },
    async (req, reply) => {
      const parsedData = req.body as any;
      localSettings = {
        ...localSettings,
        ...parsedData
      };
      return localSettings;
    }
  );
}
