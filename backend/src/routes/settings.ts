import { FastifyInstance } from "fastify";
import { authenticate } from "../core/auth";
import { db } from "../core/db";

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
      if (!req.user) {
        return localSettings;
      }
      try {
        const { data: userData, error } = await db.auth.admin.getUserById(req.user.id);
        if (error || !userData?.user) {
          return localSettings;
        }
        const metadata = userData.user.user_metadata || {};
        return {
          ...localSettings,
          profile: {
            name: metadata.name || "Kaveesh",
            email: metadata.email || userData.user.email || "kaveesh@vyuha.ai",
            title: metadata.title || "Senior SOC Analyst"
          }
        };
      } catch (err) {
        return localSettings;
      }
    }
  );

  app.put(
    "/settings",
    { preHandler: authenticate },
    async (req, reply) => {
      const parsedData = req.body as any;
      if (req.user && parsedData.profile) {
        const { name, email, title } = parsedData.profile;
        try {
          await db.auth.admin.updateUserById(req.user.id, {
            email: email,
            user_metadata: {
              name,
              title,
              email
            }
          });
        } catch (err) {
          app.log.error(err);
        }
      }

      // Merge other properties
      localSettings = {
        ...localSettings,
        ...parsedData
      };

      // Ensure we return the synced state
      if (req.user) {
        try {
          const { data: userData } = await db.auth.admin.getUserById(req.user.id);
          if (userData?.user) {
            const metadata = userData.user.user_metadata || {};
            localSettings.profile = {
              name: metadata.name || "Kaveesh",
              email: metadata.email || userData.user.email || "kaveesh@vyuha.ai",
              title: metadata.title || "Senior SOC Analyst"
            };
          }
        } catch (err) {
          // fallback
        }
      }

      return localSettings;
    }
  );
}
