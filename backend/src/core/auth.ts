import { jwtVerify, createRemoteJWKSet } from "jose";
import { FastifyRequest, FastifyReply } from "fastify";
import { config } from "./config";

export interface CurrentUser {
  id: string;
  email: string;
  role: string;
}

declare module "fastify" {
  interface FastifyRequest {
    user?: CurrentUser;
  }
}

const JWKS = createRemoteJWKSet(
  new URL(`${config.supabaseUrl}/auth/v1/.well-known/jwks.json`)
);

export async function authenticate(req: FastifyRequest, reply: FastifyReply) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return reply.code(401).send({ error: "Missing or invalid Authorization header" });
  }

  const token = authHeader.replace("Bearer ", "");

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      audience: "authenticated",
    });

    const role =
      (payload.user_metadata as any)?.role || (payload.app_metadata as any)?.role;

    if (!role) {
      return reply.code(403).send({ error: "No role assigned to this user" });
    }

    req.user = { id: payload.sub as string, email: payload.email as string, role };
  } catch (err) {
    req.log.error(err);
    return reply.code(401).send({ error: "Invalid or expired token" });
  }
}

export function requireRole(...allowedRoles: string[]) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    await authenticate(req, reply);
    if (reply.sent) return;
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return reply.code(403).send({ error: `Requires role: ${allowedRoles.join(", ")}` });
    }
  };
}