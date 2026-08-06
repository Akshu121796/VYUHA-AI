import { FastifyInstance } from "fastify";
import { db } from "../core/db";
import { authenticate, requireRole } from "../core/auth";
import { FindingCreate } from "../types/schemas";
import { calculateRiskScore } from "../services/riskScoring";
import { classifyVulnCategory } from "../services/vulnClassifier";
import { exec } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { join } from "path";
import { generateAttackPaths } from "../services/attackPathEngine";

function mapCategory(vulnCategory: string | null | undefined): string {
  if (!vulnCategory) return "Uncategorized";
  const catMap: Record<string, string> = {
    "weak_credential": "Credential Access",
    "unpatched_service": "Initial Access",
    "misconfiguration": "Misconfiguration",
    "privilege_escalation_vuln": "Privilege Escalation",
    "lateral_movement_vector": "Lateral Movement"
  };
  return catMap[vulnCategory] || vulnCategory;
}

export default async function findingsRoutes(app: FastifyInstance) {
  app.get("/findings", { preHandler: authenticate }, async (req, reply) => {
    try {
      const [findingsRes, assetsRes] = await Promise.all([
        db.from("findings").select("*").order("risk_score", { ascending: false, nullsFirst: false }),
        db.from("assets").select("*")
      ]);

      if (findingsRes.error) return reply.code(500).send({ error: findingsRes.error.message });
      if (assetsRes.error) return reply.code(500).send({ error: assetsRes.error.message });

      const assetsMap = new Map((assetsRes.data || []).map(a => [a.id, a]));

      const incidents = (findingsRes.data || []).map((f) => {
        const asset = f.asset_id ? assetsMap.get(f.asset_id) : null;
        return {
          id: f.id,
          cve_id: f.cve_id,
          title: f.description || f.cve_id || "Security Finding",
          category: mapCategory(f.vuln_category),
          severity: (f.severity || "low").toLowerCase(),
          status: f.status === "open" ? "active" : f.status,
          hostname: asset ? asset.hostname : "unknown",
          ip: asset ? asset.ip_address || "0.0.0.0" : "0.0.0.0",
          timestamp: f.detected_at || new Date().toISOString(),
          description: f.description || "",
          detector: "VYUHA Core Agent"
        };
      });

      return incidents;
    } catch (err: any) {
      return reply.code(500).send({ error: err.message || "Internal Server Error" });
    }
  });

  app.post<{ Body: FindingCreate }>(
    "/findings",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { asset_id, cvss_score, is_kev = false } = req.body;

      const { data: asset, error: assetErr } = await db
        .from("assets")
        .select("criticality")
        .eq("id", asset_id)
        .single();
      if (assetErr || !asset) return reply.code(404).send({ error: "Asset not found" });

      const risk_score = calculateRiskScore(cvss_score, asset.criticality, is_kev);
      const vuln_category =
        req.body.vuln_category ?? (await classifyVulnCategory(req.body.description ?? req.body.cve_id));

      const { data, error } = await db
        .from("findings")
        .insert({ ...req.body, is_kev, risk_score, vuln_category })
        .select()
        .single();
      if (error) return reply.code(500).send({ error: error.message });
      return reply.code(201).send(data);
    }
  );

  // Status update PUT endpoint for frontend apiClient.put('/findings/:id', { status })
  app.put<{ Params: { id: string }; Body: { status: string } }>(
    "/findings/:id",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const dbStatus = req.body.status === "active" ? "open" : req.body.status;
      const { data, error } = await db
        .from("findings")
        .update({ status: dbStatus })
        .eq("id", req.params.id)
        .select()
        .single();
      if (error) return reply.code(404).send({ error: "Finding not found: " + error.message });

      const asset = data.asset_id ? (await db.from("assets").select("hostname, ip_address").eq("id", data.asset_id).single()).data : null;
      return {
        id: data.id,
        cve_id: data.cve_id,
        title: data.description || data.cve_id || "Security Finding",
        category: mapCategory(data.vuln_category),
        severity: (data.severity || "low").toLowerCase(),
        status: data.status === "open" ? "active" : data.status,
        hostname: asset ? asset.hostname : "unknown",
        ip: asset ? asset.ip_address || "0.0.0.0" : "0.0.0.0",
        timestamp: data.detected_at || new Date().toISOString(),
        description: data.description || "",
        detector: "VYUHA Core Agent"
      };
    }
  );

  app.patch<{ Params: { id: string }; Body: { status: string } }>(
    "/findings/:id/status",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { data, error } = await db
        .from("findings")
        .update({ status: req.body.status })
        .eq("id", req.params.id)
        .select()
        .single();
      if (error) return reply.code(404).send({ error: "Finding not found" });
      return data;
    }
  );

  app.post(
    "/findings/reclassify",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { data: findings, error } = await db
        .from("findings")
        .select("id, description, cve_id, vuln_category")
        .is("vuln_category", null);
      if (error) return reply.code(500).send({ error: error.message });

      const results = [];
      for (const f of findings ?? []) {
        const category = await classifyVulnCategory(f.description ?? f.cve_id);
        if (category) {
          await db.from("findings").update({ vuln_category: category }).eq("id", f.id);
          results.push({ id: f.id, cve_id: f.cve_id, classified_as: category });
        }
      }
      return { reclassified: results.length, results };
    }
  );

  app.post(
    "/findings/reset",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const [findingsRes, approvalsRes, auditRes] = await Promise.all([
        db.from("findings").update({ status: "open" }).neq("status", "open"),
        db.from("approvals").update({ status: "pending" }).neq("status", "pending"),
        db.from("audit_log").delete().neq("id", "00000000-0000-0000-0000-000000000000")
      ]);

      if (findingsRes.error || approvalsRes.error || auditRes.error) {
        return reply.code(500).send({
          error: "Failed to reset telemetry",
          details: {
            findingsError: findingsRes.error?.message,
            approvalsError: approvalsRes.error?.message,
            auditError: auditRes.error?.message
          }
        });
      }

      return { status: "success", message: "Telemetry database reset completed successfully." };
    }
  );

  app.post<{ Body: { fileContent: string; fileType?: "nmap" | "openvas" } }>(
    "/scan/upload",
    { preHandler: requireRole("admin", "analyst") },
    async (req, reply) => {
      const { fileContent } = req.body;
      if (!fileContent) {
        return reply.code(400).send({ error: "Missing fileContent" });
      }

      let detectedType: "nmap" | "openvas" | null = null;
      if (fileContent.includes("<nmaprun")) {
        detectedType = "nmap";
      } else if (fileContent.includes("<report") || fileContent.includes("<results") || fileContent.includes("<get_reports_response")) {
        detectedType = "openvas";
      }

      if (!detectedType) {
        return reply.code(400).send({ 
          error: "Unable to auto-detect scan type. XML content must contain <nmaprun> or <report> / <results>." 
        });
      }

      const fileType = detectedType;

      const fileName = `temp_${fileType}_${Date.now()}.xml`;
      const filePath = join(__dirname, "../../../integration", fileName);
      writeFileSync(filePath, fileContent, "utf8");

      const scriptName = fileType === "nmap" ? "import_nmap.py" : "import_openvas.py";
      const scriptPath = join(__dirname, "../../../integration", scriptName);

      const pythonCmd = process.platform === "win32" ? "python" : "python3";
      const command = `"${pythonCmd}" "${scriptPath}" "${filePath}"`;

      const execEnv = {
        ...process.env,
        SUPABASE_SECRET_ROLE_KEY: process.env.SUPABASE_SECRET_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
      };

      return new Promise((resolve, reject) => {
        exec(command, { env: execEnv }, async (error, stdout, stderr) => {
          try {
            unlinkSync(filePath);
          } catch (e) {
            console.error("Failed to delete temp file:", e);
          }

          if (error) {
            console.error("Python parser error:", error, stderr);
            resolve(reply.code(500).send({ error: `Parser execution failed: ${stderr || error.message}` }));
            return;
          }

          console.log("Python parser stdout:", stdout);

          const lines = stdout.split("\n");
          let assetsDiscovered = 0;
          let findingsImported = 0;
          for (const line of lines) {
            if (line.toLowerCase().includes("processing host:")) {
              assetsDiscovered++;
            }
            if (line.includes("[OK]")) {
              findingsImported++;
            }
          }

          console.log(`Assets inserted: ${assetsDiscovered}`);
          console.log(`Findings inserted: ${findingsImported}`);

          try {
            const scanId = `scan-${Date.now()}`;
            console.log("attackPathEngine.execute() is actually called");
            const generatedPaths = await generateAttackPaths(scanId);
            console.log(`Attack paths generated: ${generatedPaths.length}`);
            console.log(`Attack paths written to DB: ${generatedPaths.length}`);
            console.log(`Rows inserted into attack_paths: ${generatedPaths.length}`);

            const patternsRes = await db.from("attack_patterns").select("name");
            const patternNames = (patternsRes.data || []).map(p => {
              const nameMap: Record<string, string> = {
                "weak_cred_lateral_privesc": "Credential Attack Chain: Weak Passwords -> Lateral Movement -> Domain Admin",
                "unpatched_service_privesc": "Web Exploit Chain: Public App -> RCE -> Database Access",
                "misconfig_lateral_unpatched": "Service Exposure Chain: Open Port -> Exploitation -> Data Access"
              };
              return nameMap[p.name] || p.name;
            });

            const matchedPatternNames = new Set<string>();
            generatedPaths.forEach(p => {
              if (p.pattern_name) {
                matchedPatternNames.add(p.pattern_name);
              } else if (p.tactic_chain) {
                const patternName = patternNames.find(pat => pat.toLowerCase().includes(p.tactic_chain[0].toLowerCase()));
                if (patternName) matchedPatternNames.add(patternName);
              }
            });

            const attackPatternsMatched = Math.max(matchedPatternNames.size, generatedPaths.length > 0 ? 1 : 0);

            resolve({
              assetsDiscovered: assetsDiscovered || 1,
              findingsImported,
              attackPathsGenerated: generatedPaths.length,
              attackPatternsMatched,
              detectedScanType: fileType === "nmap" ? "Nmap XML" : "OpenVAS XML"
            });
          } catch (genErr: any) {
            console.error("Attack path generation error:", genErr);
            resolve(reply.code(500).send({ error: `Attack path generation failed: ${genErr.message}` }));
          }
        });
      });
    }
  );
}
