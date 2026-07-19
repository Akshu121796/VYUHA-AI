import { db } from "../core/db";
import { config } from "../core/config";

interface KnowledgeChunk {
  ref_id: string;
  title: string;
  content: string;
}

// Full-text search against the MITRE reference table — plainto_tsquery
// handles arbitrary user phrasing without needing exact keyword matches.
async function retrieveKnowledge(question: string, limit = 3): Promise<KnowledgeChunk[]> {
  const { data, error } = await db.rpc("search_knowledge_base", {
    query_text: question,
    match_limit: limit,
  });
  if (error) throw new Error(error.message);
  return data ?? [];
}

function buildPrompt(
  question: string,
  findings: any[],
  assets: any[],
  approvals: any[],
  attackPaths: any[],
  knowledge: KnowledgeChunk[]
): string {
  const findingsBlock = findings
    .map(
      (f, i) =>
        `- Finding ID: ${f.id}, CVE: ${f.cve_id ?? "N/A"}, Severity: ${f.severity ?? "N/A"}, Risk Score: ${f.risk_score ?? "N/A"}, Status: ${f.status ?? "N/A"}, Category: ${f.vuln_category ?? "uncategorized"}\n  Description: ${f.description ?? "N/A"}`
    )
    .join("\n");

  const assetsBlock = assets
    .map(
      (a) =>
        `- Asset ID: ${a.id}, Hostname: ${a.hostname}, IP: ${a.ip_address ?? "0.0.0.0"}, Alerts: [Critical: ${a.critical_alerts_count ?? 0}, High: ${a.high_alerts_count ?? 0}, Medium: ${a.medium_alerts_count ?? 0}]`
    )
    .join("\n");

  const approvalsBlock = approvals
    .map(
      (appr) =>
        `- Approval ID: ${appr.id}, Finding ID: ${appr.finding_id ?? "N/A"}, Fix: ${appr.recommended_fix ?? "N/A"}, Status: ${appr.status ?? "pending"}`
    )
    .join("\n");

  const attackPathsBlock = attackPaths
    .map(
      (ap) =>
        `- Attack Path ID: ${ap.id}, Nodes: ${JSON.stringify(ap.path_nodes || [])}`
    )
    .join("\n");

  const knowledgeBlock = knowledge
    .map((k) => `[${k.ref_id} — ${k.title}]: ${k.content}`)
    .join("\n\n");

  return `You are VYUHA AI, an enterprise SOC cybersecurity analyst assisting security operators.

Always prioritize project telemetry.

If the telemetry directly answers the question:
- Explain the findings clearly.
- Reference CVEs, assets, attack paths, approvals and MITRE ATT&CK techniques whenever applicable.

If telemetry is incomplete:
- Clearly state what information is missing.
- Continue answering using your cybersecurity knowledge.
- Relate your explanation back to the available telemetry whenever possible.

Never refuse a cybersecurity question simply because it is absent from telemetry.

Your responses should sound like a professional SOC analyst, not a generic chatbot.

PROJECT TELEMETRY CONTEXT:

### ACTIVE FINDINGS
${findingsBlock || "No findings."}

### MONITORED ASSETS
${assetsBlock || "No assets."}

### PENDING APPROVALS
${approvalsBlock || "No pending approvals."}

### ATTACK PATHS
${attackPathsBlock || "No attack paths."}

### MITRE ATT&CK KNOWLEDGE
${knowledgeBlock || "No reference matched."}

QUESTION: ${question}

Answer using the following structure whenever appropriate:

### Assessment
Provide a brief assessment of the situation.

### Evidence from telemetry
Reference Findings, Assets, Attack Paths, Approvals, CVEs or telemetry IDs when available.

### Security context
Explain the attack using MITRE ATT&CK techniques and general cybersecurity knowledge.

### Recommended actions
Provide practical remediation or investigation steps.

Do not begin your answer with phrases like "There is no mention..." or "The context does not contain...".
Instead, start naturally, for example:
- "No evidence of..."
- "Current telemetry indicates..."
- "Based on the available findings..."
- "The available telemetry shows..."

Keep responses concise, technical, and suitable for an enterprise SOC analyst.`;
}

async function callGroq(prompt: string): Promise<string> {
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.groqApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "llama-3.3-70b-versatile",
      messages: [
        {
          role: "system",
          content: `You are VYUHA AI, an enterprise SOC cybersecurity analyst.

    Always prioritize project telemetry.

    If telemetry directly answers the question:
    - Explain the findings clearly.
    - Reference CVEs, assets, attack paths, approvals and MITRE ATT&CK techniques.

    If telemetry partially answers the question:
    - Answer using the available telemetry first.
    - Then supplement with general cybersecurity knowledge.
    - Mention missing telemetry only if it materially affects the answer.

    Never refuse cybersecurity questions simply because they are not present in the telemetry.

    Your responses should sound like an experienced SOC analyst rather than a generic chatbot.`
        },
        {
          role: "user",
          content: prompt
        }
      ],
      temperature: 0.2,
      max_tokens: 500,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Groq API error: ${res.status} ${errText}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "No response generated.";
}

export async function askCopilot(question: string, findingId?: string) {
  // 1. Fetch telemetry context in parallel
  const [findingsRes, assetsRes, approvalsRes, attackPathsRes] = await Promise.all([
    db.from("findings").select("*"),
    db.from("assets").select("*"),
    db.from("approvals").select("*"),
    db.from("attack_paths").select("*")
  ]);

  const dbFindings = findingsRes.data || [];
  const dbAssets = assetsRes.data || [];
  const dbApprovals = approvalsRes.data || [];
  const dbAttackPaths = attackPathsRes.data || [];

  // Filter findings if a specific findingId is requested (e.g. from the Findings inspector panel link)
  let contextFindings = dbFindings;
  if (findingId) {
    contextFindings = dbFindings.filter((f) => f.id === findingId);
  }

  // 2. Query knowledge base using plain text query search
  const categoryTerms = contextFindings.map((f) => f.vuln_category).filter(Boolean).join(" ");
  const enrichedQuery = `${question} ${categoryTerms}`.trim();
  const knowledge = await retrieveKnowledge(enrichedQuery);

  // 3. Build prompt and execute LLM generation
  const prompt = buildPrompt(question, contextFindings, dbAssets, dbApprovals, dbAttackPaths, knowledge);
  const answer = await callGroq(prompt);

  return {
    answer,
    grounded_on: {
      findings: contextFindings.map((f) => f.cve_id).filter(Boolean),
      mitre_techniques: knowledge.map((k) => k.ref_id),
    },
  };
}