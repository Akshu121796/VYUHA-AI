import { db } from "../core/db";
import { config } from "../core/config";

interface KnowledgeChunk {
  ref_id: string;
  title: string;
  content: string;
}

interface FindingContext {
  cve_id: string | null;
  severity: string | null;
  risk_score: number | null;
  vuln_category: string | null;
  description: string | null;
  hostname?: string;
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

// Structured context: either a specific finding (+ its attack path if any),
// or the current top-risk open findings if no finding_id is given.
async function retrieveFindingContext(findingId?: string): Promise<FindingContext[]> {
  let query = db
    .from("findings")
    .select("cve_id, severity, risk_score, vuln_category, description, asset_id")
    .eq("status", "open");

  if (findingId) {
    query = query.eq("id", findingId);
  } else {
    query = query.order("risk_score", { ascending: false }).limit(5);
  }

  const { data, error } = await query;
  if (error) throw new Error(error.message);
  return data ?? [];
}

function buildPrompt(question: string, findings: FindingContext[], knowledge: KnowledgeChunk[]): string {
  const findingsBlock = findings
    .map(
      (f, i) =>
        `[Finding ${i + 1}] CVE: ${f.cve_id ?? "N/A"}, Severity: ${f.severity ?? "N/A"}, Risk Score: ${f.risk_score ?? "N/A"}, Category: ${f.vuln_category ?? "uncategorized"}\nDescription: ${f.description ?? "N/A"}`
    )
    .join("\n\n");

  const knowledgeBlock = knowledge
    .map((k) => `[${k.ref_id} — ${k.title}]: ${k.content}`)
    .join("\n\n");

  return `You are a security analyst assistant. Answer the question using ONLY the context below. If the context doesn't contain enough information, say so explicitly rather than guessing.

CURRENT FINDINGS:
${findingsBlock || "No findings provided."}

MITRE ATT&CK REFERENCE:
${knowledgeBlock || "No reference matched."}

QUESTION: ${question}

Give a concise, evidence-grounded answer. Cite finding numbers or ATT&CK technique IDs where relevant.`;
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
      messages: [{ role: "user", content: prompt }],
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
  const findings = await retrieveFindingContext(findingId);

  // Enrich the search query with actual vuln_category terms from context findings —
  // bridges user phrasing gaps with the knowledge base's literal vocabulary.
  const categoryTerms = findings.map((f) => f.vuln_category).filter(Boolean).join(" ");
  const enrichedQuery = `${question} ${categoryTerms}`.trim();

  const knowledge = await retrieveKnowledge(enrichedQuery);

  const prompt = buildPrompt(question, findings, knowledge);
  const answer = await callGroq(prompt);

  return {
    answer,
    grounded_on: {
      findings: findings.map((f) => f.cve_id).filter(Boolean),
      mitre_techniques: knowledge.map((k) => k.ref_id),
    },
  };
}