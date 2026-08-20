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
      (f) =>
        `- Finding ID: ${f.id}, Asset Hostname: ${f.asset_hostname || "N/A"}, CVE: ${f.cve_id ?? "N/A"}, Severity: ${f.severity ?? "N/A"}, CVSS: ${f.cvss_score ?? "N/A"}, Risk Score: ${f.risk_score ?? "N/A"}, Status: ${f.status ?? "N/A"}, Category: ${f.vuln_category ?? "uncategorized"}\n  Description: ${f.description && f.description.length > 150 ? f.description.slice(0, 150) + "..." : (f.description ?? "N/A")}`
    )
    .join("\n");

  const assetsBlock = assets
    .map(
      (a) =>
        `- Asset Hostname: ${a.hostname}, IP: ${a.ip_address ?? "0.0.0.0"}, OS: ${a.os_type ?? "N/A"}, Criticality: ${a.criticality ?? "N/A"}`
    )
    .join("\n");

  const approvalsBlock = approvals
    .map(
      (appr) =>
        `- Approval ID: ${appr.id}, Finding ID: ${appr.finding_id ?? "N/A"}, Fix: ${appr.recommended_fix ?? "N/A"}, Status: ${appr.status ?? "pending"}`
    )
    .join("\n");

  const attackPathsBlock = attackPaths
    .map((ap) => {
      const nodes = ap.path_nodes || [];
      const stagesStr = nodes
        .map((n: any) => `${n.hostname || n.name || "UnknownNode"} [Tactic: ${n.tactic || "N/A"}, Finding: ${n.finding_id || "N/A"}]`)
        .join(" -> ");
      return `- Attack Path ID: ${ap.id}, Risk Score: ${ap.risk_score ?? "N/A"}, Target: ${ap.target_asset ?? "N/A"}\n  Chain: ${stagesStr}`;
    })
    .join("\n");

  const knowledgeBlock = knowledge
    .map((k) => {
      const truncatedContent = k.content && k.content.length > 1000 ? k.content.slice(0, 1000) + "..." : (k.content ?? "");
      return `[${k.ref_id} — ${k.title}]: ${truncatedContent}`;
    })
    .join("\n\n");

  const promptTemplateHeader = `You are VYUHA AI, an enterprise SOC cybersecurity analyst assisting security operators.

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

PROJECT TELEMETRY CONTEXT:`;

  const promptTemplateFooter = `QUESTION: ${question}

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

  let findingsPart = "### ACTIVE FINDINGS\nNo findings.";
  let assetsPart = "### MONITORED ASSETS\nNo assets.";
  let attackPathsPart = "### ATTACK PATHS\nNo attack paths.";
  let knowledgePart = "### MITRE ATT&CK KNOWLEDGE\nNo reference matched.";
  let approvalsPart = "### PENDING APPROVALS\nNo pending approvals.";

  let remainingSpace = 12000 - promptTemplateHeader.length - promptTemplateFooter.length - 200; // 200 character buffer for safety

  // 1. Findings (Priority 1)
  if (remainingSpace > 0) {
    const block = `### ACTIVE FINDINGS\n${findingsBlock || "No findings."}`;
    if (block.length <= remainingSpace) {
      findingsPart = block;
      remainingSpace -= block.length;
    } else {
      findingsPart = block.slice(0, remainingSpace) + "\n... [truncated]";
      remainingSpace = 0;
    }
  }

  // 2. Assets (Priority 2)
  if (remainingSpace > 0) {
    const block = `### MONITORED ASSETS\n${assetsBlock || "No assets."}`;
    if (block.length <= remainingSpace) {
      assetsPart = block;
      remainingSpace -= block.length;
    } else {
      assetsPart = block.slice(0, remainingSpace) + "\n... [truncated]";
      remainingSpace = 0;
    }
  }

  // 3. Attack Paths (Priority 3)
  if (remainingSpace > 0) {
    const block = `### ATTACK PATHS\n${attackPathsBlock || "No attack paths."}`;
    if (block.length <= remainingSpace) {
      attackPathsPart = block;
      remainingSpace -= block.length;
    } else {
      attackPathsPart = block.slice(0, remainingSpace) + "\n... [truncated]";
      remainingSpace = 0;
    }
  }

  // 4. Knowledge (Priority 4)
  if (remainingSpace > 0) {
    const block = `### MITRE ATT&CK KNOWLEDGE\n${knowledgeBlock || "No reference matched."}`;
    if (block.length <= remainingSpace) {
      knowledgePart = block;
      remainingSpace -= block.length;
    } else {
      knowledgePart = block.slice(0, remainingSpace) + "\n... [truncated]";
      remainingSpace = 0;
    }
  }

  // 5. Approvals (Priority 5)
  if (remainingSpace > 0) {
    const block = `### PENDING APPROVALS\n${approvalsBlock || "No pending approvals."}`;
    if (block.length <= remainingSpace) {
      approvalsPart = block;
      remainingSpace -= block.length;
    } else {
      approvalsPart = block.slice(0, remainingSpace) + "\n... [truncated]";
      remainingSpace = 0;
    }
  }

  return `${promptTemplateHeader}\n\n${findingsPart}\n\n${assetsPart}\n\n${approvalsPart}\n\n${attackPathsPart}\n\n${knowledgePart}\n\n${promptTemplateFooter}`;
}

async function callGroq(prompt: string): Promise<string> {
  console.log("Prompt character count:", prompt.length);
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.groqApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: config.groqModel,
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

  const questionLower = question.toLowerCase();

  // Attach hostname to findings for easy lookup in buildPrompt
  contextFindings.forEach((f) => {
    const asset = dbAssets.find((a) => a.id === f.asset_id);
    f.asset_hostname = asset ? asset.hostname : "N/A";
  });

  // Sort and limit findings: Max 5
  const sortedFindings = [...contextFindings].sort((a, b) => {
    if (findingId) {
      if (a.id === findingId && b.id !== findingId) return -1;
      if (b.id === findingId && a.id !== findingId) return 1;
    }
    const aCveMatch = a.cve_id && questionLower.includes(a.cve_id.toLowerCase()) ? 1 : 0;
    const bCveMatch = b.cve_id && questionLower.includes(b.cve_id.toLowerCase()) ? 1 : 0;
    if (aCveMatch !== bCveMatch) return bCveMatch - aCveMatch;

    const aHostMatch = a.asset_hostname && questionLower.includes(a.asset_hostname.toLowerCase()) ? 1 : 0;
    const bHostMatch = b.asset_hostname && questionLower.includes(b.asset_hostname.toLowerCase()) ? 1 : 0;
    if (aHostMatch !== bHostMatch) return bHostMatch - aHostMatch;

    const aScore = a.risk_score ?? 0;
    const bScore = b.risk_score ?? 0;
    return bScore - aScore;
  });
  const limitedFindings = sortedFindings.slice(0, 5);

  // Sort and limit assets: Max 5
  const sortedAssets = [...dbAssets].sort((a, b) => {
    const aMatch = a.hostname && questionLower.includes(a.hostname.toLowerCase()) ? 1 : 0;
    const bMatch = b.hostname && questionLower.includes(b.hostname.toLowerCase()) ? 1 : 0;
    if (aMatch !== bMatch) return bMatch - aMatch;

    const critWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    const aCrit = critWeight[a.criticality?.toLowerCase()] || 0;
    const bCrit = critWeight[b.criticality?.toLowerCase()] || 0;
    return bCrit - aCrit;
  });
  const limitedAssets = sortedAssets.slice(0, 5);

  // Sort and limit attack paths: Max 3
  const sortedAttackPaths = [...dbAttackPaths].sort((a, b) => {
    const aHostMatch = a.path_nodes && a.path_nodes.some((n: any) => n.hostname && questionLower.includes(n.hostname.toLowerCase())) ? 1 : 0;
    const bHostMatch = b.path_nodes && b.path_nodes.some((n: any) => n.hostname && questionLower.includes(n.hostname.toLowerCase())) ? 1 : 0;
    if (aHostMatch !== bHostMatch) return bHostMatch - aHostMatch;

    const aScore = a.risk_score ?? 0;
    const bScore = b.risk_score ?? 0;
    return bScore - aScore;
  });
  const limitedAttackPaths = sortedAttackPaths.slice(0, 3);

  // Sort and limit approvals: Max 3
  const limitedFindingsSet = new Set(limitedFindings.map(f => f.id));
  const sortedApprovals = [...dbApprovals].sort((a, b) => {
    const aMatch = a.finding_id && limitedFindingsSet.has(a.finding_id) ? 1 : 0;
    const bMatch = b.finding_id && limitedFindingsSet.has(b.finding_id) ? 1 : 0;
    return bMatch - aMatch;
  });
  const limitedApprovals = sortedApprovals.slice(0, 3);

  // 2. Query knowledge base using plain text query search
  const categoryTerms = limitedFindings.map((f) => f.vuln_category).filter(Boolean).join(" ");
  const enrichedQuery = `${question} ${categoryTerms}`.trim();
  const knowledge = await retrieveKnowledge(enrichedQuery);

  // 3. Build prompt and execute LLM generation
  const prompt = buildPrompt(question, limitedFindings, limitedAssets, limitedApprovals, limitedAttackPaths, knowledge);
  const answer = await callGroq(prompt);

  return {
    answer,
    grounded_on: {
      findings: limitedFindings.map((f) => f.cve_id).filter(Boolean),
      mitre_techniques: knowledge.map((k) => k.ref_id),
    },
  };
}