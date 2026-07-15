import { db } from "../core/db";

interface Finding {
  id: string;
  asset_id: string;
  vuln_category: string | null;
  risk_score: number | null;
  cve_id: string | null;
  severity: string | null;
}

interface AttackPattern {
  name: string;
  chain: string[];
  tactics: string[];
}

async function loadPatterns(): Promise<AttackPattern[]> {
  const { data, error } = await db
    .from("attack_patterns")
    .select("name, chain, tactics")
    .eq("active", true);
  if (error) throw new Error(error.message);
  return data ?? [];
}

function pickBestFinding(findings: Finding[], category: string): Finding | undefined {
  return findings
    .filter((f) => f.vuln_category === category)
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))[0];
}

export async function generateAttackPaths(scanId: string) {
  const [findingsRes, patterns] = await Promise.all([
    db.from("findings").select("id, asset_id, vuln_category, risk_score, cve_id, severity").eq("status", "open"),
    loadPatterns(),
  ]);

  if (findingsRes.error) throw new Error(findingsRes.error.message);
  const findings = (findingsRes.data ?? []) as Finding[];
  if (findings.length === 0 || patterns.length === 0) return [];

  const generatedPaths = [];

  for (const pattern of patterns) {
    const matchedFindings: Finding[] = [];
    for (const category of pattern.chain) {
      const match = pickBestFinding(findings, category);
      if (!match) break;
      matchedFindings.push(match);
    }
    if (matchedFindings.length !== pattern.chain.length) continue;

    const assetIds = [...new Set(matchedFindings.map((f) => f.asset_id))];
    const { data: assets } = await db.from("assets").select("id, hostname").in("id", assetIds);
    const assetMap = new Map((assets ?? []).map((a) => [a.id, a.hostname]));

    const pathNodes = matchedFindings.map((f, i) => ({
      step: i + 1,
      finding_id: f.id,
      asset_id: f.asset_id,
      hostname: assetMap.get(f.asset_id) ?? "unknown",
      vuln_category: f.vuln_category,
      cve_id: f.cve_id,
      tactic: pattern.tactics[i],
    }));

    const pathRiskScore = Math.max(...matchedFindings.map((f) => f.risk_score ?? 0));

    const { data: inserted, error: insertErr } = await db
      .from("attack_paths")
      .insert({
        scan_id: scanId,
        path_nodes: pathNodes,
        entry_point: assetMap.get(matchedFindings[0].asset_id) ?? "unknown",
        target_asset: assetMap.get(matchedFindings[matchedFindings.length - 1].asset_id) ?? "unknown",
        risk_score: pathRiskScore,
        tactic_chain: pattern.tactics,
      })
      .select()
      .single();

    if (insertErr) throw new Error(insertErr.message);
    generatedPaths.push(inserted);
  }

  return generatedPaths;
}