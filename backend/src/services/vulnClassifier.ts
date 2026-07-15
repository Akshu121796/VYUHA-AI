import { db } from "../core/db";

interface Rule {
  category: string;
  keywords: string[];
  priority: number;
}

let cachedRules: Rule[] | null = null;

// Rules rarely change mid-hackathon; cache after first load to avoid a DB
// round-trip on every finding creation.
async function loadRules(): Promise<Rule[]> {
  if (cachedRules) return cachedRules;
  const { data, error } = await db
    .from("vuln_category_rules")
    .select("category, keywords, priority")
    .order("priority", { ascending: false });
  if (error) throw new Error(error.message);
  cachedRules = data ?? [];
  return cachedRules;
}

export async function classifyVulnCategory(text: string | undefined | null): Promise<string | null> {
  if (!text) return null;
  const lower = text.toLowerCase();
  const rules = await loadRules();

  for (const rule of rules) {
    if (rule.keywords.some((kw) => lower.includes(kw.toLowerCase()))) {
      return rule.category;
    }
  }
  return null;
}