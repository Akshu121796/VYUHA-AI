import { db } from "../core/db";

// Simulated fix: in a real system this would call a patch/config API.
// For the hackathon, we mark it applied and log the action — matches the
// manual's "simulate fix applied, never auto-patch live systems in a demo" rule.
export async function applySimulatedFix(approvalId: string, findingId: string, userId: string) {
  const { error: approvalErr } = await db
    .from("approvals")
    .update({ status: "applied" })
    .eq("id", approvalId);
  if (approvalErr) throw new Error(approvalErr.message);

  await db.from("audit_log").insert({
    action: "remediation_applied",
    performed_by: userId,
    details: { approval_id: approvalId, finding_id: findingId, simulated: true },
  });
}

// Simulated verification: randomly-free in a real system this would re-scan.
// Here we deterministically "resolve" it — reliable for demo, matches the
// manual's "run once, save, replay" reliability principle.
export async function verifyRemediation(approvalId: string, findingId: string, userId: string) {
  const { error: findingErr } = await db
    .from("findings")
    .update({ status: "resolved" })  // was "remediated" — doesn't match your constraint
    .eq("id", findingId);
  if (findingErr) throw new Error(findingErr.message);

  const { error: approvalErr } = await db
    .from("approvals")
    .update({ status: "resolved" })
    .eq("id", approvalId);
  if (approvalErr) throw new Error(approvalErr.message);

  await db.from("audit_log").insert({
    action: "remediation_verified",
    performed_by: userId,
    details: { approval_id: approvalId, finding_id: findingId, result: "resolved" },
  });
}