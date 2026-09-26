import { mockAudit, mockExecutiveReport, mockLearningQueue, mockProvenance, mockRemediations, mockTrustView } from "./mock";
import type { AuditRun, ExecutiveReport, LearningQueueItem, ProvenanceChain, Remediation, TrustView } from "./types";

export type Role = "admin" | "operator" | "auditor";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
const QWEN_BASE = process.env.NEXT_PUBLIC_QWEN_BASE_URL || "http://localhost:11434";
export const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK_API !== "false";

export async function askLocalQwen(title: string, evidence: string): Promise<string> {
  const response = await fetch(`${QWEN_BASE}/v1/chat/completions`, {
    method: "POST",
    signal: AbortSignal.timeout(30_000),
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "qwen2.5:7b-instruct-q4_K_M",
      temperature: 0,
      max_tokens: 100,
      messages: [
        { role: "system", content: "Explain network security findings in two short, non-technical sentences. Do not invent facts." },
        { role: "user", content: `Finding: ${title}\nEvidence: ${evidence}` },
      ],
    }),
  });
  if (!response.ok) throw new Error("Local Qwen model is not available");
  const body = await response.json();
  const answer = body?.choices?.[0]?.message?.content;
  if (typeof answer !== "string" || !answer.trim()) throw new Error("Qwen returned no explanation");
  return answer.trim();
}

function wait(ms = 550) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function request<T>(path: string, token: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init?.headers || {}) },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export async function login(email: string, password: string, mockRole: Role = "admin") {
  if (USE_MOCK) {
    await wait(350);
    // Real login's role comes from the server (gateway/app/auth.py's users
    // table via the JWT) — the caller can't pick it. In mock mode there's no
    // server to ask, so the login form itself offers a role picker, purely
    // to make the real backend's role-scoped approval matrix (see
    // approveRemediation below) demonstrable without a live gateway.
    return { access_token: "demo-token", user: { email, role: mockRole } };
  }
  const response = await fetch(`${API_BASE}/api/login`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }),
  });
  if (!response.ok) throw new Error("Invalid credentials or gateway unavailable");
  return response.json();
}

export async function uploadConfig(file: File, token: string) {
  if (USE_MOCK) {
    await wait(850);
    return { job_id: mockAudit.id, status: "queued" };
  }
  const form = new FormData(); form.append("file", file);
  return request<{ job_id: string; status: string }>("/api/upload", token, { method: "POST", body: form });
}

export async function getAudit(runId: string, token: string): Promise<AuditRun> {
  if (USE_MOCK) { await wait(1050); return { ...structuredClone(mockAudit), id: runId }; }
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const run = await request<AuditRun>(`/api/audit-runs/${runId}`, token);
    if (["EVALUATED", "COMPLETE", "NEEDS_REVIEW", "FAILED"].includes(run.status)) return run;
    await wait(1500);
  }
  throw new Error("The audit is still processing. Reopen it from audit history shortly.");
}

export async function generateRemediations(runId: string, token: string): Promise<Remediation[]> {
  if (USE_MOCK) { await wait(700); return structuredClone(mockRemediations).map((item) => ({ ...item, audit_run_id: runId })); }
  const result = await request<{ remediations: Remediation[] }>(`/api/remediation/audit-runs/${runId}/generate`, token, { method: "POST" });
  return result.remediations;
}

// Mock-only: tracks distinct approvers per control_id across calls in this
// browser session, the same role Postgres's ledger_events plays for the
// real dual-approval quorum (services/remediation/app/db.py's approve()).
const mockApprovers = new Map<string, Set<string>>();

export interface ApprovalResult {
  approval_status: "PENDING" | "APPROVED" | "REJECTED";
  dual_approval?: { required: number; received: number } | null;
}

export async function approveRemediation(
  controlId: string,
  runId: string,
  approved: boolean,
  token: string,
  role: Role,
  actor: string,
): Promise<ApprovalResult> {
  if (USE_MOCK) {
    await wait(400);
    const item = mockRemediations.find((entry) => entry.control_id === controlId);
    if (!item) throw new Error("Proposal not found");
    if (!approved) { item.approval_status = "REJECTED"; return { approval_status: "REJECTED" }; }
    if (item.preflight_status !== "SAFE") throw new Error("Approval blocked: preflight is not SAFE");

    // Mirrors app/approval_matrix.py's check_permission exactly, so the
    // role picker on the login screen demonstrates the real backend's rules.
    const decision = item.decision;
    const risk = decision?.risk ?? "HIGH";
    const blastRadius = decision?.blast_radius_count ?? 0;
    const action = decision?.action ?? "SINGLE_APPROVAL";
    if (action === "BLOCK") throw new Error("This proposal's decision classification is BLOCK — it cannot be approved.");
    if (role === "auditor") throw new Error("Role 'auditor' is not permitted to approve remediations.");
    if (role === "operator") {
      if (risk === "HIGH") throw new Error("Network Operator cannot approve a HIGH-risk change — requires Security Lead / Change Advisory.");
      if (blastRadius > 0) throw new Error("Network Operator can only approve single-device changes.");
    }

    if (action === "DUAL_APPROVAL") {
      const priorActors = mockApprovers.get(controlId) ?? new Set<string>();
      priorActors.add(actor);
      mockApprovers.set(controlId, priorActors);
      const dual_approval = { required: 2, received: priorActors.size };
      item.dual_approval = dual_approval;
      if (priorActors.size < 2) { item.approval_status = "PENDING"; return { approval_status: "PENDING", dual_approval }; }
      item.approval_status = "APPROVED";
      return { approval_status: "APPROVED", dual_approval };
    }

    item.approval_status = "APPROVED";
    return { approval_status: "APPROVED" };
  }
  return request<ApprovalResult>(`/api/remediation/${encodeURIComponent(controlId)}/approve`, token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approved, audit_run_id: runId, comment: "Reviewed in NetAudit dashboard" }),
  });
}

export interface ApplyResult { audit_run_id: string; control_id: string; pre_change_baseline_sha256: string | null; applied_at: string; rollback_status: "APPLIED"; }
export interface RollbackResult { audit_run_id: string; control_id: string; pre_change_baseline_sha256: string | null; rollback_status: "ROLLED_BACK"; }

export async function applyRemediation(controlId: string, runId: string, token: string): Promise<ApplyResult> {
  if (USE_MOCK) {
    await wait(350);
    const item = mockRemediations.find((entry) => entry.control_id === controlId);
    if (item?.approval_status !== "APPROVED") throw new Error("Proposal not found, or it isn't APPROVED yet");
    const applied_at = new Date().toISOString();
    item.applied_at = applied_at; item.rollback_status = "APPLIED";
    return { audit_run_id: runId, control_id: controlId, pre_change_baseline_sha256: item.pre_change_baseline_sha256 ?? null, applied_at, rollback_status: "APPLIED" };
  }
  return request<ApplyResult>(`/api/remediation/${encodeURIComponent(controlId)}/apply`, token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ audit_run_id: runId }),
  });
}

export async function rollbackRemediation(controlId: string, runId: string, reason: string, token: string): Promise<RollbackResult> {
  if (USE_MOCK) {
    await wait(350);
    const item = mockRemediations.find((entry) => entry.control_id === controlId);
    if (!item?.applied_at) throw new Error("Proposal not found, or it was never marked APPLIED");
    item.rollback_status = "ROLLED_BACK";
    return { audit_run_id: runId, control_id: controlId, pre_change_baseline_sha256: item.pre_change_baseline_sha256 ?? null, rollback_status: "ROLLED_BACK" };
  }
  return request<RollbackResult>(`/api/remediation/${encodeURIComponent(controlId)}/rollback`, token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ audit_run_id: runId, reason }),
  });
}

export async function generateReport(runId: string, token: string) {
  if (USE_MOCK) {
    const report = { product: "NetAudit", mode: "deterministic presentation fallback", audit_run: runId, summary: mockAudit.summary, findings: mockAudit.findings };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    window.open(url, "_blank", "noopener,noreferrer");
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
    return { download_url: url, preview_url: url };
  }
  return request<{ download_url: string; preview_url: string }>("/api/reports/generate", token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ audit_run_id: runId }),
  });
}

export async function getLearningQueue(token: string): Promise<LearningQueueItem[]> {
  // The real endpoint's response_model returns a bare array of
  // {block_id, raw_text} — not {items: [...]}.
  if (USE_MOCK) { await wait(300); return structuredClone(mockLearningQueue); }
  return request<LearningQueueItem[]>("/api/learning/queue", token);
}

export interface LearningMapInput { block_id: string; cli_pattern: string; field: string; value: string; vendor?: string; os?: string | null; }

export async function submitLearningMap(input: LearningMapInput, token: string): Promise<{ confirmed: boolean; block_id: string; was_queued: boolean }> {
  if (USE_MOCK) {
    await wait(400);
    const index = mockLearningQueue.findIndex((item) => item.block_id === input.block_id);
    if (index >= 0) mockLearningQueue.splice(index, 1);
    return { confirmed: true, block_id: input.block_id, was_queued: true };
  }
  return request(`/api/learning/map`, token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
  });
}

export async function getExecutiveReport(token: string): Promise<ExecutiveReport> {
  if (USE_MOCK) { await wait(600); return structuredClone(mockExecutiveReport); }
  return request<ExecutiveReport>("/api/executive-report", token);
}

export async function getAuditTrust(runId: string, token: string): Promise<TrustView> {
  if (USE_MOCK) { await wait(400); return structuredClone(mockTrustView); }
  return request<TrustView>(`/api/audit-runs/${runId}/trust`, token);
}

export async function getProvenance(runId: string, controlId: string, token: string): Promise<ProvenanceChain> {
  if (USE_MOCK) { await wait(400); return structuredClone(mockProvenance(controlId)); }
  return request<ProvenanceChain>(`/api/provenance/${runId}/${encodeURIComponent(controlId)}`, token);
}

export function reportUrl(runId: string, kind: "download" | "preview" | "json" | "cef") {
  return `${API_BASE}/api/reports/${runId}/${kind}`;
}

export async function openProtectedReport(runId: string, token: string, kind: "download" | "preview" | "json" | "cef") {
  const response = await fetch(reportUrl(runId, kind), { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error("The generated report could not be opened");
  const url = URL.createObjectURL(await response.blob());
  window.open(url, "_blank", "noopener,noreferrer");
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
