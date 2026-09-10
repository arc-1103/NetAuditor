import { mockAudit, mockRemediations } from "./mock";
import type { AuditRun, Remediation } from "./types";

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

export async function login(email: string, password: string) {
  if (USE_MOCK) {
    await wait(350);
    return { access_token: "demo-token", user: { email, role: "admin" } };
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

export async function approveRemediation(
  controlId: string,
  runId: string,
  approved: boolean,
  token: string,
): Promise<{ approval_status: "APPROVED" | "REJECTED" }> {
  if (USE_MOCK) {
    await wait(400);
    const item = mockRemediations.find((entry) => entry.control_id === controlId);
    if (approved && item?.preflight_status !== "SAFE") throw new Error("Approval blocked: preflight is not SAFE");
    return { approval_status: approved ? "APPROVED" : "REJECTED" };
  }
  return request<{ approval_status: "APPROVED" | "REJECTED" }>(`/api/remediation/${encodeURIComponent(controlId)}/approve`, token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approved, audit_run_id: runId, comment: "Reviewed in NetAudit dashboard" }),
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

export async function getLearningQueue(token: string): Promise<{ items: any[] }> {
  if (USE_MOCK) { await wait(300); return { items: [] }; }
  return request<{ items: any[] }>("/api/learning/queue", token);
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
