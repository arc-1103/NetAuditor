import { mockAudit, mockRemediations } from "./mock";
import type { AuditRun, Remediation } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
export const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK_API !== "false";

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
    if (["EVALUATED", "COMPLETE", "REVIEW_REQUIRED", "FAILED"].includes(run.status)) return run;
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
  if (USE_MOCK) { await wait(650); return { download_url: "#mock-report", preview_url: "#mock-report" }; }
  return request<{ download_url: string; preview_url: string }>("/api/reports/generate", token, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ audit_run_id: runId }),
  });
}

export function reportUrl(runId: string, kind: "download" | "preview" | "json" | "cef") {
  return `${API_BASE}/api/reports/${runId}/${kind}`;
}
