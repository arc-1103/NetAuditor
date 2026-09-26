export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  control_id: string;
  framework: string;
  title: string;
  status: "FAIL";
  severity: Severity;
  evidence: string;
  remediation: string | null;
  risk_score: number;
  source_lines?: Array<number | { line: number; text: string }>;
  blast_radius?: string[];
}

export interface Summary {
  total_findings: number;
  by_severity: Record<Severity, number>;
  risk_score: number;
  // null when the run hasn't been evaluated yet (e.g. NEEDS_REVIEW) — the
  // backend never fabricates a score for a device that was never audited.
  compliance_score: number | null;
  controls_evaluated?: number;
  controls_failed?: number;
  controls_passed?: number;
  control_pass_rate?: number | null;
}

export interface AuditRun {
  id: string;
  job_id?: string;
  original_filename: string;
  file_hash: string;
  status: string;
  created_at: string;
  device?: {
    detected_vendor?: string;
    detected_os?: string;
    parsing_confidence?: number;
    mean_logprob?: number | null;
    reverse_translation_fidelity?: number | null;
  };
  findings: Finding[];
  summary: Summary;
  anomaly?: { status: string; is_anomaly?: boolean; anomaly_score?: number } | null;
  policy_bundle_version?: string;
}

export interface Remediation {
  audit_run_id: string;
  control_id: string;
  template_name: string;
  script: string;
  rollback_script?: string | null;
  source: "template" | "agentic_rag";
  preflight_status?: "SAFE" | "RISK_FLAGS" | "UNAVAILABLE";
  preflight?: { status: "SAFE" | "RISK_FLAGS" | "UNAVAILABLE"; risk_flags: string[]; engine: string };
  risk_flags?: string[];
  approval_status: "PENDING" | "APPROVED" | "REJECTED";
  // docs/Additional-Features.md §2/§7 — the confidence-weighted decision
  // this proposal was classified under, and (once at least one approval has
  // been recorded) how many of a DUAL_APPROVAL's required 2 signatures are
  // in. Absent on a mock/legacy proposal that predates these fields.
  decision?: {
    action: "BLOCK" | "DUAL_APPROVAL" | "SINGLE_APPROVAL" | "AUTO_APPLY";
    rule_id: string; ruleset_version: string; reason: string;
    risk: "LOW" | "MEDIUM" | "HIGH"; blast_radius_count: number;
  };
  dual_approval?: { required: number; received: number } | null;
  approved_by?: string | null;
  approval_comment?: string | null;
  approved_at?: string | null;
  // docs/Additional-Features.md §3 — Approved -> Applied -> (optionally)
  // Rolled back. `rollback_status` starts "NONE"; apply sets "APPLIED",
  // rollback sets "ROLLED_BACK". `applied_at` is the only signal the UI
  // needs to know Apply already happened (no live device push exists —
  // this just records that an operator ran the script by hand).
  applied_at?: string | null;
  rollback_status?: "NONE" | "APPLIED" | "ROLLED_BACK";
  pre_change_baseline_sha256?: string | null;
}

// GET /api/learning/queue's response_model only exposes these two fields —
// audit_run_id/chunk_context/status/created_at are computed server-side but
// not returned (services/learning/backend/app/main.py's UnrecognizedBlock).
export interface LearningQueueItem {
  block_id: string;
  raw_text: string;
}

export interface ExecutiveReport {
  fleet_score: { devices_scored: number; fleet_score: number };
  fleet_score_trend: Array<{ evaluated_at: string; fleet_score: number }>;
  top_exposed_devices: Array<{
    audit_run_id: string;
    original_filename?: string;
    detected_vendor?: string;
    detected_os?: string;
    compliance_score: number;
    total_findings: number;
    risk_score: number;
  }>;
  violations: { found: number; resolved: number; still_open: number };
  remediation_action_mix: {
    total: number; auto_applied: number; human_approved: number;
    blocked: number; rejected: number; pending: number;
  };
  mttr: {
    by_severity: Record<Severity, { avg_mttr_seconds: number | null; target_seconds: number; sample_size: number }>;
    open_violations: Array<{ audit_run_id: string; control_id: string; severity: string; age_seconds: number; over_sla: boolean }>;
    open_violations_over_sla: number;
  };
}

// docs/Suggestions.md item 7 (AI Interpretation Trust Layer) — per-field
// agreement between the SLM's extraction and the deterministic TextFSM
// cross-check, for the whole audit run (not one finding).
export interface TrustView {
  parser_agreement: number | null;
  fields_compared: number;
  fields: Array<{
    field: string; slm_value: unknown; deterministic_value: unknown;
    agree: boolean; source: "agreement" | "disagreement";
  }>;
}

export interface ProvenanceChain {
  audit_run_id: string;
  control_id: string;
  finding: Record<string, unknown> | null;
  policy: Record<string, unknown> | null;
  remediation: Record<string, unknown> | null;
  events: Array<{
    event_type: string; actor: string; ruleset_version: string | null;
    payload: Record<string, unknown>; created_at: string;
  }>;
}
