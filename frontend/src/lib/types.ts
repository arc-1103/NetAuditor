export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Waiver {
  waiver_id: string;
  audit_run_id: string;
  device_key: string;
  control_id: string;
  reason: string;
  ticket?: string | null;
  granted_by: string;
  granted_at: string;
  expires_at: string;
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  revoked_by?: string | null;
  revoked_reason?: string | null;
}

export interface Finding {
  waiver?: Waiver | null;
  waiver_note?: string;
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

export interface FixSimulation {
  control_id: string;
  current: { compliance_score: number };
  proposed: { compliance_score: number };
  compliance_delta: number;
  violations_resolved: string[];
  violations_introduced: string[];
  risk: "LOW" | "MEDIUM" | "HIGH";
  verdict: "SAFE" | "RISK_FLAG";
}

export interface DeviceHistory {
  runs: Array<{ run_id: string; created_at: string; filename?: string | null; failing: string[]; compliance_score: number }>;
  transitions: Array<{ run_id: string; created_at: string; introduced: string[]; resolved: string[]; score_change: number }>;
  control_streaks: Record<string, { failing_since_run: string; failing_since: string; audits_failing: number; last_passed_run: string | null; first_audit_of_device: boolean }>;
}

export interface DriftResult {
  control_id: string;
  compared_to: { run_id: string; created_at: string; filename?: string | null } | null;
  changes: Array<{ path: string; before: unknown; after: unknown; related: boolean }>;
  evidence: { text: string; source_lines: Array<number | { line: number; text: string }> } | null;
  note?: string;
}

export interface TopologyGraph {
  center: string | null;
  nodes: Array<{ id: string; kind: "device" | "unresolved"; hostname?: string | null; vendor?: string | null; ip?: string | null }>;
  edges: Array<{ source: string; target: string; protocol?: string | null }>;
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
  waived?: number;
  score_without_waivers?: number;
}

export interface ControlResult {
  control_id: string;
  title: string;
  result: "PASS" | "FAIL" | "WAIVED";
  severity: Severity;
}

export interface SecurityFlag {
  kind: "possible_prompt_injection" | "line_truncated";
  chunk?: number;
  line_in_chunk?: number;
}

export interface AuditRun {
  status_detail?: { security_flags?: SecurityFlag[] } | null;
  control_results?: ControlResult[];
  id: string;
  job_id?: string;
  original_filename: string;
  file_hash: string;
  status: string;
  created_at: string;
  device?: {
    hostname?: string | null;
    detected_os_version?: string | null;
    hardware_model?: string | null;
    serial_number?: string | null;
    detected_vendor?: string;
    detected_os?: string;
    parsing_confidence?: number;
    mean_logprob?: number | null;
    reverse_translation_fidelity?: number | null;
    parser_agreement?: number | null;
  };
  findings: Finding[];
  summary: Summary;
  anomaly?: { status: string; is_anomaly?: boolean; anomaly_score?: number } | null;
  policy_bundle_version?: string;
}

export interface TwinResult {
  modeled: boolean;
  method?: "z3-smt" | "sample-packet";
  checks: Array<{
    kind: "routing" | "management"; description: string; result: "PRESERVED" | "BROKEN";
    method?: "z3-smt" | "sample-packet";
    counterexample?: { src: string; dst: string; proto: string; sport: number; dport: number } | null;
  }>;
  broken: number;
  repairs?: Array<{ acl: string; target: string; status: "REPAIRED" | "ALREADY_SAFE" | "UNREPAIRABLE"; add_lines: string[]; rounds: number; reason?: string | null }>;
  note?: string | null;
}

export interface Remediation {
  twin?: TwinResult | null;
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
export interface UnfamiliarKeyword {
  keyword: string;
  count: number;
  command_position: boolean;
  security_related: boolean;
  example: string;
}

export interface KnowledgeMatch {
  id: string;
  document: string;
  metadata: Record<string, string | number | null>;
  distance?: number;
  fusion?: number;
  rerank?: number;
}

export interface KnowledgeSearchResult {
  query: string;
  matches: KnowledgeMatch[];
  cache?: string;
  retrieval?: string;
  rerank?: string;
  guardrail: { query_flags: string[]; quarantined: number; visible_tiers: string[] };
}

export interface LearningQueueItem {
  block_id: string;
  raw_text: string;
  sections?: string[];
  keywords?: UnfamiliarKeyword[];
}

export interface ScoreCycle {
  detected: boolean;
  method: string;
  days_analysed: number;
  period_days?: number;
  power_share?: number;
  autocorrelation_at_period?: number;
  p_value?: number;
  amplitude?: number;
  markers: Array<{ date: string; score: number; deviation: number }>;
  note?: string;
}

export interface RiskMapNode {
  id: string;
  kind: "device" | "unresolved";
  label: string;
  compliance_score: number | null;
  findings: number | null;
  audit_run_id: string | null;
  connections: number;
}

export interface ControlAnalysis {
  reach_by_step: Array<{ step: number; new: number; total: number; devices: string[] }>;
  reachable: number;
  devices: number;
  converged_at_step: number;
  steps_to_core: number | null;
  core_reachable: boolean;
  min_cut: { size: number; links: string[][] } | null;
}

export interface RiskMap {
  control?: ControlAnalysis;
  nodes: RiskMapNode[];
  edges: Array<{ source: string; target: string; protocol?: string | null }>;
  highlight: { entry_point: string; core: string | null; path: string[] | null; entry_reason: string; core_reason: string } | null;
  note?: string | null;
}

export interface SimilarMappings {
  block_id: string;
  query: { x: number; y: number } | null;
  points: Array<{ id: string; x: number; y: number; similarity: number; cli_pattern?: string | null; field?: string | null; value?: string | null }>;
  best: { id: string; similarity: number; cli_pattern?: string | null; field?: string | null; value?: string | null } | null;
  total_confirmed?: number;
  note?: string | null;
  method?: string;
}

export interface ExecutiveReport {
  score_cycle?: ScoreCycle;
  violation_cycle?: ScoreCycle;
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
    id?: string;
    event_type: string; actor: string; ruleset_version: string | null;
    payload: Record<string, unknown>; created_at: string;
  }>;
}
