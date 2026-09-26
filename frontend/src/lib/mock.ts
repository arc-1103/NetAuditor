import type { AuditRun, ExecutiveReport, Finding, LearningQueueItem, ProvenanceChain, Remediation, Severity, TrustView } from "./types";

export const DEMO_RUN_ID = "9f141c66-35d6-4e2a-9c91-f178b276ce83";

const findings: Finding[] = [
  { control_id: "CIS-NET-1.1.2", framework: "CIS", title: "Telnet administrative access is enabled", status: "FAIL", severity: "CRITICAL", evidence: "line 31: transport input telnet ssh", remediation: "ios_disable_telnet.j2", risk_score: 40, source_lines: [31] },
  { control_id: "CIS-NET-1.2.2", framework: "CIS", title: "Default SNMP community string is in use", status: "FAIL", severity: "CRITICAL", evidence: "line 17: snmp-server community [REDACTED] RO", remediation: "ios_snmp_community_fix.j2", risk_score: 40, source_lines: [17] },
  { control_id: "CIS-NET-1.1.1", framework: "CIS", title: "SSH version 2 is not enforced", status: "FAIL", severity: "HIGH", evidence: "line 12: ip ssh version 1", remediation: "ios_ssh_v2_fix.j2", risk_score: 25, source_lines: [12] },
  { control_id: "CIS-NET-1.3.1", framework: "CIS", title: "Weak IKE encryption is configured", status: "FAIL", severity: "CRITICAL", evidence: "lines 20–23: encryption 3des", remediation: "ios_ike_encryption_fix.j2", risk_score: 40, source_lines: [20, 23], blast_radius: ["branch-fw-02", "finance-core-01"] },
  { control_id: "CIS-NET-1.7.1", framework: "CIS", title: "Unencrypted HTTP management is enabled", status: "FAIL", severity: "MEDIUM", evidence: "line 10: ip http server", remediation: "ios_disable_http_server.j2", risk_score: 10, source_lines: [10] },
  { control_id: "CIS-NET-1.8.1", framework: "CIS", title: "Remote syslog is not configured", status: "FAIL", severity: "MEDIUM", evidence: "No remote logging host was observed", remediation: "ios_syslog_fix.j2", risk_score: 10 },
];

const severityCounts = findings.reduce((acc, finding) => {
  acc[finding.severity] += 1;
  return acc;
}, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Severity, number>);

export const mockAudit: AuditRun = {
  id: DEMO_RUN_ID,
  original_filename: "cisco-branch-insecure.cfg",
  file_hash: "0e4038c51f2b20cd788477fa8715c705c64ab481ea232c3522b95a89e6bda191",
  status: "EVALUATED",
  created_at: "2026-09-10T09:12:42Z",
  device: { detected_vendor: "cisco", detected_os: "IOS-XE", parsing_confidence: 0.96, mean_logprob: -0.18, reverse_translation_fidelity: 0.91 },
  findings,
  summary: { total_findings: findings.length, by_severity: severityCounts, risk_score: 165, compliance_score: 0, controls_evaluated: 11, controls_failed: 6, controls_passed: 5, control_pass_rate: 45 },
  anomaly: { status: "insufficient_peers" },
};

// docs/Additional-Features.md §2's decision table, mirrored here for the
// demo fallback exactly as decision_table.yaml would classify each finding
// (risk derived from severity; blast_radius from the finding's own list) —
// see app/approval_matrix.py + policy/decision_table.yaml on the backend.
function mockDecision(finding: Finding): Remediation["decision"] {
  const risk: "LOW" | "MEDIUM" | "HIGH" = finding.severity === "CRITICAL" || finding.severity === "HIGH" ? "HIGH" : finding.severity === "MEDIUM" ? "MEDIUM" : "LOW";
  const blastRadiusCount = finding.blast_radius?.length ?? 0;
  if (risk === "HIGH" && blastRadiusCount >= 1) {
    return { action: "DUAL_APPROVAL", rule_id: "dual-approval-high-risk-reachability-change", ruleset_version: "1.1.0", reason: "HIGH risk with a reachability change — requires two independent approvals.", risk, blast_radius_count: blastRadiusCount };
  }
  return { action: "SINGLE_APPROVAL", rule_id: "single-approval-small-blast-radius", ruleset_version: "1.1.0", reason: ">=95% parser agreement, <=2 services affected.", risk, blast_radius_count: blastRadiusCount };
}

export const mockRemediations: Remediation[] = findings.map((finding) => {
  const risky = finding.control_id === "CIS-NET-1.2.2";
  return {
    audit_run_id: DEMO_RUN_ID,
    control_id: finding.control_id,
    template_name: finding.remediation || "manual-review",
    script: risky
      ? "no snmp-server community public\n! Configure an approved SNMPv3 user before deployment\nsnmp-server user <USERNAME> NETAUDIT v3 auth sha <SECRET>"
      : finding.control_id === "CIS-NET-1.1.1"
        ? "configure terminal\nip ssh version 2\nend\nwrite memory"
        : "configure terminal\n! Deterministic reviewed remediation\nend\nwrite memory",
    source: "template",
    preflight_status: risky ? "RISK_FLAGS" : "SAFE",
    risk_flags: risky ? ["Script contains site-specific credential placeholders"] : [],
    approval_status: "PENDING",
    decision: mockDecision(finding),
    dual_approval: null,
    rollback_status: "NONE",
  };
});

export const mockExecutiveReport: ExecutiveReport = {
  fleet_score: { devices_scored: 4, fleet_score: 62 },
  fleet_score_trend: [
    { evaluated_at: "2026-08-27T09:00:00Z", fleet_score: 48 },
    { evaluated_at: "2026-09-03T09:00:00Z", fleet_score: 55 },
    { evaluated_at: "2026-09-10T09:00:00Z", fleet_score: 62 },
  ],
  top_exposed_devices: [
    { audit_run_id: DEMO_RUN_ID, original_filename: "cisco-branch-insecure.cfg", detected_vendor: "cisco", detected_os: "IOS-XE", compliance_score: 0, total_findings: 6, risk_score: 165 },
    { audit_run_id: "5c2e2b0a-9c3d-4a8e-8b0a-1f2e3d4c5b6a", original_filename: "fortinet-edge-fw.conf", detected_vendor: "fortinet", detected_os: "FortiOS", compliance_score: 55, total_findings: 3, risk_score: 70 },
    { audit_run_id: "7a1b2c3d-4e5f-6789-abcd-ef0123456789", original_filename: "arista-spine-01.cfg", detected_vendor: "arista", detected_os: "EOS", compliance_score: 82, total_findings: 1, risk_score: 10 },
  ],
  violations: { found: 9, resolved: 3, still_open: 6 },
  remediation_action_mix: { total: 6, auto_applied: 0, human_approved: 2, blocked: 0, rejected: 1, pending: 3 },
  mttr: {
    by_severity: {
      CRITICAL: { avg_mttr_seconds: 15120, target_seconds: 28800, sample_size: 2 },
      HIGH: { avg_mttr_seconds: 112320, target_seconds: 432000, sample_size: 1 },
      MEDIUM: { avg_mttr_seconds: null, target_seconds: 2592000, sample_size: 0 },
      LOW: { avg_mttr_seconds: null, target_seconds: 2592000, sample_size: 0 },
    },
    open_violations: [
      { audit_run_id: DEMO_RUN_ID, control_id: "CIS-NET-1.3.1", severity: "CRITICAL", age_seconds: 9000, over_sla: false },
    ],
    open_violations_over_sla: 0,
  },
};

// Field-by-field SLM-vs-deterministic agreement — deliberately includes one
// disagreement (crypto.ike_policies) so the demo shows what that looks like,
// not just a wall of green checks.
export const mockTrustView: TrustView = {
  parser_agreement: mockAudit.device?.parsing_confidence ?? null,
  fields_compared: 5,
  fields: [
    { field: "telnet.enabled", slm_value: "ENABLED", deterministic_value: "ENABLED", agree: true, source: "agreement" },
    { field: "ssh.version", slm_value: "1", deterministic_value: "1", agree: true, source: "agreement" },
    { field: "snmp.community_strings", slm_value: ["public"], deterministic_value: ["public"], agree: true, source: "agreement" },
    { field: "services.http_server_enabled", slm_value: "ENABLED", deterministic_value: "ENABLED", agree: true, source: "agreement" },
    { field: "crypto.ike_policies[0].encryption", slm_value: "3DES", deterministic_value: "UNKNOWN", agree: false, source: "disagreement" },
  ],
};

// Previously always [] in mock mode, which meant the Learning queue's
// "teach the model" feature couldn't be demoed at all without a live
// backend — one representative unrecognized block makes it demoable.
export const mockLearningQueue: LearningQueueItem[] = [
  { block_id: "blk-9f2a1c", raw_text: "set security zone security-zone TRUST interfaces ge-0/0/1.0" },
];

export function mockProvenance(controlId: string): ProvenanceChain {
  const finding = findings.find((item) => item.control_id === controlId) ?? null;
  const remediation = mockRemediations.find((item) => item.control_id === controlId) ?? null;
  return {
    audit_run_id: DEMO_RUN_ID,
    control_id: controlId,
    finding: finding ? { ...finding } : null,
    policy: { framework: "CIS", policy_bundle_version: "cis-generic-level1@1.0.0", schema_version: "1.0.0", baseline_sha256: mockAudit.file_hash, evaluated_at: mockAudit.created_at, rule_id: controlId },
    remediation: remediation ? { template_name: remediation.template_name, script: remediation.script, source: remediation.source, preflight_status: remediation.preflight_status, approval_status: remediation.approval_status } : null,
    events: [
      { event_type: "VIOLATION_DETECTED", actor: "system", ruleset_version: "cis-generic-level1@1.0.0", payload: {}, created_at: mockAudit.created_at },
      { event_type: "REMEDIATION_PROPOSED", actor: "system", ruleset_version: null, payload: { source: "template" }, created_at: mockAudit.created_at },
    ],
  };
}
