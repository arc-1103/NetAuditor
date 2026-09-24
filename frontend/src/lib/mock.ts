import type { AuditRun, Finding, Remediation, Severity } from "./types";

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
  };
});
