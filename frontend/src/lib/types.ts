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
  source_lines?: number[];
  blast_radius?: string[];
}

export interface Summary {
  total_findings: number;
  by_severity: Record<Severity, number>;
  risk_score: number;
  compliance_score: number;
}

export interface AuditRun {
  id: string;
  job_id?: string;
  original_filename: string;
  file_hash: string;
  status: string;
  created_at: string;
  device?: { detected_vendor?: string; detected_os?: string; parsing_confidence?: number };
  findings: Finding[];
  summary: Summary;
  anomaly?: { status: string; is_anomaly?: boolean; anomaly_score?: number } | null;
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
}
