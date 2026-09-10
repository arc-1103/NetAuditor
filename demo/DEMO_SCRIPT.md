# Four-minute final prototype demo

## Preflight

1. Run `./scripts/check_env.sh` and the stack smoke test.
2. Keep `NEXT_PUBLIC_USE_MOCK_API=false` for the real run.
3. Open a second browser tab with mock mode as the offline fallback.
4. Generate and retain one backup PDF before presenting.

## Narration

**0:00 — Problem.** “Mixed-vendor networks turn compliance into a manual,
vendor-locked exercise. NetAudit converts raw configurations into one auditable
security model.”

**0:25 — Upload.** Upload `demo/cisco_insecure.cfg`. Point out that the original
file receives a SHA-256 fingerprint and credentials are redacted before storage.

**0:55 — Decision boundary.** “Our local AI extracts configuration facts. It is
not allowed to declare a control compliant. Pydantic gates the structure and OPA
makes the reproducible verdict.”

**1:25 — Findings.** Open Telnet, SNMP and IKE findings. Show the control,
severity, normalized evidence and original source line.

**2:05 — Safe remediation.** Generate proposals. Approve the deterministic SSH
template. Then open the SNMP proposal and show that site-specific placeholders
produce `RISK_FLAGS` and disable approval.

**2:50 — Evidence.** Generate the report and show SHA-256, policy version,
findings, remediation status and export formats.

**3:25 — Multi-vendor proof.** Show the prepared Fortinet audit. “The syntax is
different; the normalized policy model is unchanged, while the remediation
template remains vendor-specific.”

**3:50 — Close.** “This gives NTRO an air-gap-ready, explainable compliance
pipeline that can add vendors and policy bundles without trusting AI to decide
security.”

## Claims discipline

- Say “CIS-style prototype policy subset,” not “CIS certified.”
- Say “Cisco and Fortinet demonstrated,” not “every vendor implemented.”
- Present NIST, STIG and ISO bundles as roadmap work.
- Present GraphRAG/anomaly output as optional context, never part of the verdict.
- Do not claim zero lockout risk; say unsafe proposals are blocked from approval.
