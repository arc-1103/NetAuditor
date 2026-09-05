# SIH presentation claims checklist

Checked against the slide content supplied on 2026-09-05. Use this before the
Monday demo so the spoken claims match what the prototype can demonstrate.

| Slide claim | Repository evidence | Demo wording |
|---|---|---|
| AI parses; rules decide | Compliance uses OPA/Rego; parsing is a separate contract | Safe to claim as architecture. Show a Rego finding with evidence. |
| Jinja2 vendor-specific remediation | 11 Cisco IOS templates cover every current policy finding | Say "Cisco IOS remediation is implemented; other vendors are extensible templates." |
| Batfish pre-flight, zero lock-out risk | Fail-safe adapter and static lockout checks exist; real topology snapshot integration is not configured | Do not claim proven zero risk. Say "approval is blocked unless preflight is SAFE; the demo uses mock Batfish plus deterministic safety checks." |
| HTML/PDF reporting | Implemented HTML preview and real WeasyPrint PDF generation | Safe to demonstrate. |
| SIEM-compatible JSON/CEF | Implemented authenticated JSON and CEF export routes | Safe to demonstrate. |
| Finding includes SHA-256 + policy version + timestamp | SHA-256 and timestamps exist; policy version is not stored per finding | Say SHA-256/timestamp today. Add policy-bundle version before claiming the full tuple. |
| PostgreSQL append-only audit trail | `audit_runs` persists state, but findings are replaced on re-evaluation | Call it an auditable run record, not a fully append-only ledger yet. |
| Cisco, Juniper, Palo Alto, Fortinet, Arista, SONiC, cloud SGs | Current policy/remediation implementation is Cisco IOS only | Present these as planned adapters, not completed coverage. |
| CIS, NIST, DISA STIG verdicts | Current policy bundle is an illustrative CIS Cisco IOS subset | Demonstrate CIS; describe NIST/STIG as roadmap bundles. |
| `<30s`, `>=50 devices/hour`, `99%+`, `~0% drift`, `<5 min` | No benchmark dataset or performance harness currently proves these figures | Label all as design targets until benchmark results are recorded. |
| Every remediation is simulated before operator sees it | Risk-flagged proposals remain visible for review and cannot be approved | Say "every proposal is preflighted before approval," which matches the implementation. |
| Ticket automation | No ticketing connector is implemented | Remove from demo narration or label as next-step integration. |

## Remediation/reporting demo proof points

- Generate all proposals for one evaluated audit run.
- Contrast a `SAFE` SSHv2 fix with a `RISK_FLAGS` SNMP/ACL fix containing site-specific values.
- Show that approval of the risk-flagged proposal returns HTTP 409.
- Approve the safe proposal with an operator ID and comment.
- Open the HTML preview and download the PDF.
- Download CEF output and point out audit ID, file hash, framework, evidence, and remediation template.

