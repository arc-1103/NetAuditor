# NetAudit Engine — submission architecture

**SIH26155 | NTRO | AI-Driven Multi-Vendor Network Security Compliance Auditor**

## 1. Design

NetAudit converts heterogeneous device configuration into explainable,
vendor-neutral security evidence. A local AI model may extract structure from
unfamiliar syntax, but only version-controlled OPA rules produce PASS/FAIL
verdicts. Invalid or low-confidence extraction becomes `NEEDS_REVIEW`, never
compliant.

```text
Browser → API gateway → ingestion → Redis → parsing worker
                                      ↓              ↓
                              MinIO + PostgreSQL   SecurityBaseline JSON
                                                        ↓
                                                OPA compliance engine
                                                   ↓          ↓
                                         remediation       PDF/JSON/CEF
                                         + approval         reporting

Optional: reviewed learning/RAG · topology blast radius · Batfish preflight
```

Runtime services use an internal Docker network. Only the dashboard and API
gateway publish host ports. Uploaded configurations are bounded, MIME checked,
credential-redacted, SHA-256 fingerprinted and stored with audit provenance.
Authentication uses role-based access (`admin`, `operator`, `auditor`).

## 2. Pipeline and extensibility

1. **Ingest:** accept `.cfg`, `.conf` or `.txt`; validate, redact and enqueue.
2. **Normalize:** detect vendor/OS and map CLI chunks to a strict Pydantic
   `SecurityBaseline`. Cisco IOS-XE and Fortinet FortiOS fixtures demonstrate
   current adapters; local Ollama and deterministic mock modes share the same gate.
3. **Learn:** unknown blocks enter a review queue. An administrator confirms a
   CLI pattern-to-field mapping, which becomes vendor/OS-filtered retrieval
   context for later parses. It never changes a verdict directly.
4. **Evaluate:** OPA checks the normalized model using an 11-control,
   CIS-inspired generic Level 1 prototype policy. Findings retain exact source
   evidence, severity, policy/schema versions and risk score.
5. **Act and report:** reviewed Jinja2 templates produce vendor-specific CLI.
   Preflight labels proposals `SAFE` or `RISK_FLAGS`; only safe proposals can be
   approved. Reports export browser HTML, PDF, JSON and CEF.

New vendors generally require examples/mappings and reviewed remediation
templates—not a new end-to-end service. New frameworks are separate versioned
policy bundles over the stable normalized schema.

## 3. Prototype proof and limits

| SIH requirement | Current proof | Honest limit / next milestone |
|---|---|---|
| Unified ingestion | Dashboard upload, hashing, redaction, MinIO | Single-file UI today; bulk orchestration next |
| AI adaptation | Local structured parsing + reviewed learning APIs | Learning admin UI is not yet wired into dashboard |
| Multi-framework engine | Pluggable OPA policy architecture | One CIS-inspired prototype bundle; no certification claim |
| Actionable reporting | Evidence, risk, remediation, PDF/JSON/CEF | Validate more hardware/firmware combinations |
| Vendor agnosticism | Shared schema; Cisco + Fortinet fixtures | Add Juniper/Palo Alto validated fixtures and policies |

The default Compose profile is a deterministic presentation core. Optional
`advanced` and `model` profiles add learning/topology/Batfish and local Ollama.
No configuration is pushed automatically to a device; a human remains
responsible for review and change control.
