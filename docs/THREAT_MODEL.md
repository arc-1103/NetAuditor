# NetAudit prototype threat model

## Assets and trust boundaries

Protected assets are raw configurations, credentials embedded in them,
normalized baselines, compliance verdicts, remediation scripts, operator
identities and audit reports. The browser and uploaded files are untrusted.
Only the gateway is exposed; application services communicate on an internal
Compose network. PostgreSQL, MinIO, Redis, ChromaDB, Neo4j, OPA and Ollama are
not public ingress points.

## Principal threats and controls

| Threat | Current mitigation | Residual work |
|---|---|---|
| Malicious or oversized upload | extension + MIME check, bounded streaming, size limit | archive formats intentionally unsupported |
| Secret disclosure | line-oriented credential redaction before object storage | expand vendor-specific patterns; encrypt volumes |
| Parser hallucination | strict schema, confidence/logprob and reverse-translation gates | benchmark on reviewed vendor corpus |
| False clean verdict | invalid/uncertain parses become `NEEDS_REVIEW`; unavailable OPA is an error | formal coverage indicator per schema section |
| Policy tampering | read-only mounted, versioned Rego; bundle version in history | sign release bundles |
| Unsafe remediation | allow-listed templates, static/Batfish preflight, human gate | real topology validation per site |
| AI-generated command execution | agentic proposals forced to `RISK_FLAGS` and unapprovable | require a reviewed template promotion workflow |
| Broken access control | signed JWT plus admin/operator/auditor roles | external identity provider and token revocation |
| Credential guessing/DoS | bcrypt, request rate limiting, bounded upstream timeouts | distributed limiter at ingress for multi-instance deployment |
| Audit-history rewriting | append-only evaluation snapshots plus current-state view | database roles/triggers and external WORM export |
| Dependency compromise | pinned application dependencies, lockfile and CI audit | pin container digests and generate signed SBOM in releases |

## Non-goals

The prototype does not push configuration directly to production equipment,
replace organizational change control, establish certification against a full
commercial benchmark, or prove that every vendor syntax has been parsed.

## Security invariants

1. AI output cannot directly create a compliance verdict.
2. An unavailable evaluator cannot yield a clean result.
3. Insufficient parsing evidence cannot yield `COMPLIANT`.
4. A proposal that is not `SAFE` cannot be approved.
5. An AI-generated proposal is never `SAFE`.
6. Every persisted evaluation identifies its configuration, normalized baseline,
   schema, policy bundle and evaluation time.
