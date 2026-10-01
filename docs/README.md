# Documentation map

Start with the root [`README.md`](../README.md) for what the system does,
[`SETUP.md`](../SETUP.md) to run it, and [`Architecture.md`](../Architecture.md)
for how it works.

**[`../Architecture.md`](../Architecture.md) is the authoritative architecture
reference.** Everything in this folder is either a submission deliverable, a
specification that code comments cite, or a single-feature engineering note.

## Submission package

Use only these for SIH upload.

- [`SUBMISSION_CHECKLIST.md`](SUBMISSION_CHECKLIST.md) — final upload checklist and honest scope matrix
- [`ARCHITECTURE_SUBMISSION.md`](ARCHITECTURE_SUBMISSION.md) — condensed architecture for the two-page limit
- [`PRESENTATION_CLAIMS_CHECKLIST.md`](PRESENTATION_CLAIMS_CHECKLIST.md) — defensible prototype wording
- [`EVALUATION_ALIGNMENT.md`](EVALUATION_ALIGNMENT.md) — requirement-to-evidence map
- [`../presentation/FINAL_PROTOTYPE_DECK.md`](../presentation/FINAL_PROTOTYPE_DECK.md) — five-slide deck source
- [`../demo/DEMO_SCRIPT.md`](../demo/DEMO_SCRIPT.md) — four-minute demo; trim for the two-minute video

## Specifications cited from code

**Do not delete these.** Roughly 420 citations across 180+ source files reference them by section number
(`# docs/action.md Phase 2`, `docs/Suggestions.md item 7`). They are the
requirements traceability for features already built.

- [`Additional-Features.md`](Additional-Features.md) — numbered feature specs (§1–§8); 254 citations in 112 files
- [`Suggestions.md`](Suggestions.md) — numbered improvement items; 84 citations in 61 files
- [`action.md`](action.md) — phased delivery plan; 65 citations in 52 files
- [`ArchitecturalChanges.md`](ArchitecturalChanges.md) — accepted design changes; 17 citations in 17 files

## Feature and operations notes

One subsystem each, kept beside the code they describe.

| Doc | Covers |
|---|---|
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Security analysis — read before any deployment |
| [`PARSER_SANDBOX.md`](PARSER_SANDBOX.md) | Parser container hardening, gVisor/AppArmor upgrade path |
| [`LEDGER_INTEGRITY.md`](LEDGER_INTEGRITY.md) | Append-only event ledger and seals |
| [`WAIVERS.md`](WAIVERS.md) | Accepted-risk workflow |
| [`DIGITAL_TWIN.md`](DIGITAL_TWIN.md) | Fix simulation and Z3 verification |
| [`AIRGAP_UPDATE_PROCEDURE.md`](AIRGAP_UPDATE_PROCEDURE.md) | Signed rule/template transfer across the gap |
| [`LOCAL_LLM_SETUP.md`](LOCAL_LLM_SETUP.md) | Ollama configuration and model choice |
| [`SECRETS_VAULT.md`](SECRETS_VAULT.md) | Vault integration (`secrets` profile) |
| [`IAM_KEYCLOAK.md`](IAM_KEYCLOAK.md) | Keycloak identity (`iam` profile) |
| [`SIEM_FORWARDING.md`](SIEM_FORWARDING.md) | Fluent Bit CEF/JSON event forwarding |
| [`TIME_SYNC.md`](TIME_SYNC.md) | Trusted time for ledger timestamps (`time` profile) |
| [`REMEDIATION_REPORTING_DEMO.md`](REMEDIATION_REPORTING_DEMO.md) | Remediation and reporting walkthrough |
| [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) | Pre-release gates |
| [`ARCHITECTURE_ADVANCED_FEATURES.md`](ARCHITECTURE_ADVANCED_FEATURES.md) | Detailed design of the optional `advanced`-profile features |

## Historical

- [`MEMORY.md`](MEMORY.md) — durable lessons from building the harder lanes
  (active learning, reverse translation, GraphRAG, anomaly detection). Written
  forward-looking, so it stays useful; not a status snapshot.
- [`SIH26155_NetAudit_Architecture_Blueprint.md`](SIH26155_NetAudit_Architecture_Blueprint.md) —
  the original long-form blueprint. Kept as the design's origin record. Where it
  disagrees with [`../Architecture.md`](../Architecture.md), the latter is correct.

Per-service `README.md` files cover component-specific setup and behaviour.
