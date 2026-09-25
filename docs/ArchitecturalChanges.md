# NetAudit Engine — Architectural Changes
**Project:** NetAudit Engine (PS 26155, SIH 2026, team No_Talks_IC)
**Window:** 3 months, firm finale date
**Team:** 6 people
**Status key:** 🔴 not started · 🟡 in progress · 🟢 done · owner + last-verified date on every row — update this file when the item changes, not just when it's finished.

---

## 0. Ground rule this document enforces

The deck's one defensible sentence is: **the model never decides anything — every pass/fail comes from OPA/Rego.** Every change below is checked against that line before it's approved. If a proposed change makes the SLM (or any other model) issue a compliance verdict, it doesn't go in, regardless of how useful it looks otherwise.

---

## 1. Decision-model boundary — resolved

**Trigger:** proposal to introduce TypeSafe's Jev ("System One" model) for "decision making" in the pipeline.

**Finding:**
- Jev's weights are closed — API-only, hosted by TypeSafe. Calling it means device configs leave the premises, which breaks the "fully air-gapped, no cloud API, no telemetry" claim (slide 3).
- Using any decision model — Jev or otherwise — to produce a compliance verdict breaks the "model never decides anything" claim (slide 2).

**Resolution:**
- 🔴 No decision model of any kind in the verdict path. OPA/Rego stays the sole source of pass/fail. **Owner:** whole team / architecture review — enforce at code review, not just design time.
- 🔴 (Optional, ML-capacity-dependent) A **self-hostable** typed-decision model — `circuit-8b` (Qwen3-8B-Base + LoRA, open weights) or `any2jev` (converts a model you already run into a one-forward-pass decision model) — may be used *upstream* of the verdict only: vendor-fingerprint confidence scoring, or flagging suspicious/anomalous parsed output before it reaches OPA. Never for the verdict itself. **Owner:** whoever owns the SLM/ML workstream (§3). Build only if that workstream has capacity after the cross-check in §3 is working.

---

## 2. Credential evidence paradox — fix

**Problem:** slide 4 claims credentials are regex-redacted at ingest (hashes only retained); slide 2 claims every finding ships the failing config line as evidence. For credential-related findings (weak passwords, default SNMP strings, weak encryption types) these two claims can't both hold on the same data.

**Fix:**
- 🟢 Capture evidence **before** redaction, but store a **masked** form (e.g. last 4 characters + position + hash), never the raw credential. Evidence stays verifiable by a human; nothing sensitive persists in Postgres/MinIO/the generated report. Implemented in `services/ingestion/app/uploader.py` (`capture_credential_evidence`/`_mask_secret`), persisted via a new `audit_runs.credential_evidence` JSONB column (`infra/postgres/migrations/0005_add_credential_evidence.sql`). Not yet consumed by any compliance control or the report UI — this ticket was capture-and-storage only. **Verified:** Claude, 2026-09-25.
- 🔴 Update the "credentials inside configs" risk-containment bullet on slide 4 to describe this precisely — don't leave the current wording, which implies full redaction with no exception. (No deck file exists in this repo to edit — presentation-only, out of a code change's scope.)
- **Owner:** ingest-pipeline owner. **Effort:** ~1 day.

---

## 3. Malicious-input threat model

Four separate attack surfaces — treat as four items, not one:

| Surface | Risk | Mitigation | Owner | Status |
|---|---|---|---|---|
| Parser (TextFSM/NTC-Templates, chunking) | Regex catastrophic backtracking, oversized input defeating chunking assumptions | Hard timeout + size cap at ingest; parse in a resource-bounded subprocess | Ingest-pipeline owner | 🟢 Per-line length cap in `services/ingestion/app/chunker.py` (`max_line_length`, truncates + marks pathologically long lines before chunking). Mock-mode regex extraction (`services/parsing/app/slm_client.py`) now runs in a real `ProcessPoolExecutor` subprocess with a hard wall-clock deadline (`PARSE_TIMEOUT_SECONDS`, env-overridable) — a genuine OS-process kill, not a thread-based timeout Python's GIL can't enforce. Verified the stuck-process reclaim actually works (its future resolves with `BrokenProcessPool` instead of hanging forever) and that the next chunk lands on a fresh pool without queuing behind it. The real (non-mock) Ollama path already had its own bounded HTTP timeout — untouched. **Verified:** Claude, 2026-09-25. |
| SLM input (Qwen2.5-Coder-7B + Outlines) | Grammar constraint bounds *output schema*, not semantic correctness — adversarial content in a config can produce a schema-valid but wrong object, which passes straight through to OPA | (1) Independent cross-check: run TextFSM and SLM extraction in parallel, flag disagreement. (2) Anomaly/plausibility scoring of parsed output against known-good corpus distribution. Neither fully closes this — it's a mitigation, not a fix; state that honestly if asked | ML/SLM workstream owner | 🔴 — genuinely hard, budget for early attempts not working |
| Remediation templates (Jinja2) | Template injection if config-derived content is ever rendered *as* template source rather than passed as a variable | `jinja2.sandbox.SandboxedEnvironment`, `autoescape=True`; config values only ever passed as variables, never concatenated into template source | Remediation-engine owner | 🟢 `services/remediation/app/template_engine.py` now uses `SandboxedEnvironment`. `autoescape` deliberately left `False`: these templates render plain-text vendor CLI, not HTML — autoescaping would corrupt legitimate output (e.g. an `&` in a login banner becoming `&amp;` in the actual device config). Confirmed `context` is already only ever passed as template variables, never concatenated into template source. **Verified:** Claude, 2026-09-25. |
| File type / format | Files claiming to be Cisco IOS config but are archives, binaries, or malformed encodings designed to break ingest | MIME/extension allowlist; reject anything else pre-parse; decompressed-size cap if archives are accepted at all | Ingest-pipeline owner | 🔴 |

**Effort:** parser + template + file-type gates are days, not weeks — do these first (weeks 1–2). The SLM cross-check is the long pole (see §5).

---

## 4. Append-only ledger

**Problem (from slide 8, amber item):** `audit_runs` persists state, but findings are replaced on re-evaluation — it's an auditable run record, not an append-only ledger, despite the "evidence-linked, reproducible" framing.

- 🟢 Built as `ledger_events` (`infra/postgres/migrations/0006_add_ledger_events.sql`) — a separate append-only event stream (VIOLATION_DETECTED, REMEDIATION_PROPOSED, DECISION_MADE, APPROVED/REJECTED, APPLIED, VERIFICATION_FAILED, ROLLED_BACK, REPORT_GENERATED), not a redesign of `compliance_findings` itself, which stays current-state/replace-on-re-evaluation as before. `compliance_findings` remains the queryable "what does this run look like now" table; `ledger_events` is the "what happened and when" trail MTTR (docs/Additional-Features.md §5), rollback (§3), approval provenance (§7), and the webhook dispatcher (§8) all read from. Old findings snapshots by evaluation are still separately available via the pre-existing `audit_evaluations` table. **Owner:** backend/data-model owner. **Verified:** 2026-09-25.

---

## 5. Benchmark harness + labelled corpus

**This is the actual long pole of the three months — not the code.**

- 🔴 Corpus labelling against CIS/STIG/NIST ground truth. Domain-review work; does not compress by adding people who aren't confident reviewing configs against these frameworks.
- 🔴 Harness measuring parse latency, batch throughput, control coverage — replaces slide 5's "design targets" with measured numbers, published with the dataset (already a public commitment in the deck's own notes).
- 🔴 Same labelled corpus feeds the SLM/TextFSM disagreement check in §3 — start this in week 1, not month 3.
- **Owner:** 2 people, dedicated, weeks 1–12.

---

## 6. New-vendor mapping GUI

- 🔴 Already named as the "principal finale-build deliverable" (slide 9's own notes). Don't let it slip because it wasn't part of this review.
- **Owner:** 1 person, weeks 4–9.

---

## 7. Timeline

| Weeks | Workstream | Owner(s) |
|---|---|---|
| 1–2 | Ingest gate, Jinja2 sandboxing, credential evidence fix | 1 |
| 1–4 | Append-only ledger redesign | 1 |
| 1–12 | Corpus labelling + benchmark harness | 2 |
| 1–6 | SLM/TextFSM cross-check + anomaly scoring | 1–2 (strongest ML person) |
| 4–9 | Vendor-mapping GUI | 1 |
| 10–12 | Integration, demo rehearsal, QA against live prototype, deck rewrite with real numbers | all 6 |

---

## 8. Items to state honestly, not solve

- The SLM-input semantic-manipulation gap (§3) is mitigated, not closed, even after three months. Say so if asked — same move the deck already makes on slide 4's unbenchmarked figures.
- If the ML/anomaly-detection workstream turns out to be understaffed relative to skill, cut it back to the cross-check alone and drop anomaly scoring rather than ship something unvalidated.
