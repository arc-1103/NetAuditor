# NetAudit Engine --- Additional Concrete Features

## Purpose

`Suggestions.md` is strong on architectural novelty and weak on
buildability: no compliance scoring formula, no explicit
auto/human/block decision rule, no rollback path, and a priority
roadmap that treats a cheap feature (provenance) and an expensive,
dependency-heavy feature (Batfish-based blast radius) as equally
"P0."

This document closes those gaps with concrete, implementable
specifications, and proposes a cost-aware build order.

---

# 1. Compliance Scoring Formula --- Fills a Gap

## Problem

`Suggestions.md` uses "CIS Compliance: 72%" repeatedly (counterfactual
engine, drift tracking) with no defined calculation. An undefined
number is not demoable under questioning.

## Proposed formula

```
Compliance Score =
    Σ (control_weight × control_pass) / Σ (control_weight)
```

- `control_weight`: severity tier from the framework itself
  (CIS assigns Level 1 / Level 2; STIG assigns CAT I/II/III).
  Suggested weights: CAT I / Level 2 = 3, CAT II / Level 1 = 2,
  CAT III = 1.
- `control_pass`: 1 if the control passes on the device, 0 if it
  fails, `null` (excluded from denominator) if not applicable to
  that device class.

## Per-device and fleet-wide rollup

```
Device score:  weighted pass rate for that device
Fleet score:   weighted pass rate across all devices
                (not an average of device percentages --
                 a device with 40 controls should count more
                 than one with 4)
```

## Why this matters

Every other proposed feature (counterfactual engine, drift tracking,
digital twin) consumes this number. Define it once, here, and every
downstream feature inherits a defensible answer to "how is that
percentage computed?"

---

# 2. Confidence-Weighted Auto-Decision Table --- Fills a Gap

## Problem

The Agent Firewall diagram in `Suggestions.md` asks "SAFE / BLOCK /
HUMAN APPROVAL?" at every stage but never specifies the rule. This is
the actual product surface, and it currently doesn't exist as a rule
--- only as a box in a flowchart.

## Proposed decision table

| Parser Agreement | Blast Radius | Risk | Action |
|---|---|---|---|
| ≥ 99% | 0 reachability changes | LOW | Auto-apply, log to ledger |
| ≥ 95% | ≤ 2 services affected | LOW–MEDIUM | Single human approval |
| 90–95% | any | MEDIUM | Dual approval required |
| < 90% (parser disagreement) | any | any | Block, force human review |
| any | ≥ 1 reachability change to a flagged critical service | any | Block regardless of confidence |

This table is intentionally conservative and tunable — the point is
that it exists, is versioned, and is itself an artifact in the
Provenance Graph (every remediation should record *which version of
this table* authorized or blocked it).

## Implementation note

This table should be a config object (YAML/JSON), not hardcoded logic
— so it can be edited without a code change, and so the provenance
record can cite the exact ruleset version used for a given decision.

---

# 3. Rollback & Undo Ledger --- Fills a Gap

## Problem

The system's entire pitch is "AI proposes, deterministic policy and
humans decide, only then does it act." But an *approved* action can
still be wrong — a stale topology snapshot, an underestimated blast
radius, a misconfigured test case. Nothing in `Suggestions.md`
addresses reversing a bad-but-approved change.

## Proposed mechanism

```
Pre-Change Snapshot
        |
        v
Approved Remediation Applied
        |
        v
Post-Change Verification
        |
        v
  +-----------+-----------+
  |                       |
  v                       v
Verified OK          Verification Failed
  |                       |
  v                       v
Close ledger entry    AUTO-ROLLBACK
                           |
                           v
                    Restore Pre-Change Snapshot
                           |
                           v
                    Escalate to human + log
```

- Every remediation ledger entry stores the full pre-change config
  hash (not just a diff), so rollback is a restore operation, not a
  reconstructed guess.
- Post-change verification re-runs the same blast-radius / reachability
  check *against the live device* (not just the simulation) within a
  short window (e.g. 60 seconds) to catch simulation-vs-reality drift.
- Rollback itself is logged with the same provenance fields as the
  original action (who/what/why), so an undo is never a silent event.

## Why this matters

Without this, "human approved it" is being used as the system's only
safety net. This gives the system a second one.

---

# 4. Demo-Safe Reachability Fallback --- Risk Mitigation

## Problem

Blast-Radius Analysis and the Counterfactual Compliance Engine both
depend on Batfish (or an equivalent full network simulator) working
end-to-end. Batfish requires real topology modeling and has a steep
setup curve — a common point where prototype timelines slip. If it
breaks the day before a demo, two of the three "P0" features go dark
simultaneously.

## Proposed fallback: deterministic ACL/route diffing

A lighter-weight, dependency-free reachability estimator that doesn't
require full topology modeling:

```
Proposed Config Change
        |
        v
Parse affected ACLs / route statements only
        |
        v
Diff: (permitted flows before) vs (permitted flows after)
        |
        v
Flag: newly blocked flows, newly permitted flows
        |
        v
Approximate Blast Radius
  (interfaces touched, ACL lines touched, services referenced
   in those ACLs)
```

This will not catch multi-hop topology effects the way Batfish does —
it's explicitly a narrower, best-effort estimate — but it:

- has zero external dependency risk,
- runs in milliseconds,
- gives the Counterfactual Engine and Blast-Radius feature *something
  real* to show even if Batfish integration isn't finished,
- can be kept permanently as a fast first-pass filter, with Batfish
  invoked only for changes it flags as non-trivial (a sensible
  production architecture regardless of the demo).

## Recommendation

Build this before attempting Batfish integration. Treat Batfish as an
upgrade path, not a dependency for the MVP demo.

---

# 5. Mean-Time-to-Remediate (MTTR) & Compliance SLA --- New

## Idea

`Suggestions.md`'s Drift Detection (item 8) shows compliance *dropping*
over time but never measures how long violations stay open once
found — which is the metric that actually matters to a security
buyer.

## Concrete metric

```
MTTR = time(remediation approved) - time(violation first detected)
```

Tracked per control severity tier, with a rolling dashboard:

```
CAT I violations:   avg MTTR = 4.2 hours   (target: < 8h)
CAT II violations:  avg MTTR = 1.3 days    (target: < 5 days)
CAT III violations: avg MTTR = 6.1 days    (target: < 30 days)

Open > SLA: 3 violations flagged RED
```

## Why it's worth building

This is cheap (it's a timestamp query against the existing append-only
ledger — no new subsystem) and it's the kind of metric that reads as
"enterprise-credible" rather than "hackathon demo" to a judging panel
with any security operations background.

---

# 6. Executive Compliance Report Export --- New

## Idea

None of the ten original features produce an artifact a non-technical
stakeholder (a CISO, an SIH judge without a networking background) can
actually read. Everything proposed is a live UI view.

## Concrete deliverable

A one-click generated PDF/HTML report per audit run, containing:

```
- Fleet compliance score (from Section 1 formula) + trend line
- Top 5 highest-exposure devices
- Violations found / resolved this period
- Remediations auto-applied vs. human-approved vs. blocked
- MTTR by severity tier
- Full provenance chain for any single finding, linked by ID
```

This is a small amount of new engineering (templating over data the
system already has, once Sections 1 and 5 exist) and disproportionately
improves how the project reads to evaluators who won't drive the live
UI themselves.

---

# 7. Approval Matrix / Reviewer RBAC --- New

## Idea

The Agent Firewall assumes "a human" approves. In any real deployment,
*which* human is allowed to approve *what* is itself a control.

## Concrete spec

```
Role: Network Operator
  - Can approve: LOW risk, single-device changes
  - Cannot approve: multi-device, CAT I control changes

Role: Security Lead
  - Can approve: MEDIUM risk, multi-device changes
  - Can override: single Network Operator rejection

Role: Change Advisory (2-person rule)
  - Required for: HIGH risk, reachability-changing actions
  - Requires 2 independent approvals, logged separately
```

Ties directly into the Provenance Graph (item 5 in the original doc)
— "who approved it" becomes "which role, under which permission,
matching which policy version."

---

# 8. Ticketing / SIEM Integration Hook --- New

## Idea

A webhook/API layer that pushes findings and remediation events to
external systems (ServiceNow, Jira, Slack, a generic webhook URL).

## Concrete shape

```
On new violation found       -> POST to ticketing webhook
On remediation proposed      -> POST to approval-queue webhook
On human approval/rejection  -> POST status update
On rollback triggered        -> POST high-priority alert
```

This is a small, well-scoped integration (outbound webhooks, not a
full connector suite) that signals the project is thinking about
fitting into an existing security operations workflow rather than
being a standalone demo tool — a common judging criterion for
enterprise-track hackathon projects.

---

# 9. Revised Build Order (cost-aware, not novelty-only)

The original roadmap orders by novelty value alone. This orders by
(value ÷ implementation cost), assuming limited build time:

## Tier A --- Cheap, high demo value, no external dependencies
1. Compliance Scoring Formula (Section 1)
2. Confidence-Weighted Auto-Decision Table (Section 2)
3. Policy Provenance Graph (original doc, item 5)
4. AI Interpretation Trust Layer (original doc, item 7)
5. Configuration/Compliance Drift + MTTR (original doc item 8 + Section 5)

## Tier B --- Moderate cost, de-risks the flagship feature
6. Demo-Safe Reachability Fallback (Section 4)
7. AI Authorization / Agent Firewall (original doc, item 1) --- built
   *on top of* Tier A and the Section 4 fallback, not on Batfish
8. Rollback & Undo Ledger (Section 3)

## Tier C --- High value, high cost / dependency risk
9. Blast-Radius + Counterfactual Engine with real Batfish (original
   doc, items 2–3) --- attempt only once A and B are demo-stable
10. Executive Report Export (Section 6)

## Tier D --- Longer-term / research track, not demo-critical
11. Adversarial Configuration Benchmark (original doc, item 6)
12. Policy-to-Rego Compiler (original doc, item 4)
13. Approval Matrix / RBAC (Section 7)
14. Ticketing/SIEM Hooks (Section 8)
15. Compliance Digital Twin (original doc, item 9)

## Rationale

Tier A alone is enough to demonstrate the core novelty thesis ("AI
proposes, deterministic policy + evidence decide") without touching
Batfish at all. Tier B gets the flagship Agent Firewall demoable on a
fallback that can't fail from a topology-modeling problem the night
before judging. Tier C is where the doc's most impressive material
lives — but it should be additive to a working demo, not the demo's
critical path.
