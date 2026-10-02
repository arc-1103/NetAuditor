# NetAuditor UI spec

Dark-mode, high-density analyst console. Full spec with live mocks and the
interactive Remediation Action Card: https://claude.ai/artifact/F1n5XRxeUgdCdZ7zMx1bey
(private; ask the owner for access). This file is the in-repo summary.

## Fixes are approved, not deployed

NetAuditor never pushes changes to devices. The Remediation Action Card's
primary button follows the lifecycle in `services/remediation/app/approval_matrix.py`:
Approve → second approval (two-person rule) → Mark applied → Roll back.
AI-synthesized drafts (`source: "agentic_rag"`) are never approvable. Every gate
that can disable the button is shown on the card.

## Workflow

Discover → Normalize → Audit → Remediate. Every screen belongs to one stage.

## Layout

| Region | Size | Notes |
|---|---|---|
| Top bar | 48px | scope, audit-run picker (timestamp + policy bundle version), search, role |
| Pipeline strip | 36px | item counts per stage; click filters the workspace |
| Nav rail | 56 / 224px | collapse state saved per user; badges count only actionable items |
| Workspace | fluid, min 720px | 12 columns, 16px gutters; tables over 200 rows virtualized |
| Detail drawer | 480px (420–640) | one item at a time; pinned header and footer; `J`/`K` step, `Esc` closes |

Below 1024px the rail moves to a bottom bar, the drawer becomes a full-screen
sheet, and the split view stacks raw above normalized. Density: compact by
default (28px rows, 13px base); comfortable toggle changes padding only.

## Views

- **Global Compliance Dashboard:** one-row score ledger (CIS L1, NIST as a
  crosswalk from CIS results, devices audited, parse confidence, open
  critical/high, awaiting approval); priority feed of failing, unwaived
  findings sorted by risk, severity, age; pass rate per control; per-vendor
  table including an "Unrecognized" row. An unevaluated run shows "Not
  evaluated", never a score.
- **Normalization split-screen:** raw config left, `SecurityBaseline` right,
  matched lines highlight on both sides. Severity markers appear only in the
  normalized gutter. Unmapped lines are marked and sent to the Learning queue.
  Confidence ledger (parse confidence, fidelity, agreement) stays in the
  header. Read-only.
- **Remediation Action Card:** `frontend/src/components/RemediationActionCard.tsx`.

Devices are gated by parse confidence only, never by a vendor allowlist.

## Color

Color marks deviations. Everything fine stays neutral.

- **Alert (red, orange):** CRITICAL/HIGH chips, offending config lines,
  regressions, failed gates. Nothing else.
- **Attention (amber):** MEDIUM, risk flags, AI drafts, low confidence, needs review.
- **Action (teal):** primary buttons, focus, selection, matched lines.
- Only the CRITICAL chip is a solid alert fill. HIGH is outlined, MEDIUM tinted,
  LOW a neutral outline.
- Passing items stay neutral. No vendor colors. Color is never the only signal.

Tokens live in `frontend/src/app/styles.css`. `--dim` is `#7a8692` in dark mode
(4.81:1 on `--panel`).

## Type

IBM Plex Sans for the interface, IBM Plex Mono for anything machine-produced
(config, control IDs, hostnames, IPs, hashes, scores). Sizes: 20 view title, 15
card title, 13 body, 12 table and meta, 11 labels (caps, +0.06em tracking).
Numeric columns use `tabular-nums` and align right. Hashes show 4 characters
per side.
