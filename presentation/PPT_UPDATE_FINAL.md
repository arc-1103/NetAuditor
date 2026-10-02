# PPT update: UI changes to add to the five-slide deck

Applies to `NetAudit_SIH2026_5slides_v3.pptx` (outline in `FINAL_PROTOTYPE_DECK.md`).
Slide count stays at five. Slides 1 and 5 do not change. Edit slides 2, 3 and 4 as below.

---

## Slide 2: One safe, explainable pipeline

**Add one bullet** under the existing four:

- The analyst console follows the same four stages: Discover → Normalize → Audit → Remediate. Each screen shows which stage it belongs to and what decision it asks for.

No other change.

---

## Slide 3: Live prototype: evidence to safe action

**Replace step 4** with:

4. Show a **Remediation Action Card** per finding: the exact violating lines, the vendor CLI fix, the rollback script, and a row of five checks (source, preflight, reachability, policy, your role) that explains every disabled button. The main button follows the approval lifecycle: Approve → second approval → Mark applied → Roll back.

**Add after the numbered list:**

> Console design: dark mode and high data density. Red and orange are reserved for real problems. Passing items stay neutral, so alerts are what the eye finds first.

**Replace the Visual line** with:

Visual: screenshot of the finding drawer with the Remediation Action Card, showing the violating line, the CLI fix, the five checks and the approval button. Take it from the running app, not a mockup (see the checklist below).

---

## Slide 4: Innovation, proof and honest scope

**Add one row** to the table:

| Analyst-safe interface | Fixes are approved by people, never pushed by the tool. Reviewed templates can be approved. AI-drafted fixes are labeled unverified and cannot be approved. Two-person rule and role limits are shown on the card. |

**Add to the "Demonstrated today" paragraph**, after "single-file upload":

the analyst console with role-aware approval.

Keep the existing sentence that this is not CIS certification or independent real-device validation.

---

## Screenshot checklist

Capture these from the running app (hard-reload first, since the browser may cache the old page):

1. Finding drawer with the card, scenario: template fix, preflight SAFE, signed in as admin.
2. The same card signed in as auditor, with the button disabled and the reason shown.
3. An AI-drafted fix (no template for the vendor): amber "unverified" label, Approve disabled.
4. Upload screen after the layout fix.

Use only screenshots you have actually seen. The card has not been checked in a browser yet.

---

## Do not claim

- That NetAuditor deploys fixes to devices. It does not. An operator applies the fix and records it.
- GPU-accelerated inference. The model does not load on the GPU yet.
- CIS certification. Keep the existing "CIS-inspired" wording.
- Any figure from the design mockups (scores, device counts, vendor tables). They are example data.

---

## Speaker line for slide 3

"The AI drafts and explains. Fixed rules decide. A person approves. The card shows the analyst why a fix can or can't go ahead."
