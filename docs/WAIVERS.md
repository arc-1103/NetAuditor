# Time-bounded waivers (accepted risk)

Some devices must fail a control on purpose: an unpatched legacy system isolated for
a mission, a deliberately vulnerable honeypot. A waiver records that decision without
hiding the failure.

## What a waiver does

- **Excludes the finding from the score and from new alerts** (webhooks and the SIEM
  feed) for a fixed period.
- **Never deletes or hides the finding.** It stays in the evidence, annotated WAIVED
  with who granted it, why, the ticket, and the expiry. The score is shown both ways
  ("score without waivers").
- **Ends by itself.** Status is computed from the clock: after the expiry the finding
  counts again and the audit says "a waiver expired on <date>". There is no cleanup
  job that could forget.
- **Is tamper-evident.** Grants and revocations are ledger events, covered by the
  signed Merkle seals (`docs/LEDGER_INTEGRITY.md`). When a signing key is configured a
  new waiver is sealed immediately, so editing or deleting it later is detected by
  `GET /api/ledger/verify`.

## Rules

- Admins only (grant and revoke). Every grant records the verified user.
- A written justification of at least 15 characters is required.
- Must expire in the future, at most `WAIVER_MAX_DAYS` (default 90). To continue, grant
  a new one; the register keeps the full history.
- Only for a control that is failing in that audit.
- A waiver applies to one control on one device (vendor + hostname), across audits of
  that device, and never to another device.

## Where it shows

Audit workspace (WAIVED badge, waiver section in the finding drawer, waived count by
the score), Reports (waiver register with revoke), the PDF ("Waived Findings
(Accepted Risk)" with approver, expiry and ticket), and the JSON report.

## Limits

- The executive fleet score does not apply waivers yet; it still counts every
  failure. Say so if asked.
- A waiver is an accepted-risk record, not a compensating control. Require the
  justification to name the compensating control (for example an air-gapped VLAN).
- Existing databases need migration `0013_add_waiver_events.sql` (it extends the
  allowed ledger event types) before waivers can be granted.
