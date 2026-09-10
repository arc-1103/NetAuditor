# NetAudit — panelist-friendly presentation guide

## The one-sentence idea

NetAudit reads the settings of different network devices, finds unsafe choices,
shows the exact proof, and proposes a fix that a human must approve.

## Explain the problem without jargon

“A large organization may have routers and firewalls from many companies. Each
company writes its settings differently, so checking them by hand is slow and
mistakes are easy. NetAudit translates those different formats into one common
security checklist.”

## Explain the four screens

1. **Upload:** We provide a device's text configuration. It is fingerprinted so
   the report can prove which file was checked.
2. **Results:** Red means urgent. Each finding says what is wrong and shows the
   supporting line from the file.
3. **Safe fix:** NetAudit prepares a vendor-specific change. A safety check runs
   first, and a person—not the AI—decides whether to approve it.
4. **Report:** The evidence, rule version, file fingerprint, and approval history
   are exported for an auditor.

## A simple analogy

“Think of NetAudit as a spell-checker for network security. It understands
different device languages, underlines risky settings, explains why they are
risky, and suggests a correction. Unlike autocorrect, it never applies a
security change without permission.”

## If asked where AI is used

“AI helps read messy vendor language and convert it into structured facts. A
fixed, version-controlled rule engine makes every pass/fail decision. This keeps
the flexible part useful and the accountable part repeatable.”

## If asked whether it is complete

“Today is a working prototype proving the full loop for Cisco and Fortinet with
11 CIS-inspired checks: upload, normalize, evaluate, explain, propose a fix,
approve, and report. Production work is broader vendor coverage, validated
official policy mappings, enterprise identity, and larger-scale testing.”

## Likely panel questions

**Why not use only AI?** AI output can vary. Security verdicts must be repeatable,
so AI extracts facts and deterministic rules decide.

**How do you prevent a bad fix?** Reviewed templates are simulated first. Unsafe
or incomplete proposals are blocked, and every approval is attributed to a
person.

**What happens without internet?** The core services and model can run locally,
which is important for sensitive configurations and isolated networks.

**How do you add another vendor?** Add a parser that maps its syntax into the
same security model. The common checks can then be reused; only vendor-specific
fix templates need adaptation.

**Is this CIS certified?** No. The prototype demonstrates an 11-control,
CIS-inspired policy set. Official mappings and certification are roadmap work.

## Words to prefer

- “common security model” instead of “canonical Pydantic schema”
- “fixed security rules” instead of “OPA/Rego policies”
- “proof from the uploaded file” instead of “source provenance”
- “safety simulation” instead of “preflight validation”
- “works without internet” instead of “air-gapped deployment”
- “other devices that may be affected” instead of “GraphRAG blast radius”

## Closing line

“NetAudit turns different device languages into one understandable, provable,
human-controlled security workflow.”
