# NetAudit Engine --- Novelty Suggestions

## Objective

Strengthen NetAudit Engine's novelty beyond "LLM + network compliance"
by positioning it as a **trusted execution boundary for AI-driven
network security**.

The current architecture already establishes an important foundation:

> **The model parses; the policy decides.**

The proposed extensions should build on that architecture rather than
replace it.

------------------------------------------------------------------------

# 1. AI Authorization / Agent Firewall --- Highest Priority

## Idea

Introduce an explicit authorization layer between AI-generated actions
and network infrastructure.

The AI should be able to:

-   interpret configurations
-   identify violations
-   propose remediation
-   explain proposed changes

But it should **not directly execute network changes**.

### Proposed flow

``` text
AI / Automation
      |
      v
+----------------------+
|   AI AGENT FIREWALL  |
|                      |
| What can AI do?      |
| What requires review?|
| What is prohibited?  |
+----------+-----------+
           |
           v
   Authorization Policy
           |
           v
   Network Action
```

## Example

``` text
AI Proposal:
"Disable Telnet on R1"

        ↓

Authorization Engine

Device: R1
Action: configuration change
Affected control: CIS-X
Risk: LOW
Blast radius: 0 reachable services

        ↓

Policy

Allowed?
Simulation required?
Human approval required?

        ↓

SAFE / BLOCK / HUMAN APPROVAL
```

## Novelty

The system is not simply an AI network copilot.

It becomes a **policy-enforced runtime boundary between AI agents and
network infrastructure**.

------------------------------------------------------------------------

# 2. Blast-Radius Analysis

## Idea

For every proposed remediation, calculate what the change could affect.

Instead of only asking:

> "Is this fix compliant?"

ask:

> **"What could this fix break?"**

## Potential outputs

``` text
Device: R1
Interfaces affected: 4
ACLs affected: 2
Routes affected: 0
Services affected: 1
Reachability changes: 0
Compliance controls improved: 2
Risk: LOW
```

For a dangerous change:

``` text
Devices affected: 3
Flows affected: 147
Services affected: 12
Reachability changes: 31
Risk: HIGH
```

## Implementation direction

Use Batfish or equivalent network analysis to compare:

``` text
Current topology
        vs.
Proposed topology/configuration
```

Then expose the delta to the authorization layer.

## Why it matters

This makes remediation **consequence-aware**, not merely syntax-aware.

------------------------------------------------------------------------

# 3. Counterfactual Compliance Engine --- High Demo Value

## Idea

Allow an operator to ask:

> **"What happens if I apply this fix?"**

The system evaluates the proposed configuration before it is applied.

### Example

``` text
CURRENT STATE

CIS Compliance: 72%
Violations: 14
Risk: Medium

        ↓

PROPOSED FIXES

+ Disable Telnet
+ Enable password encryption
+ Configure login blocking

        ↓

COUNTERFACTUAL ANALYSIS

CIS Compliance: 89%
Violations: 7
Reachability: unchanged
Risk: Low

        ↓

SAFE
```

## Compare

The UI should show:

-   current compliance
-   proposed compliance
-   network reachability before/after
-   affected devices
-   affected controls
-   risk changes
-   proposed commands

## Novelty

NetAudit becomes a **decision-support simulator**, not just a compliance
scanner.

------------------------------------------------------------------------

# 4. Policy-to-Rego Compiler

## Idea

Reduce the manual effort required to convert security frameworks into
executable policy.

### Proposed pipeline

``` text
CIS / STIG / NIST Policy
          |
          v
    Policy Parser
          |
          v
     Control IR
          |
          v
   Candidate Rego
          |
          v
   Test Generation
          |
          v
   Policy Validation
          |
          v
    Trusted Bundle
```

## Important security constraint

The LLM may generate a **candidate** rule.

It must never automatically become authoritative.

The rule should pass:

-   syntax validation
-   semantic validation
-   known test cases
-   regression tests
-   policy review

before entering the trusted Rego bundle.

## Novelty

This creates a path toward **automated compliance-policy engineering**
while preserving deterministic enforcement.

------------------------------------------------------------------------

# 5. Policy Provenance Graph

## Idea

Make every finding traceable from policy source to final remediation.

### Example

``` text
CIS Control
     |
     v
Rego Rule v1.4
     |
     v
Normalized Config Field
     |
     v
Raw Config Line
     |
     v
Finding
     |
     v
Remediation
     |
     v
Pre-flight Result
     |
     v
Human Approval
```

## Every finding should answer

-   Which framework control?
-   Which policy version?
-   Which Rego rule?
-   Which normalized field?
-   Which raw configuration line?
-   Which configuration hash?
-   Which remediation?
-   What did pre-flight report?
-   Who approved the action?

## Novelty

This strengthens NetAudit's existing evidence-linked and append-only
audit architecture into a full **policy-to-action provenance chain**.

------------------------------------------------------------------------

# 6. Adversarial Configuration Benchmark

## Idea

Turn the current "adversarial config" concern into an explicit research
feature.

The existing design already identifies the risk of a **valid-but-wrong
object** and proposes TextFSM/SLM cross-checking plus anomaly detection.

Expand this into a benchmark.

## Test classes

``` text
Normal configuration
        ↓
Expected parsing

Ambiguous configuration
        ↓
Expected human review

Malformed configuration
        ↓
Expected rejection

Adversarial configuration
        ↓
Expected rejection / escalation
```

## Measure

-   parser disagreement
-   extraction accuracy
-   schema rejection rate
-   policy-result deviation
-   false acceptance rate
-   unsafe-remediation rate
-   human-review rate

## Potential research metric

### Unsafe Action Escape Rate

Percentage of adversarial inputs that result in an unsafe or
unauthorized remediation reaching the execution/approval boundary.

This would give the project a measurable AI-security dimension.

------------------------------------------------------------------------

# 7. AI Interpretation Trust Layer

## Idea

Expose the provenance and agreement of every AI-derived interpretation.

Instead of:

``` text
hostname = R1
```

show:

``` text
hostname = R1

Source:
TextFSM

SLM:
R1

Agreement:
98%

Evidence:
line 4

Confidence:
HIGH

Authority:
Deterministic parser
```

If parsers disagree:

``` text
TextFSM: ALLOW
SLM: DENY

DISAGREEMENT
↓
HUMAN REVIEW
```

## Why

The current architecture already uses confidence thresholds and human
confirmation.

Making this visible gives the operator a direct view into **why the
system trusts or distrusts an interpretation**.

------------------------------------------------------------------------

# 8. Configuration Drift + Compliance Drift

## Idea

Use the existing append-only ledger and configuration hashes to detect
security posture changes over time.

### Example

``` text
Monday
CIS Compliance: 94%

Tuesday
CIS Compliance: 91%

Wednesday
CIS Compliance: 83%
```

NetAudit identifies:

``` text
Device: R14

BEFORE:
service password-encryption

AFTER:
[removed]

Compliance impact:
CIS-X → FAIL
```

## Capabilities

-   configuration drift
-   compliance drift
-   newly introduced violations
-   resolved violations
-   unexplained changes
-   policy-version impact

## Novelty

This turns the ledger from an audit archive into a **security-state
history**.

------------------------------------------------------------------------

# 9. Compliance Digital Twin

## Idea

Represent the network as a continuously queryable security state.

``` text
                 NETAUDIT
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
   CONFIG STATE  POLICY STATE  NETWORK STATE
        |           |           |
        +-----------+-----------+
                    |
                    v
             SECURITY STATE
```

The system could answer:

-   What controls are currently violated?
-   What changed since the previous audit?
-   What remediation would fix the most violations?
-   What would a proposed change affect?
-   Which devices have the highest compliance exposure?
-   Which remediation has the smallest blast radius?

This should be treated as a longer-term extension rather than a
mandatory SIH feature.

------------------------------------------------------------------------

# 10. Recommended Combined Architecture

The strongest novelty direction is to combine the most complementary
ideas.

``` text
             RAW CONFIG / POLICY
                     |
                     v
          +---------------------+
          | AI NORMALIZATION    |
          | SLM + DETERMINISTIC |
          | PARSERS             |
          +----------+----------+
                     |
                     v
               SCHEMA GATE
                     |
                     v
          +---------------------+
          | POLICY AUTHORITY    |
          | OPA / REGO          |
          +----------+----------+
                     |
                     v
              COMPLIANCE STATE
                     |
             +-------+-------+
             |               |
             v               v
        VIOLATION        FIX PROPOSAL
                             |
                             v
                    BLAST-RADIUS ENGINE
                             |
                             v
                   COUNTERFACTUAL TEST
                             |
                             v
                          BATFISH
                             |
                    +--------+--------+
                    |                 |
                    v                 v
                  SAFE           RISK FLAG
                    |                 |
                    v                 v
             HUMAN APPROVAL         BLOCK
```

Every proposed action should produce:

``` text
WHO proposed it?
WHAT policy allowed it?
WHAT evidence supports it?
WHAT configuration changes?
WHAT network behavior changes?
WHAT devices are affected?
WHAT compliance controls change?
WHAT simulation says?
WHO approved it?
WHAT actually happened?
```

------------------------------------------------------------------------

# 11. Priority Roadmap

## P0 --- Strongest novelty / SIH impact

### 1. AI Authorization / Agent Firewall

Make this the central differentiator.

### 2. Blast-Radius + Counterfactual Remediation

Show that NetAudit evaluates consequences before changes reach
infrastructure.

### 3. Evidence + Policy Provenance

Connect policy → rule → config line → finding → remediation → approval.

------------------------------------------------------------------------

## P1 --- Strong research differentiation

### 4. Adversarial Configuration Benchmark

Create measurable security evaluation for AI-assisted parsing.

### 5. AI Interpretation Trust Layer

Expose parser/SLM agreement, confidence, evidence and escalation.

### 6. Compliance Drift

Use the append-only ledger to detect changes over time.

------------------------------------------------------------------------

## P2 --- Longer-term platform capabilities

### 7. Policy-to-Rego Compiler

Automate framework-to-policy engineering with validation gates.

### 8. Compliance Digital Twin

Build a persistent security-state model of the network.

------------------------------------------------------------------------

# 12. What NOT to Add

Avoid adding features just to make the architecture bigger.

Do not make the novelty claim:

``` text
"We use Qwen."
"We use RAG."
"We use multiple LLMs."
"We use Batfish."
"We use OPA."
"We support many vendors."
```

These are implementation choices or existing capabilities.

The stronger claim is:

> **AI can interpret and propose, but it cannot become the authority
> that decides or directly changes network state. Deterministic policy,
> simulation, authorization and human approval form the trust
> boundary.**

------------------------------------------------------------------------

# 13. Recommended Novelty Thesis

## Short version

> **NetAudit is a trusted execution boundary for AI-driven network
> security: AI interprets configurations and proposes remediation, while
> deterministic policy, evidence provenance, network simulation and
> authorization controls determine whether any action can proceed.**

## One-line pitch

> **"Let AI reason about the network --- never let AI be the authority
> over the network."**

## Core differentiator

``` text
AI
↓
INTERPRET
↓
VERIFY
↓
POLICY
↓
SIMULATE
↓
AUTHORIZE
↓
ACT
```

This should be the conceptual evolution of the current NetAudit Engine.
