# NetAudit Engine — five-slide technical presentation

Use one `##` section per slide. Footer:
`SIH26155 · NTRO · NetAudit Team · github.com/arc-1103/NetAuditor`.

## 1. The gap: mixed networks, fragmented assurance

**AI-Driven Multi-Vendor Network Security Compliance Auditor**

- Enterprises run incompatible Cisco, Fortinet, Juniper, Palo Alto and cloud syntax.
- Manual checklists are slow; vendor-locked suites are expensive and brittle.
- One misconfiguration—Telnet, weak crypto, default SNMP or missing logs—can expose the network.

**Our outcome:** upload raw configuration and receive line-level evidence,
severity, a guarded vendor-specific fix and an auditable report—offline.

Visual: vendor configuration snippets converging into one NetAudit shield.

## 2. One safe, explainable pipeline

```text
Upload → redact + hash → identify + normalize → validate
       → deterministic OPA verdict → preflighted remediation
       → human approval → PDF / JSON / CEF evidence
```

- Local AI interprets syntax; it never decides compliance.
- A strict vendor-neutral Pydantic model is the source of truth.
- Low confidence or invalid structure becomes `NEEDS_REVIEW`, never PASS.
- Docker profiles keep the core reliable and advanced AI/topology optional.

Visual: architecture from `docs/ARCHITECTURE_SUBMISSION.md`.

## 3. Live prototype: evidence to safe action

Demo `demo/cisco_insecure.cfg`:

1. Detect Cisco IOS-XE; redact credentials; preserve SHA-256 provenance.
2. Evaluate 11 CIS-inspired controls and show exact offending source lines.
3. Generate reviewed Jinja2 CLI; mark placeholders/environment risks.
4. Enable approval only for `SAFE` proposals; retain operator attribution.
5. Export a device report in browser/PDF plus JSON and CEF.

Also validated: Fortinet fixture, RBAC gateway, immutable evaluation versions,
offline UI fallback and optional local Qwen explanation.

Visual: dashboard screenshot with evidence line and SAFE approval state.

## 4. Innovation, proof and honest scope

| Differentiator | Prototype proof |
|---|---|
| AI/rules separation | Schema gate + OPA-only verdicts |
| Unknown-vendor learning | Admin-reviewed mapping/RAG APIs |
| Safe remediation | Template provenance + preflight + human approval |
| Defensible output | Source lines + policy/schema/baseline versions |
| Sovereign deployment | Local services; no cloud dependency at runtime |

**Demonstrated today:** Cisco IOS-XE and Fortinet FortiOS, single-file upload,
one 11-control CIS-inspired policy bundle. This is not CIS certification.

Visual: green checks for demonstrated capability; grey roadmap tags for bulk UI,
complete framework content and additional validated vendors.

## 5. Scale path, impact and ask

**Next 90 days**

- Validate Juniper/Palo Alto adapters and add bulk inventory ingestion.
- Encode authorized CIS, NIST, STIG and ISO mappings as versioned bundles.
- Wire the learning queue into the dashboard and benchmark false mappings.
- Pilot with sanitized configurations; measure audit time, precision/recall and
  remediation acceptance.

**Impact:** one explainable compliance workflow for heterogeneous networks,
lower manual effort, faster evidence production and safer change preparation.

**Ask:** representative sanitized configurations, framework SMEs and a
controlled pilot environment.

- Repository: `https://github.com/arc-1103/NetAuditor`
- Demo video: `<insert final public link>`
- Team: `NetAudit Team · Manav Mishra · manavmishra260205@gmail.com`
