# Compliance / OPA Lane — Handover Report

**Lane:** Compliance / OPA (`services/compliance/`) — see `/TEAM_OWNERSHIP.md`
**Author:** Ayush
**Scope of this report:** everything built for the Compliance lane, the MinIO
fix that came with it, plus every bug and cross-lane correction found along the
way.

Sections 3 and 4 are the ones other lanes need to act on.

---

## 1. What was built

### 1.1 The policy bundle — `services/compliance/policies/`

`cis/cisco_ios_level1.rego` implements CIS Cisco IOS Level 1 as an illustrative
subset, per master blueprint §7. Eleven controls: the six in the blueprint plus
five more built off fields the schema already carries.

| Control | Severity | Fires when | Remediation template |
|---|---|---|---|
| CIS-IOS-1.1.1 | HIGH | `ssh.version != "2"` | `ios_ssh_v2_fix.j2` |
| CIS-IOS-1.1.2 | CRITICAL | `telnet.enabled != "DISABLED"` | `ios_disable_telnet.j2` |
| CIS-IOS-1.1.3 | HIGH | SSH on, no `ssh.management_acl` | `ios_ssh_mgmt_acl_fix.j2` |
| CIS-IOS-1.2.1 | HIGH | SNMP on with v1/v2c | `ios_snmp_v3_fix.j2` |
| CIS-IOS-1.2.2 | CRITICAL | community string `public`/`private` | `ios_snmp_community_fix.j2` |
| CIS-IOS-1.3.1 | CRITICAL | IKE policy uses DES/3DES | `ios_ike_encryption_fix.j2` |
| CIS-IOS-1.4.1 | MEDIUM | NTP on, auth off | `ios_ntp_auth_fix.j2` |
| CIS-IOS-1.5.1 | HIGH | `aaa.password_encryption != "ENABLED"` | `ios_password_encryption_fix.j2` |
| CIS-IOS-1.6.1 | LOW | no login banner | `ios_login_banner_fix.j2` |
| CIS-IOS-1.7.1 | MEDIUM | `services.http_server_enabled == "ENABLED"` | `ios_disable_http_server.j2` |
| CIS-IOS-1.8.1 | MEDIUM | syslog off, or on with no host | `ios_syslog_fix.j2` |

Control IDs follow the blueprint's `CIS-IOS-x.y.z` scheme. They are **not**
verbatim CIS Benchmark numbering — if we need real numbering for judging, that
is a mapping exercise on top of these rules, not a rewrite of them.

`cis/cisco_ios_level1_test.rego` — 20 `opa test` cases. Each control gets a
compliant baseline that must produce nothing and a violating one that must fire.

### 1.2 The service — `services/compliance/app/`

| File | Role |
|---|---|
| `opa_client.py` | POSTs the baseline to OPA, walks the result for `deny` sets |
| `risk_scorer.py` | Severity → risk weight; the per-run summary |
| `evaluator.py` | The one pass: evaluate → score → persist |
| `worker.py` | Celery consumer for `compliance.evaluate_baseline` |
| `main.py` | `GET /audit-runs/{id}` (Gateway proxies here), `POST /evaluate` |
| `db.py` | `compliance_findings` table + `audit_runs.status` |

Two design decisions worth knowing about:

**Adding a vendor is a file, not a code change.** `opa_client.evaluate()`
evaluates the whole `data.compliance.<framework>` subtree in one call and
collects every `deny` set it finds. Drop `policies/cis/juniper_junos.rego` in
and it is live on the next OPA restart.

The price is that **every package sees every device**, so every rule must guard
on `input.device.detected_vendor` through its `applies` rule. Without the guard
a Juniper config gets judged against Cisco rules.
`test_non_cisco_device_is_ignored` exists to catch a forgotten guard.

**A dead policy engine is never reported as a clean device.** OPA returns `{}`
for a path with no bundle loaded, which is indistinguishable from "no findings"
if you are not careful. `opa_client` raises `OPAEvaluationError`, and
`POST /evaluate` surfaces it as **502**, not 200-with-empty-findings. This is
the single most important behaviour in the lane: a compliance engine that
silently passes a broken device is worse than one that is down.

### 1.3 Verification

- `opa test policies/` → **20/20**
- `opa check --strict policies/` → clean
- `pytest` → **57 passed** with the `opa` binary on PATH; **51 passed, 6
  skipped** without it, so a teammate who has not installed OPA still gets a
  green run.
- Live run against a real OPA server + real uvicorn: insecure Cisco config
  fires all 11 controls with evidence (`compliance_score: 0`); hardened config
  gives 0 findings (score 100); Juniper config gives 0 findings; missing bundle
  gives 502.
- The drift guards in `tests/test_contracts.py` were mutation-tested — each
  guarded thing was deliberately broken and the matching test confirmed to fail.

---

## 2. Files changed outside this lane

Per `CONTRIBUTING.md` these are cross-lane changes and need a heads-up, which
is what this section is.

| File | Change | Why |
|---|---|---|
| `infra/postgres/init.sql` | Added `compliance_findings` table + index | This lane has to persist findings somewhere; there is no per-service migration framework |
| `docker-compose.yml` | OPA `command`, MinIO volume/console/healthcheck, new `compliance-worker` service | The stack could not start OPA at all — see §3.3 |
| `contracts/security_baseline.schema.json` | Was **empty**, filled from blueprint §4.1 | It is this lane's input contract; see §4.1 |
| `contracts/compliance_finding.schema.json` | Was **empty**, filled | Output of this lane — ours to own |
| `contracts/README.md` | One line documenting the Celery task name/payload | So Parsing does not have to guess it |

`compliance_findings` is **current state, not an append-only log**: re-running
an audit deletes that run's rows and reinserts. Otherwise a policy update
leaves findings for controls that no longer fail. The immutable trail the
blueprint's NFR asks for lives in `audit_runs`.

---

## 3. Bugs found

### 3.1 The blueprint's own Rego does not compile — §7

`deny[finding] { ... }` is Rego v0. OPA 1.0 (Dec 2024) and later reject it
without `--v0-compatible`. Every rule had to be rewritten as
`deny contains finding if { ... }`.

**Anyone copying Rego out of the blueprint will hit this.** The working syntax
is in `policies/cis/cisco_ios_level1.rego`.

### 3.2 The blueprint's Rego silently passes devices — §7

This one is worse than a syntax error because it fails quietly.

```rego
deny[finding] {
    input.ssh.version != "2"     # config with no SSH block at all
    ...
}
```

If the parser produced no `ssh` object, `input.ssh.version` is **undefined**.
An undefined expression makes the rule body fail, the rule does not fire, and
the device **passes** "SSH version 2 must be enabled" by having no SSH config
whatsoever. Same for every other control in the sample.

Fixed by reading every optional field through `object.get(input, [...], default)`.
Which way each default points is decided per control by the device's out-of-box
state, not by a blanket rule:

- Where the insecure state is the IOS default (telnet on, no password
  encryption, no banner, no syslog) — absent or `UNKNOWN` **fails**. The parser
  could not prove the operator hardened it, and an unproven control is not a
  passed control.
- Where the insecure state must be turned on deliberately (`ip http server`) —
  only an explicit `ENABLED` fails. Failing those on `UNKNOWN` would bury real
  findings under noise from thin configs.

`test_empty_config_trips_the_fail_closed_controls` pins that split so it cannot
drift.

### 3.3 The OPA container never started

```yaml
opa:
  image: openpolicyagent/opa      # no command
```

`openpolicyagent/opa` with no arguments prints its help text and exits. The
container was in a crash loop from day one, so nothing could ever have queried
it. Fixed to `run --server --addr=0.0.0.0:8181 /policies`, image pinned to
`1.20.2` (the version the bundle was verified against), volume made `:ro`.

### 3.4 MinIO lost every uploaded config on restart

```yaml
minio:
  command: server /data           # no volume
```

`/data` was container-local, so `docker compose down` discarded every raw
config. Worse than plain data loss: `pgdata` **is** persisted, so `audit_runs`
rows survive pointing at `storage_path` values that no longer exist, and
Ingestion's SHA-256 dedup (which checks `stat_object` in MinIO) silently starts
accepting files it already recorded. Postgres and MinIO drift apart on every
restart.

Fixed: `miniodata` volume, `--console-address ":9001"`, healthcheck. No bucket
bootstrap needed — `services/ingestion/app/uploader.py::get_minio_client`
already creates `raw-configs` on first use.

### 3.5 `sqlalchemy` without the `[asyncio]` extra — affects two other lanes

Plain `sqlalchemy` only declares its `greenlet` dependency for `x86_64` and
`aarch64`. On Apple Silicon (`arm64`) greenlet is not installed, and **every
async DB call raises** `ValueError: the greenlet library is required to use
this function`.

Linux and Docker happen to get greenlet anyway, which is exactly what hides it:
the stack works in Compose and fails on a Mac dev machine.

Found because it broke this lane's `test_db.py`. Fixed here with
`sqlalchemy[asyncio]==2.0.35`. **Still present in:**

- `services/ingestion/requirements.txt`
- `gateway/requirements.txt`

### 3.6 The contract mismatch the drift tests caught

`contracts/compliance_finding.schema.json` listed `risk_score` as required, but
Rego does not emit it — `risk_scorer.py` adds it after evaluation. The contract
describes what *leaves* the lane, which is always the scored form, so validation
now happens post-scoring and
`test_rego_supplies_every_contract_field_except_risk_score` pins which side owns
that field. Worth recording because it is the class of thing that only surfaces
on integration day.

---

## 4. Corrections required — by lane

### 4.1 Parsing / Schema lane

**`services/schema/` does not exist.** `BUILD_GUIDE.md` and `CONTRIBUTING.md`
both describe it as the single home of `SecurityBaseline`, installed by other
lanes with `pip install -e ../schema`. There is no such directory in the repo.
`BUILD_GUIDE.md`'s own "order of operations" says it must exist before Parsing
or Compliance can be meaningfully tested.

**`contracts/security_baseline.schema.json` was a 0-byte file.** It is this
lane's input contract, so rather than integrate blind I filled it from blueprint
§4.1 — per `CONTRIBUTING.md`, "if it's not there yet, propose it there first".
**Please review it**, and keep it in step with `services/schema/` when that
lands. Anything I got wrong there, this lane's Rego is currently built on.

**Send this Celery task when a baseline passes Pydantic validation:**

```
task: compliance.evaluate_baseline     (broker: redis://redis:6379/0)
payload: {
  "audit_run_id": "<the job_id Ingestion generated>",
  "framework":    "CIS",     # optional, defaults to DEFAULT_FRAMEWORK
  "baseline":     { ... }    # contracts/security_baseline.schema.json
}
```

Celery queues it, so Parsing never blocks on this service being up. A job
missing `audit_run_id` or `baseline` raises rather than defaulting — a job with
no baseline would otherwise report a device with zero findings as fully
compliant.

One field to get right: `device.detected_vendor` must be the **lowercase**
vendor key (`"cisco"`, `"juniper"`, …). Every policy package dispatches on it,
and `"Cisco"` would match nothing and silently produce zero findings.

### 4.2 Remediation lane

Findings carry a `remediation` field naming the Jinja2 template to render. The
eleven templates the current bundle can ask for are listed in §1.1 — all
`ios_*.j2`. The blueprint gives you a worked example of the first one
(`ios_ssh_v2_fix.j2`) in §8.

`contracts/compliance_finding.schema.json` is the exact shape you receive.
`tests/test_contracts.py::test_every_finding_names_a_remediation_template`
guarantees no finding ever reaches you without one.

### 4.3 Reporting + Frontend lanes

`GET /api/audit-runs/{id}` (Gateway → this service) returns the AuditRun columns
plus:

```json
{
  "findings": [ /* contracts/compliance_finding.schema.json */ ],
  "summary": {
    "total_findings": 11,
    "by_severity": {"CRITICAL": 3, "HIGH": 4, "MEDIUM": 3, "LOW": 1},
    "risk_score": 235,
    "compliance_score": 0
  }
}
```

`compliance_score` is `100 - risk_score`, floored at 0. Only **failed** controls
are emitted — a control absent from the list passed. `summary` is computed on
read, so it can never drift from the stored findings.

### 4.4 Infra lane

Four things, roughly in order of how badly they bite:

1. **Nothing is reachable from a browser.** `audit-net` is `internal: true` and
   no service publishes a `ports:` mapping, so the frontend on :3000 and the
   gateway on :8000 cannot be opened from the host. Blueprint §9 has nginx as
   the TLS terminator and ingress, and root `.env.example` defines
   `NGINX_PORT=443`, but **there is no nginx service in `docker-compose.yml`**
   and `infra/nginx/` holds only a `.gitkeep`. This is a demo-day blocker, not
   a nice-to-have.
2. **`CHROMADB_PORT=8500`** in root `.env.example`, but the `chromadb/chroma`
   image listens on 8000 by default and the compose service passes no override.
   Worth verifying before the Learning lane wires against it.
3. **`version: "3.9"`** at the top of `docker-compose.yml` is obsolete under
   Compose v2 and emits a warning on every command. Safe to delete.
4. **Image tags are unpinned** (`minio/minio`, `chromadb/chroma`,
   `ollama/ollama`, `batfish/allinone`). For an air-gapped deliverable these
   should be pinned to digests or explicit versions. I pinned `opa` to `1.20.2`
   because the Rego syntax is version-sensitive; the rest are the infra lane's
   call.

### 4.5 Whole team — `audit_runs.status` has no agreed vocabulary

Ingestion writes `INGESTED`. This lane now writes `EVALUATED` after findings are
persisted. Nothing defines the full set or the transitions. Suggested, but
**this needs an actual decision, not my guess**:

```
INGESTED → PARSED → EVALUATED → REMEDIATED → COMPLETE
```

The Frontend will render whatever we pick, so it should be settled before the
dashboard's status column is built.

---

## 5. Known gaps in this lane

Being explicit so nobody assumes these are done:

- **Only the CIS Cisco IOS bundle exists.** `NIST` and `STIG` are accepted as
  framework names but have no policy files. Asking for one raises a 502 rather
  than returning "compliant" — deliberate, but it does mean a NIST audit does
  not work yet.
- **Only Cisco.** A Juniper/PAN-OS/Arista config evaluates cleanly with zero
  findings because no package claims it. §1.2 describes how to add one; the
  work is writing the rules, not wiring them.
- **`POST /evaluate` is unauthenticated.** It sits on the internal network
  behind the Gateway, same trust model as the Ingestion hop.
- **Control IDs are the blueprint's scheme, not verbatim CIS numbering** (§1.1).
- **`RISK_SCORE_CONFIG=/app/risk_weights.yaml` was removed** from
  `.env.example`. Four integers that change roughly never did not earn a config
  file, a parser, and a missing-file failure mode. The weights are a module
  constant in `risk_scorer.py`. If someone wants them runtime-tunable, say so
  and it goes back.

---

## 6. Running this lane

```bash
cd services/compliance
cp .env.example .env

opa test policies/ -v          # the rules — no Docker, no Python needed
opa check --strict policies/

pip install -r requirements-dev.txt
pytest                          # 57 with opa on PATH, 51 + 6 skipped without

# the service against a live OPA
opa run --server --addr localhost:8181 policies/ &
OPA_URL=http://localhost:8181/v1/data uvicorn app.main:app --reload --port 8002
```

Full stack: `docker compose up opa compliance compliance-worker`.

`services/compliance/README.md` has a copy-pasteable `curl` that evaluates a
config end-to-end without Ingestion, Parsing, or Postgres — omitting
`audit_run_id` makes it a dry run that skips persistence.
