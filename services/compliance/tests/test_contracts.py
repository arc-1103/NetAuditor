"""
Drift tests for the things the other lanes actually depend on.

The rest of the suite tests this lane's code in isolation. These test the
seams — the places where a change here silently breaks Remediation,
Reporting, the Frontend, or `docker compose up`, and where nothing else in
the repo would notice until integration day:

  1. Do the findings the Rego bundle emits conform to
     contracts/compliance_finding.schema.json?
  2. Does infra/postgres/init.sql's table match the columns app/db.py writes?
  3. Does docker-compose.yml actually start OPA with the bundle mounted?

The OPA-backed test needs the `opa` binary on PATH and skips without it —
see the README for install. The Rego rules themselves are tested by
`opa test policies/ -v`, not from here.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.db import _FINDING_COLUMNS
from app.opa_client import collect_findings
from app.risk_scorer import score_findings

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = REPO_ROOT / "contracts"
POLICIES = REPO_ROOT / "services" / "compliance" / "policies"
INIT_SQL = REPO_ROOT / "infra" / "postgres" / "init.sql"
COMPOSE = REPO_ROOT / "docker-compose.yml"

# A Cisco device with every control violated at once, so one OPA call yields a
# sample of every finding this bundle can produce.
FULLY_INSECURE = {
    "schema_version": "1.0.0",
    "device": {
        "raw_hostname": "EDGE-RTR-02",
        "detected_vendor": "cisco",
        "detected_os": "IOS",
        "config_sha256": "a" * 64,
        "parsing_confidence": 0.91,
    },
    "aaa": {"password_encryption": "DISABLED"},
    "ssh": {"enabled": True, "version": "1-2", "management_acl": None},
    "telnet": {"enabled": "ENABLED", "vty_lines_with_telnet": ["0 4"]},
    "snmp": {"enabled": True, "version": "v2c", "community_strings": ["public"]},
    "logging": {"syslog_enabled": False, "syslog_hosts": []},
    "ntp": {"enabled": True, "authentication_enabled": False},
    "crypto": {"ike_policies": [{"policy_id": 10, "encryption": "3DES"}]},
    "banners": {"login_banner_present": False},
    "services": {"http_server_enabled": "ENABLED"},
}


def _load_contract(name: str) -> dict:
    return json.loads((CONTRACTS / name).read_text())


# ── 1. Rego output vs. the published finding contract ───────────────
@pytest.fixture(scope="module")
def opa_findings() -> list[dict]:
    """Every finding the real bundle emits for a fully insecure device."""
    opa = shutil.which("opa")
    if opa is None:
        pytest.skip("opa binary not on PATH — see services/compliance/README.md")

    proc = subprocess.run(
        [opa, "eval", "-d", str(POLICIES), "-I", "-f", "json", "data.compliance.cis"],
        input=json.dumps(FULLY_INSECURE),
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    return collect_findings(value)


def test_bundle_emits_a_finding_for_every_control(opa_findings):
    """Guards the fixture itself — a bundle that suddenly emits nothing would
    make every conformance assertion below vacuously pass."""
    assert len(opa_findings) == 11


def test_every_finding_conforms_to_the_published_contract(opa_findings):
    """Remediation, Reporting and the Frontend all read this shape. A rule
    written with a missing field or a typo'd severity breaks them, not us.

    Validated after scoring, because what crosses the lane boundary is the
    scored finding — `risk_score` is the one contract field Rego does not
    emit, and the next test pins that split.
    """
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_contract("compliance_finding.schema.json")

    validator = jsonschema.Draft7Validator(schema)
    errors = [
        f"{f.get('control_id', '?')}: {e.message}"
        for f in score_findings(opa_findings)
        for e in validator.iter_errors(f)
    ]

    assert errors == []


def test_rego_supplies_every_contract_field_except_risk_score(opa_findings):
    """Rego owns the verdict, risk_scorer owns the number. If a .rego file ever
    starts emitting risk_score itself, the two would disagree silently."""
    schema = _load_contract("compliance_finding.schema.json")
    # audit_run_id and created_at are added by db.py on persist.
    from_rego = set(schema["required"]) - {"risk_score"}

    for f in opa_findings:
        assert from_rego <= set(f), f"{f.get('control_id')} is missing {from_rego - set(f)}"
        assert "risk_score" not in f


def test_every_finding_names_a_remediation_template(opa_findings):
    """The Remediation lane keys its Jinja2 templates off this field, so a
    finding without one is a control an operator can't act on."""
    missing = [f["control_id"] for f in opa_findings if not f.get("remediation")]

    assert missing == []
    assert all(f["remediation"].endswith(".j2") for f in opa_findings)


def test_control_ids_are_unique(opa_findings):
    """control_id is half the primary key of compliance_findings — two rules
    sharing one would make the second insert clobber the first."""
    ids = [f["control_id"] for f in opa_findings]

    assert len(ids) == len(set(ids))


def test_severities_are_all_scoreable(opa_findings):
    """A severity outside the weight table still scores (risk_scorer falls
    back), but it would silently mis-rank the dashboard."""
    from app.risk_scorer import SEVERITY_WEIGHTS

    unknown = {f["severity"] for f in opa_findings} - set(SEVERITY_WEIGHTS)

    assert unknown == set()


# ── 2. init.sql vs. what db.py writes ───────────────────────────────
# tests/test_db.py declares its own CREATE TABLE for SQLite, so nothing else
# would catch init.sql and db.py drifting apart.
def _declared_columns(table: str) -> set[str]:
    body = re.search(
        rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\n\);",
        INIT_SQL.read_text(),
        re.DOTALL,
    )
    assert body, f"{table} not found in {INIT_SQL}"

    columns = set()
    for line in body.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith(("--", "PRIMARY KEY", "UNIQUE", "FOREIGN KEY", "CONSTRAINT")):
            continue
        columns.add(line.split()[0])
    return columns


def test_init_sql_has_every_column_db_py_inserts():
    declared = _declared_columns("compliance_findings")

    assert set(_FINDING_COLUMNS) | {"audit_run_id"} <= declared


def test_findings_table_is_keyed_by_run_and_control():
    """save_findings relies on this to replace a run's findings cleanly."""
    sql = INIT_SQL.read_text()

    assert "PRIMARY KEY (audit_run_id, control_id)" in sql
    assert "REFERENCES audit_runs(id) ON DELETE CASCADE" in sql


def test_contract_and_table_agree_on_finding_fields():
    """The schema other lanes read must not promise a column we never store."""
    schema = _load_contract("compliance_finding.schema.json")
    declared = _declared_columns("compliance_findings")

    assert set(schema["properties"]) - {"audit_run_id"} <= declared


# ── 3. docker-compose wiring ────────────────────────────────────────
# `openpolicyagent/opa` with no command prints help and exits, which is how
# the stack shipped before. These pin the fix.
@pytest.fixture(scope="module")
def compose() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(COMPOSE.read_text())


def test_opa_runs_as_a_server(compose):
    command = " ".join(compose["services"]["opa"]["command"])

    assert "run" in command and "--server" in command


def test_opa_mounts_the_policy_directory_this_lane_owns(compose):
    opa = compose["services"]["opa"]
    host_path, container_path = opa["volumes"][0].split(":")[:2]

    assert (REPO_ROOT / host_path).resolve() == POLICIES.resolve()
    # .env.example's POLICY_BUNDLE_PATH documents this path for humans.
    assert container_path == "/policies"


def test_opa_serves_on_the_port_the_env_example_points_at(compose):
    command = " ".join(compose["services"]["opa"]["command"])
    env_example = (POLICIES.parent / ".env.example").read_text()

    assert "8181" in command
    assert "opa:8181" in env_example


def test_a_worker_consumes_the_celery_queue(compose):
    """Without this service the HTTP side is up but parsed baselines pile up
    in Redis unevaluated."""
    worker = compose["services"]["compliance-worker"]

    assert "app.worker" in worker["command"]
    assert "redis" in worker["depends_on"]


def test_minio_persists_its_data(compose):
    """`server /data` with no volume loses every uploaded config on restart,
    while the SHA-256 dedup in ingestion still thinks they were stored."""
    minio = compose["services"]["minio"]

    assert any(v.endswith(":/data") for v in minio["volumes"])
    assert "miniodata" in compose["volumes"]
