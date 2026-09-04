"""
Unit tests for app.opa_client. The OPA HTTP call is stubbed — the policy
content itself is covered by `opa test policies/ -v`, not from Python.

The response shapes asserted here were captured from a real
`opa run --server` against services/compliance/policies/.
"""

import httpx
import pytest

from app import opa_client
from app.opa_client import OPAEvaluationError


class _StubResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


class _StubClient:
    """Stands in for httpx.AsyncClient as an async context manager."""

    def __init__(self, response=None, raises=None):
        self.response = response
        self.raises = raises
        self.calls = []

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None):
        self.calls.append((url, json))
        if self.raises:
            raise self.raises
        return self.response


def _install(monkeypatch, stub):
    monkeypatch.setattr(opa_client.httpx, "AsyncClient", stub)
    return stub


# ── policy_path ─────────────────────────────────────────────────────
def test_policy_path_lowercases_framework():
    assert opa_client.policy_path("CIS").endswith("/compliance/cis")
    assert opa_client.policy_path("stig").endswith("/compliance/stig")


def test_policy_path_rejects_unknown_framework():
    with pytest.raises(ValueError, match="Unknown framework"):
        opa_client.policy_path("HIPAA")


# ── collect_findings ────────────────────────────────────────────────
def test_collect_findings_walks_nested_packages():
    # The exact shape OPA returns for POST /v1/data/compliance/cis.
    result = {
        "cisco_ios": {
            "level1": {
                "applies": True,
                "deny": [{"control_id": "CIS-IOS-1.1.2"}, {"control_id": "CIS-IOS-1.1.1"}],
            }
        },
        "juniper_junos": {"level1": {"applies": False}},
    }

    found = opa_client.collect_findings(result)

    assert {f["control_id"] for f in found} == {"CIS-IOS-1.1.1", "CIS-IOS-1.1.2"}


def test_collect_findings_ignores_helper_rules():
    """`applies`, `remote_logging_configured` etc. must not become findings."""
    result = {"cisco_ios": {"level1": {"applies": True, "remote_logging_configured": True, "deny": []}}}

    assert opa_client.collect_findings(result) == []


def test_collect_findings_handles_empty_result():
    assert opa_client.collect_findings({}) == []


# ── evaluate ────────────────────────────────────────────────────────
async def test_evaluate_returns_findings_sorted_by_control_id(monkeypatch, baseline):
    _install(
        monkeypatch,
        _StubClient(
            _StubResponse(
                payload={
                    "result": {
                        "cisco_ios": {
                            "level1": {
                                "deny": [
                                    {"control_id": "CIS-IOS-1.2.1"},
                                    {"control_id": "CIS-IOS-1.1.1"},
                                ]
                            }
                        }
                    }
                }
            )
        ),
    )

    findings = await opa_client.evaluate(baseline, "CIS")

    # Stable ordering keeps two runs over the same config byte-identical.
    assert [f["control_id"] for f in findings] == ["CIS-IOS-1.1.1", "CIS-IOS-1.2.1"]


async def test_evaluate_posts_baseline_as_opa_input(monkeypatch, baseline):
    stub = _install(monkeypatch, _StubClient(_StubResponse(payload={"result": {}})))

    await opa_client.evaluate(baseline, "CIS")

    url, body = stub.calls[0]
    assert url.endswith("/compliance/cis")
    assert body == {"input": baseline}


async def test_evaluate_raises_when_bundle_is_not_loaded(monkeypatch, baseline):
    """OPA answers `{}` for an undefined path — that is a missing bundle, not a
    clean device, and must never be reported as zero findings."""
    _install(monkeypatch, _StubClient(_StubResponse(payload={})))

    with pytest.raises(OPAEvaluationError, match="No policy bundle loaded"):
        await opa_client.evaluate(baseline, "NIST")


async def test_evaluate_raises_on_opa_error_status(monkeypatch, baseline):
    _install(monkeypatch, _StubClient(_StubResponse(status_code=500, text="boom")))

    with pytest.raises(OPAEvaluationError, match="returned 500"):
        await opa_client.evaluate(baseline, "CIS")


async def test_evaluate_raises_when_opa_is_unreachable(monkeypatch, baseline):
    _install(monkeypatch, _StubClient(raises=httpx.ConnectError("connection refused")))

    with pytest.raises(OPAEvaluationError, match="failed"):
        await opa_client.evaluate(baseline, "CIS")


async def test_evaluate_falls_back_to_default_framework(monkeypatch, baseline):
    stub = _install(monkeypatch, _StubClient(_StubResponse(payload={"result": {}})))
    monkeypatch.setattr(opa_client, "DEFAULT_FRAMEWORK", "STIG")

    await opa_client.evaluate(baseline)

    assert stub.calls[0][0].endswith("/compliance/stig")
