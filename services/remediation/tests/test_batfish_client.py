import pytest

from app import batfish_client


def test_static_safety_checks_detect_lockout_commands():
    flags = batfish_client.static_safety_checks("configure terminal\nline vty 0 4\n transport input none\n")
    assert any("remote VTY" in flag for flag in flags)


@pytest.mark.asyncio
async def test_mock_preflight_is_safe_for_reviewed_template(monkeypatch):
    monkeypatch.setattr(batfish_client, "USE_MOCK", True)
    result = await batfish_client.preflight("configure terminal\nip ssh version 2\nend")
    assert result.status == "SAFE"


@pytest.mark.asyncio
async def test_static_risk_never_becomes_safe(monkeypatch):
    monkeypatch.setattr(batfish_client, "USE_MOCK", True)
    result = await batfish_client.preflight("configure terminal\nshutdown\nend")
    assert result.status == "RISK_FLAGS"


@pytest.mark.asyncio
async def test_placeholder_secrets_require_review(monkeypatch):
    monkeypatch.setattr(batfish_client, "USE_MOCK", True)
    result = await batfish_client.preflight("snmp-server user x auth sha <REPLACE_AUTH_SECRET>")
    assert result.status == "RISK_FLAGS"
