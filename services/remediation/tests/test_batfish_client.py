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


@pytest.mark.asyncio
async def test_reachability_widening_forces_risk_flags(monkeypatch):
    """docs/Additional-Features.md §4: removing an access-class is a widening
    change static_safety_checks alone doesn't catch — the reachability
    fallback must still gate approval on it."""
    monkeypatch.setattr(batfish_client, "USE_MOCK", True)
    result = await batfish_client.preflight("line vty 0 15\n no access-class NETAUDIT-MGMT in\nend")
    assert result.status == "RISK_FLAGS"
    assert result.engine == "static-safety+reachability-fallback"
    assert any("Reachability fallback" in flag for flag in result.risk_flags)


@pytest.mark.asyncio
async def test_reachability_narrowing_alone_stays_safe(monkeypatch):
    """Applying a new access-class narrows reachability — routine for a
    compliance fix, so it must not block a template that's otherwise clean
    (ios_ssh_mgmt_acl_fix.j2 itself is still caught separately, by its
    unresolved '! REVIEW:' comment via static_safety_checks)."""
    monkeypatch.setattr(batfish_client, "USE_MOCK", True)
    result = await batfish_client.preflight("line vty 0 15\n access-class NETAUDIT-MGMT in\n transport input ssh\nend")
    assert result.status == "SAFE"
