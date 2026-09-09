import pytest

from app.rag_remediation import RemediationSynthesisError, synthesize_remediation
from app.slm_client import SLMError


class FakeManualProvider:
    def __init__(self, excerpts=None):
        self.excerpts = excerpts or []
        self.calls = []

    async def lookup(self, vendor, os_name, control_id):
        self.calls.append((vendor, os_name, control_id))
        return self.excerpts


class FakeSLM:
    def __init__(self, response=None, fail=False):
        self.response = response or {"remediation_cli": "fix it", "rollback_cli": "unfix it"}
        self.fail = fail
        self.prompts = []

    async def synthesize(self, prompt):
        self.prompts.append(prompt)
        if self.fail:
            raise SLMError("ollama unavailable")
        return self.response


async def test_synthesize_remediation_is_grounded_when_manual_context_exists():
    manual_provider = FakeManualProvider(excerpts=["disable telnet via config t / no telnet"])
    slm = FakeSLM()

    result = await synthesize_remediation(
        vendor="cisco", os_name="IOS-XE", control_id="CIS-IOS-1.1.1",
        title="Telnet disabled", evidence="telnet.enabled = ENABLED",
        manual_provider=manual_provider, slm_client=slm,
    )

    assert result.grounded is True
    assert result.remediation_cli == "fix it"
    assert result.rollback_cli == "unfix it"
    assert manual_provider.calls == [("cisco", "IOS-XE", "CIS-IOS-1.1.1")]
    assert "disable telnet via config t / no telnet" in slm.prompts[0]


async def test_synthesize_remediation_is_ungrounded_when_no_manual_context():
    result = await synthesize_remediation(
        vendor="cisco", os_name="IOS-XE", control_id="CIS-IOS-1.1.1",
        title="Telnet disabled", evidence="telnet.enabled = ENABLED",
        manual_provider=FakeManualProvider(), slm_client=FakeSLM(),
    )

    assert result.grounded is False


async def test_synthesize_remediation_surfaces_a_missing_rollback():
    slm = FakeSLM(response={"remediation_cli": "fix it", "rollback_cli": ""})

    result = await synthesize_remediation(
        vendor="cisco", os_name="IOS-XE", control_id="CIS-IOS-1.1.1",
        title="t", evidence="e", manual_provider=FakeManualProvider(), slm_client=slm,
    )

    assert result.rollback_cli == ""


async def test_synthesize_remediation_raises_when_slm_produces_no_cli():
    slm = FakeSLM(response={"remediation_cli": "", "rollback_cli": "x"})

    with pytest.raises(RemediationSynthesisError):
        await synthesize_remediation(
            vendor="cisco", os_name="IOS-XE", control_id="CIS-IOS-1.1.1",
            title="t", evidence="e", manual_provider=FakeManualProvider(), slm_client=slm,
        )


async def test_synthesize_remediation_wraps_slm_errors():
    with pytest.raises(RemediationSynthesisError):
        await synthesize_remediation(
            vendor="cisco", os_name="IOS-XE", control_id="CIS-IOS-1.1.1",
            title="t", evidence="e", manual_provider=FakeManualProvider(), slm_client=FakeSLM(fail=True),
        )
