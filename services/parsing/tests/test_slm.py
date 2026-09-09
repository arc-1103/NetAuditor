import pytest

from app.models import DeviceContext
from app.slm_client import OllamaSLMClient, SLMError


@pytest.mark.asyncio
async def test_mock_slm_uses_job_vendor_context_and_does_not_invent_cisco():
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("cisco", "IOS-XE", "17.9.3", None, None, 0.96)
    result = await client.generate(
        "prompt",
        "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0",
        {},
        device_context=context,
    )
    assert result.value["device"]["detected_vendor"] == "cisco"
    assert result.value["device"]["detected_os"] == "IOS-XE"
    assert "ssh" not in result.value


@pytest.mark.asyncio
async def test_mock_slm_extracts_fields_regardless_of_recognized_vendor():
    """Extraction patterns are no longer gated on context.vendor — an
    unrecognized vendor that still matches known syntax should get credit
    for it, since a real SLM doesn't need the vendor's name to read
    "set system host-name" or "ip ssh version 2"."""
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("unknown", None, None, None, None, 0.0)
    result = await client.generate(
        "prompt",
        "set system host-name edge01\nip ssh version 2\nbanner login\n",
        {},
        device_context=context,
    )

    assert result.value["device"]["raw_hostname"] == "edge01"
    assert result.value["ssh"] == {"enabled": True, "version": "2"}
    assert result.value["banners"] == {"login_banner_present": True}
    assert result.value["device"]["parsing_confidence"] > 0.5
    assert result.mean_logprob == result.value["device"]["parsing_confidence"] - 1.0


@pytest.mark.asyncio
async def test_mock_slm_confidence_reflects_fields_found_not_vendor_name():
    client = OllamaSLMClient("http://unused", "model", mock=True)
    known_vendor_empty_chunk = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate(
        "prompt",
        "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0",
        {},
        device_context=known_vendor_empty_chunk,
    )

    assert result.value["device"]["parsing_confidence"] == 0.20
    assert result.mean_logprob == pytest.approx(-0.80)


@pytest.mark.asyncio
async def test_invalid_ollama_response(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "not json"}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("app.slm_client.httpx.AsyncClient", FakeClient)
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    with pytest.raises(SLMError):
        await client.generate("prompt", "config", {}, device_context=context)


def _fake_ollama_client(monkeypatch, response_body: dict):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return response_body

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("app.slm_client.httpx.AsyncClient", FakeClient)


@pytest.mark.asyncio
async def test_generate_extracts_mean_logprob_when_backend_reports_it(monkeypatch):
    _fake_ollama_client(
        monkeypatch,
        {
            "response": '{"schema_version": "1.0.0", "device": {"parsing_confidence": 0.9}}',
            "logprobs": [{"logprob": -0.1}, {"logprob": -0.3}, -0.2],
        },
    )
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate("prompt", "config", {}, device_context=context)
    assert result.mean_logprob == pytest.approx(-0.2)


@pytest.mark.asyncio
async def test_generate_mean_logprob_is_none_when_backend_omits_it(monkeypatch):
    """An Ollama version that doesn't report logprobs must not be treated as
    low confidence — no signal is not the same as a bad signal."""
    _fake_ollama_client(
        monkeypatch,
        {"response": '{"schema_version": "1.0.0", "device": {"parsing_confidence": 0.9}}'},
    )
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate("prompt", "config", {}, device_context=context)
    assert result.mean_logprob is None
