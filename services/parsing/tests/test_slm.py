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
    assert result["device"]["detected_vendor"] == "cisco"
    assert result["device"]["detected_os"] == "IOS-XE"
    assert "ssh" not in result


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
