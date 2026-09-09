import pytest

from app.slm_client import OllamaSLMClient, SLMError


async def test_mock_mode_returns_deterministic_placeholder():
    client = OllamaSLMClient("http://unused", "model", mock=True)

    result = await client.synthesize("any prompt")

    assert result["remediation_cli"]
    assert result["rollback_cli"]


def _fake_ollama_client(monkeypatch, response_body):
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


async def test_synthesize_parses_the_ollama_response(monkeypatch):
    _fake_ollama_client(
        monkeypatch,
        {"response": '{"remediation_cli": "ip ssh version 2", "rollback_cli": "no ip ssh version 2"}'},
    )
    client = OllamaSLMClient("http://ollama", "model")

    result = await client.synthesize("prompt")

    assert result == {"remediation_cli": "ip ssh version 2", "rollback_cli": "no ip ssh version 2"}


async def test_synthesize_rejects_non_json_response(monkeypatch):
    _fake_ollama_client(monkeypatch, {"response": "not json"})
    client = OllamaSLMClient("http://ollama", "model")

    with pytest.raises(SLMError):
        await client.synthesize("prompt")


async def test_synthesize_rejects_a_response_missing_the_response_field(monkeypatch):
    _fake_ollama_client(monkeypatch, {})
    client = OllamaSLMClient("http://ollama", "model")

    with pytest.raises(SLMError):
        await client.synthesize("prompt")
