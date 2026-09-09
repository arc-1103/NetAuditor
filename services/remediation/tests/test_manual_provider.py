import httpx

from app.manual_provider import EmptyRemediationManualProvider, LearningRemediationManualProvider


async def test_empty_provider_returns_no_context():
    provider = EmptyRemediationManualProvider()

    assert await provider.lookup("cisco", "IOS-XE", "CIS-IOS-1.1.1") == []


async def test_learning_provider_returns_excerpts_on_success(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"found": True, "manual_excerpts": ["do the thing"]}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json):
            self.last_call = (url, json)
            return FakeResponse()

    fake_client = FakeClient()
    monkeypatch.setattr("app.manual_provider.httpx.AsyncClient", lambda *a, **k: fake_client)

    provider = LearningRemediationManualProvider("http://learning:8003")
    result = await provider.lookup("fortinet", "FortiOS", "CIS-FORTI-1.1.1")

    assert result == ["do the thing"]
    assert fake_client.last_call == (
        "http://learning:8003/learning/remediation-manuals/search",
        {"vendor": "fortinet", "os": "FortiOS", "control_id": "CIS-FORTI-1.1.1"},
    )


async def test_learning_provider_degrades_to_empty_on_outage(monkeypatch):
    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise httpx.ConnectError("learning unavailable")

    monkeypatch.setattr("app.manual_provider.httpx.AsyncClient", FailingClient)

    provider = LearningRemediationManualProvider("http://learning:8003")

    assert await provider.lookup("cisco", "IOS-XE", "CIS-IOS-1.1.1") == []
