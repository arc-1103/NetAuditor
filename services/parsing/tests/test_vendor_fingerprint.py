import pytest

from app.vendor_fingerprint import (
    EmptyVendorFingerprintProvider,
    LearningVendorFingerprintProvider,
    VendorGuess,
)


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


def _fake_client(body):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse(body)

    return FakeClient


@pytest.mark.asyncio
async def test_empty_provider_always_returns_none():
    assert await EmptyVendorFingerprintProvider().identify("anything") is None


@pytest.mark.asyncio
async def test_learning_provider_returns_a_guess_on_a_match(monkeypatch):
    monkeypatch.setattr(
        "app.vendor_fingerprint.httpx.AsyncClient",
        _fake_client({"vendor": "fortinet", "os": "FortiOS", "confidence": 0.82}),
    )
    provider = LearningVendorFingerprintProvider("http://learning:8003")

    guess = await provider.identify("config system global")

    assert guess == VendorGuess(vendor="fortinet", os="FortiOS", confidence=0.82)


@pytest.mark.asyncio
async def test_learning_provider_returns_none_when_no_vendor_in_response(monkeypatch):
    monkeypatch.setattr(
        "app.vendor_fingerprint.httpx.AsyncClient",
        _fake_client({"vendor": None}),
    )
    provider = LearningVendorFingerprintProvider("http://learning:8003")

    assert await provider.identify("unrelated text") is None


@pytest.mark.asyncio
async def test_learning_provider_returns_none_on_transport_error(monkeypatch):
    import httpx

    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("app.vendor_fingerprint.httpx.AsyncClient", FailingClient)
    provider = LearningVendorFingerprintProvider("http://learning:8003")

    assert await provider.identify("anything") is None
