import pytest

from app.rag import EmptyRAGContextProvider, LearningRAGContextProvider


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


def _search_results(documents, distances, metadatas=None):
    return {
        "results": {
            "documents": [documents],
            "distances": [distances],
            "metadatas": [metadatas or [{}] * len(documents)],
        }
    }


@pytest.mark.asyncio
async def test_empty_provider_always_returns_empty_string():
    assert await EmptyRAGContextProvider().retrieve("cisco", "IOS-XE", "anything") == ""


@pytest.mark.asyncio
async def test_correct_band_is_trusted_without_a_pattern_check(monkeypatch):
    monkeypatch.setattr(
        "app.rag.httpx.AsyncClient",
        _fake_client(_search_results(["doc-close"], [0.1], [{"cli_pattern": "unrelated text"}])),
    )
    provider = LearningRAGContextProvider("http://learning:8003")

    context = await provider.retrieve("cisco", "IOS-XE", "ip ssh version 2")

    assert context == "doc-close"


@pytest.mark.asyncio
async def test_ambiguous_band_is_trusted_when_pattern_is_confirmed_in_chunk(monkeypatch):
    monkeypatch.setattr(
        "app.rag.httpx.AsyncClient",
        _fake_client(_search_results(
            ["doc-ambiguous"], [0.6], [{"cli_pattern": "ip ssh version 2"}]
        )),
    )
    provider = LearningRAGContextProvider("http://learning:8003")

    context = await provider.retrieve("cisco", "IOS-XE", "ip ssh version 2\nhostname EDGE-RTR")

    assert context == "doc-ambiguous"


@pytest.mark.asyncio
async def test_ambiguous_band_is_dropped_when_pattern_is_not_confirmed(monkeypatch):
    monkeypatch.setattr(
        "app.rag.httpx.AsyncClient",
        _fake_client(_search_results(
            ["doc-ambiguous"], [0.6], [{"cli_pattern": "crypto isakmp policy 10"}]
        )),
    )
    provider = LearningRAGContextProvider("http://learning:8003")

    context = await provider.retrieve("cisco", "IOS-XE", "ip ssh version 2\nhostname EDGE-RTR")

    assert context == ""


@pytest.mark.asyncio
async def test_incorrect_band_is_dropped_regardless_of_pattern_match(monkeypatch):
    monkeypatch.setattr(
        "app.rag.httpx.AsyncClient",
        _fake_client(_search_results(
            ["doc-far"], [0.95], [{"cli_pattern": "ip ssh version 2"}]
        )),
    )
    provider = LearningRAGContextProvider("http://learning:8003")

    context = await provider.retrieve("cisco", "IOS-XE", "ip ssh version 2")

    assert context == ""


@pytest.mark.asyncio
async def test_provider_caps_trusted_matches_at_top_k(monkeypatch):
    monkeypatch.setattr(
        "app.rag.httpx.AsyncClient",
        _fake_client(_search_results(
            ["a", "b", "c"], [0.1, 0.2, 0.3], [{}, {}, {}]
        )),
    )
    provider = LearningRAGContextProvider("http://learning:8003", top_k=2)

    context = await provider.retrieve("cisco", "IOS-XE", "config text")

    assert context == "a\n\nb"


@pytest.mark.asyncio
async def test_provider_returns_empty_string_on_transport_error(monkeypatch):
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

    monkeypatch.setattr("app.rag.httpx.AsyncClient", FailingClient)
    provider = LearningRAGContextProvider("http://learning:8003")

    assert await provider.retrieve("cisco", "IOS-XE", "config text") == ""
