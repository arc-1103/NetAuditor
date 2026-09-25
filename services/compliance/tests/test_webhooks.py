"""Unit tests for app.webhooks — docs/Additional-Features.md §8."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app import webhooks


async def test_dispatch_does_nothing_when_no_webhook_url_is_configured(monkeypatch):
    monkeypatch.setattr(webhooks, "WEBHOOK_URL", None)
    with patch("httpx.AsyncClient") as client_cls:
        await webhooks.dispatch("VIOLATION_DETECTED", {"control_id": "CIS-NET-1.1.2"})
    client_cls.assert_not_called()


async def test_dispatch_posts_the_event_type_and_payload(monkeypatch):
    monkeypatch.setattr(webhooks, "WEBHOOK_URL", "https://example.com/hook")
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    with patch("httpx.AsyncClient", return_value=mock_client):
        await webhooks.dispatch("VIOLATION_DETECTED", {"control_id": "CIS-NET-1.1.2"})

    mock_client.post.assert_awaited_once_with(
        "https://example.com/hook", json={"event_type": "VIOLATION_DETECTED", "control_id": "CIS-NET-1.1.2"}
    )


async def test_dispatch_swallows_a_failed_delivery(monkeypatch):
    """A webhook target being down must never raise into the caller."""
    monkeypatch.setattr(webhooks, "WEBHOOK_URL", "https://example.com/hook")
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.side_effect = httpx.ConnectError("refused")
    with patch("httpx.AsyncClient", return_value=mock_client):
        await webhooks.dispatch("VIOLATION_DETECTED", {"control_id": "CIS-NET-1.1.2"})  # must not raise
