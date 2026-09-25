"""
Ticketing/SIEM webhook dispatch — docs/Additional-Features.md §8.

A generic outbound POST to WEBHOOK_URL for each event the doc names
(ServiceNow, Jira, Slack and a plain webhook receiver all accept a POST
with a JSON body at their own incoming-webhook URL, so this doesn't need a
connector per target). Best-effort: a webhook target being down or slow
must never fail or block the compliance operation that triggered it, so
failures are logged and swallowed here, never raised, and a short timeout
keeps a hung endpoint from blocking the caller.
"""

import logging
import os

import httpx

logger = logging.getLogger("netaudit.compliance.webhooks")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "5"))


async def dispatch(event_type: str, payload: dict) -> None:
    if not WEBHOOK_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
            await client.post(WEBHOOK_URL, json={"event_type": event_type, **payload})
    except httpx.HTTPError as exc:
        logger.warning("Webhook dispatch failed for %s: %s", event_type, exc)
