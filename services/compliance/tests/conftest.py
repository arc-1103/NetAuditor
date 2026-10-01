import pytest

from app import db


@pytest.fixture(autouse=True)
def no_waivers_unless_a_test_sets_them(monkeypatch):
    """Audit reads consult waiver events from the ledger; unit tests have no database."""
    async def none():
        return []
    monkeypatch.setattr(db, "get_waiver_events", none)

import os as _os

_os.environ.setdefault("SERVICE_JWT_SECRET", "test-service-secret")  # signed calls to Learning
