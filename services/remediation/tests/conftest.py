import pytest

from app import db


@pytest.fixture(autouse=True)
def no_real_database_for_the_twin(monkeypatch):
    """The digital twin reads the run's stored baseline; unit tests have no database."""
    async def none(_audit_run_id):
        return None
    monkeypatch.setattr(db, "get_run_baseline", none)

import os as _os

_os.environ.setdefault("SERVICE_JWT_SECRET", "test-service-secret")  # signed calls to Learning
