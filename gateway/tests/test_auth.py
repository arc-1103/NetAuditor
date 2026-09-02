"""
Unit tests for app.auth: JWT issuance/validation and password
authentication. `authenticate_user` is exercised against a mocked
AsyncSession — no live Postgres required.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app import auth


def make_session_returning(row: dict | None) -> AsyncMock:
    session = AsyncMock()
    result = MagicMock()
    result.mappings.return_value.first.return_value = row
    session.execute.return_value = result
    return session


async def test_issue_token_round_trips_through_get_current_user():
    user = {"id": "u-1", "email": "admin@netaudit.local", "role": "admin"}

    token = auth.issue_token(user)
    payload = await auth.get_current_user(f"Bearer {token}")

    assert payload["sub"] == "u-1"
    assert payload["email"] == "admin@netaudit.local"
    assert payload["role"] == "admin"
    assert "exp" in payload


async def test_get_current_user_rejects_missing_header():
    with pytest.raises(HTTPException) as exc:
        await auth.get_current_user(None)

    assert exc.value.status_code == 401


async def test_get_current_user_rejects_non_bearer_header():
    with pytest.raises(HTTPException) as exc:
        await auth.get_current_user("Basic dXNlcjpwYXNz")

    assert exc.value.status_code == 401


async def test_get_current_user_rejects_malformed_token():
    with pytest.raises(HTTPException) as exc:
        await auth.get_current_user("Bearer not-a-real-jwt")

    assert exc.value.status_code == 401


async def test_authenticate_user_success_returns_public_fields_only():
    row = {
        "id": "u-1",
        "email": "admin@netaudit.local",
        "password_hash": auth.pwd_context.hash("changeme"),
        "role": "admin",
    }
    session = make_session_returning(row)

    user = await auth.authenticate_user("admin@netaudit.local", "changeme", session)

    assert user == {"id": "u-1", "email": "admin@netaudit.local", "role": "admin"}
    assert "password_hash" not in user


async def test_authenticate_user_rejects_wrong_password():
    row = {
        "id": "u-1",
        "email": "admin@netaudit.local",
        "password_hash": auth.pwd_context.hash("changeme"),
        "role": "admin",
    }
    session = make_session_returning(row)

    with pytest.raises(HTTPException) as exc:
        await auth.authenticate_user("admin@netaudit.local", "wrong-password", session)

    assert exc.value.status_code == 401


async def test_authenticate_user_rejects_unknown_email():
    session = make_session_returning(None)

    with pytest.raises(HTTPException) as exc:
        await auth.authenticate_user("nobody@netaudit.local", "whatever", session)

    assert exc.value.status_code == 401
