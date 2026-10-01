"""
Loads this service's secrets from HashiCorp Vault into os.environ at import
time, before any module reads its settings. Standard library only.

Inert unless VAULT_ADDR is set, so local development and the default stack
are unchanged. Config (all environment variables):

  VAULT_ADDR         e.g. http://vault:8200
  VAULT_TOKEN        a token, OR
  VAULT_ROLE_ID + VAULT_SECRET_ID   AppRole login (preferred for services)
  VAULT_MOUNT        KV v2 mount, default "secret"
  VAULT_REQUIRED     "true" = refuse to start if Vault can't be read

Secrets live at <mount>/netaudit/<service> as plain key/value pairs named
exactly like the environment variables they replace (JWT_SECRET, ...).
Vault values override the environment. Canonical copy: infra/vault/;
the per-service copies are checked for drift by infra/vault/test_vault_loader.py.
"""

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger("netaudit.vault")


def _request(url: str, *, token: str | None = None, body: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def _client_token(addr: str) -> str:
    token = os.getenv("VAULT_TOKEN")
    if token:
        return token
    role_id, secret_id = os.getenv("VAULT_ROLE_ID"), os.getenv("VAULT_SECRET_ID")
    if not (role_id and secret_id):
        raise RuntimeError("VAULT_ADDR is set but neither VAULT_TOKEN nor VAULT_ROLE_ID/VAULT_SECRET_ID is")
    login = _request(f"{addr}/v1/auth/approle/login", body={"role_id": role_id, "secret_id": secret_id})
    return login["auth"]["client_token"]


def load(service: str) -> int:
    """Returns how many variables were set (0 when Vault isn't configured)."""
    addr = os.getenv("VAULT_ADDR", "").rstrip("/")
    if not addr:
        return 0
    try:
        mount = os.getenv("VAULT_MOUNT", "secret")
        secret = _request(f"{addr}/v1/{mount}/data/netaudit/{service}", token=_client_token(addr))
        values = secret["data"]["data"]
    except (urllib.error.URLError, OSError, KeyError, ValueError, RuntimeError) as exc:
        if os.getenv("VAULT_REQUIRED", "false").lower() == "true":
            raise RuntimeError(f"Vault is required but secrets for {service!r} could not be read: {exc}") from exc
        logger.warning("Vault unavailable for %s (%s); using environment variables", service, exc)
        return 0
    for key, value in values.items():
        os.environ[str(key)] = str(value)
    logger.info("Loaded %d secret(s) for %s from Vault", len(values), service)
    return len(values)
