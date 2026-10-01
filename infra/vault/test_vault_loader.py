import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import vault_loader

ROOT = Path(__file__).resolve().parents[2]
COPIES = [
    "gateway/app", "services/ingestion/app", "services/parsing/app",
    "services/compliance/app", "services/remediation/app", "services/reporting/app",
]


class FakeVault(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        if self.headers.get("X-Vault-Token") != "good-token":
            return self._send(403, {"errors": ["permission denied"]})
        if self.path == "/v1/secret/data/netaudit/gateway":
            return self._send(200, {"data": {"data": {"JWT_SECRET": "from-vault", "OTHER": "x"}}})
        self._send(404, {"errors": []})

    def do_POST(self):
        self._send(200, {"auth": {"client_token": "good-token"}})


@pytest.fixture
def vault():
    server = HTTPServer(("127.0.0.1", 0), FakeVault)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_REQUIRED", "JWT_SECRET"):
        monkeypatch.delenv(name, raising=False)


def test_inert_without_vault_addr():
    assert vault_loader.load("gateway") == 0


def test_token_login_overrides_environment(vault, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", vault)
    monkeypatch.setenv("VAULT_TOKEN", "good-token")
    monkeypatch.setenv("JWT_SECRET", "from-env")
    assert vault_loader.load("gateway") == 2
    assert vault_loader.os.environ["JWT_SECRET"] == "from-vault"


def test_approle_login(vault, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", vault)
    monkeypatch.setenv("VAULT_ROLE_ID", "r")
    monkeypatch.setenv("VAULT_SECRET_ID", "s")
    assert vault_loader.load("gateway") == 2


def test_unreachable_vault_falls_back_unless_required(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_TOKEN", "good-token")
    assert vault_loader.load("gateway") == 0
    monkeypatch.setenv("VAULT_REQUIRED", "true")
    with pytest.raises(RuntimeError, match="required"):
        vault_loader.load("gateway")


def test_service_copies_match_the_canonical_loader():
    canonical = (Path(__file__).parent / "vault_loader.py").read_bytes()
    for d in COPIES:
        assert (ROOT / d / "vault_loader.py").read_bytes() == canonical, f"{d} has drifted"
