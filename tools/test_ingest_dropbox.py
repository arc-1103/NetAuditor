import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import ingest_dropbox as d

RECEIVED = []


class FakeGateway(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path == "/api/login":
            return self._send(200, {"access_token": "tok"})
        if self.headers.get("Authorization") != "Bearer tok":
            return self._send(401, {"detail": "no"})
        if b"reject-me" in body:
            return self._send(400, {"detail": "not a plain-text config"})
        RECEIVED.append(body)
        self._send(200, {"job_id": "run-1", "status": "queued"})

    def _send(self, code, payload):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())


@pytest.fixture
def gateway():
    RECEIVED.clear()
    server = HTTPServer(("127.0.0.1", 0), FakeGateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_files_are_uploaded_sorted_into_processed_and_failed(gateway, tmp_path):
    (tmp_path / "good.cfg").write_text("hostname r1\n")
    (tmp_path / "bad.txt").write_text("reject-me")
    (tmp_path / "notes.pdf").write_text("ignored: wrong extension")
    token = d.login(gateway, "op@x", "pw")
    ok, bad = d.run(tmp_path, gateway, token)
    assert (ok, bad) == (1, 1)
    assert (tmp_path / "processed" / "good.cfg").exists()
    assert (tmp_path / "failed" / "bad.txt").exists()
    assert "plain-text" in (tmp_path / "failed" / "bad.txt.error").read_text()
    assert (tmp_path / "notes.pdf").exists()  # untouched
    assert b"hostname r1" in RECEIVED[0] and b'filename="good.cfg"' in RECEIVED[0]
