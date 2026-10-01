"""
Loads configuration files from a landing directory (filled by a data diode or
a scanned-media kiosk) into NetAudit through the normal gateway.

  NETAUDIT_URL=http://gateway:8000 NETAUDIT_EMAIL=operator@netaudit.local \
  NETAUDIT_PASSWORD=... python tools/ingest_dropbox.py /landing

Each .cfg/.conf/.txt file is uploaded exactly like a manual upload, so the
ingest gate's checks all apply (extension, content type, size, credential
redaction, hash de-duplication). Accepted files move to <dir>/processed/,
rejected ones to <dir>/failed/ with the reason in a .error file next to them.
"""

import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from urllib import error, request

ALLOWED = {".cfg", ".conf", ".txt"}


def _post(url: str, data: bytes, headers: dict[str, str]) -> dict:
    req = request.Request(url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def login(base: str, email: str, password: str) -> str:
    body = json.dumps({"email": email, "password": password}).encode()
    return _post(f"{base}/api/login", body, {"Content-Type": "application/json"})["access_token"]


def upload(base: str, token: str, path: Path) -> dict:
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": f"multipart/form-data; boundary={boundary}"}
    return _post(f"{base}/api/upload", body, headers)


def run(landing: Path, base: str, token: str) -> tuple[int, int]:
    processed, failed = landing / "processed", landing / "failed"
    processed.mkdir(exist_ok=True)
    failed.mkdir(exist_ok=True)
    ok = bad = 0
    for path in sorted(p for p in landing.iterdir() if p.is_file() and p.suffix.lower() in ALLOWED):
        try:
            result = upload(base, token, path)
            print(f"{path.name}: {result.get('status')} (run {result.get('job_id')})")
            shutil.move(str(path), processed / path.name)
            ok += 1
        except (error.HTTPError, error.URLError, OSError, ValueError) as exc:
            detail = exc.read().decode(errors="replace") if isinstance(exc, error.HTTPError) else str(exc)
            print(f"{path.name}: REJECTED - {detail}", file=sys.stderr)
            (failed / f"{path.name}.error").write_text(detail, encoding="utf-8")
            shutil.move(str(path), failed / path.name)
            bad += 1
    return ok, bad


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    landing = Path(argv[1])
    base = os.getenv("NETAUDIT_URL", "http://localhost:8000").rstrip("/")
    email, password = os.getenv("NETAUDIT_EMAIL"), os.getenv("NETAUDIT_PASSWORD")
    if not (email and password) or not landing.is_dir():
        print("Set NETAUDIT_EMAIL and NETAUDIT_PASSWORD, and pass an existing landing directory.", file=sys.stderr)
        return 2
    ok, bad = run(landing, base, login(base, email, password))
    print(f"{ok} uploaded, {bad} rejected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
