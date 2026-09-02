"""
Unit tests for app.uploader: size/extension/MIME validation, credential
redaction, SHA-256 dedup, and the MinIO write. The real `magic` C library
and a real MinIO server are never touched — both are monkeypatched so
these tests run anywhere, offline.
"""
import hashlib
from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

from app import uploader


def make_s3_error(code: str) -> S3Error:
    # response=None: the constructor only stores it, never reads it, and
    # a real BaseHTTPResponse isn't worth building for a test double.
    return S3Error(code, "mocked", "resource", "req-id", "host-id", None)  # type: ignore[arg-type]


class FakeUploadFile:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content

    async def read(self) -> bytes:
        return self._content


def make_fake_minio_client(existing_hash: str | None = None) -> MagicMock:
    """Simulates an empty bucket, unless `existing_hash` is given — then
    any object name starting with it looks already-ingested (stat_object
    succeeds instead of raising NoSuchKey)."""
    client = MagicMock()

    def stat_object(bucket, object_name):
        if existing_hash and object_name.startswith(existing_hash):
            return MagicMock()
        raise make_s3_error("NoSuchKey")

    client.stat_object.side_effect = stat_object
    return client


@pytest.fixture(autouse=True)
def fake_mime(monkeypatch):
    monkeypatch.setattr(uploader.magic, "from_buffer", lambda data, mime=True: "text/plain")


@pytest.fixture
def fake_minio(monkeypatch):
    client = make_fake_minio_client()
    monkeypatch.setattr(uploader, "get_minio_client", lambda: client)
    return client


async def test_rejects_oversized_file(monkeypatch, fake_minio):
    monkeypatch.setattr(uploader, "MAX_UPLOAD_SIZE_MB", 0)
    file = FakeUploadFile("device.cfg", b"interface Gi0/1\n")

    with pytest.raises(ValueError, match="exceeds"):
        await uploader.validate_and_store(file)


async def test_rejects_disallowed_extension(fake_minio):
    file = FakeUploadFile("device.exe", b"interface Gi0/1\n")

    with pytest.raises(ValueError, match="not allowed"):
        await uploader.validate_and_store(file)

    fake_minio.put_object.assert_not_called()


async def test_rejects_non_text_mime(monkeypatch, fake_minio):
    monkeypatch.setattr(uploader.magic, "from_buffer", lambda data, mime=True: "application/x-executable")
    file = FakeUploadFile("device.cfg", b"MZ\x90\x00fake binary masquerading as a config")

    with pytest.raises(ValueError, match="not a plain-text config"):
        await uploader.validate_and_store(file)

    fake_minio.put_object.assert_not_called()


async def test_stores_new_file_and_redacts_credentials(fake_minio):
    raw = (
        "hostname router1\n"
        "enable secret 5 $1$abc$verysecrethash\n"
        "username admin secret 5 $1$xyz$anothersecret\n"
        "snmp-server community SuperSecretString RO\n"
        "interface Gi0/1\n"
        " description uplink\n"
    )
    file = FakeUploadFile("device.cfg", raw.encode())

    result = await uploader.validate_and_store(file)

    assert result["original_filename"] == "device.cfg"
    assert result["file_hash"] == hashlib.sha256(raw.encode()).hexdigest()
    assert result["storage_path"] == f"{uploader.MINIO_BUCKET}/{result['file_hash']}.cfg"

    for secret in ("verysecrethash", "anothersecret", "SuperSecretString"):
        assert secret not in result["raw_text"]
    assert "[REDACTED]" in result["raw_text"]
    # Structure around the secret is preserved, only the value is dropped.
    assert "enable secret 5 [REDACTED]" in result["raw_text"]
    assert "interface Gi0/1" in result["raw_text"]

    fake_minio.put_object.assert_called_once()
    args, kwargs = fake_minio.put_object.call_args
    assert args[0] == uploader.MINIO_BUCKET
    assert args[1] == f"{result['file_hash']}.cfg"
    assert kwargs["content_type"] == "text/plain"
    written = args[2].read()
    assert b"verysecrethash" not in written


async def test_rejects_duplicate_upload(monkeypatch):
    raw = b"hostname router1\ninterface Gi0/1\n"
    file_hash = hashlib.sha256(raw).hexdigest()
    client = make_fake_minio_client(existing_hash=file_hash)
    monkeypatch.setattr(uploader, "get_minio_client", lambda: client)
    file = FakeUploadFile("device.cfg", raw)

    with pytest.raises(ValueError, match="already ingested"):
        await uploader.validate_and_store(file)

    client.put_object.assert_not_called()


def test_redact_credentials_leaves_unrelated_lines_untouched():
    text = "hostname router1\ninterface Gi0/1\n description uplink to core\n"

    assert uploader.redact_credentials(text) == text
