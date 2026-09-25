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
        self._offset = 0

    async def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._content) - self._offset
        chunk = self._content[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk


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

    # Masked evidence captured before redaction (docs/ArchitecturalChanges.md §2):
    # never the raw secret, only a trailing mask, line number, and a hash a
    # reviewer can use to confirm two findings share a secret.
    evidence = result["credential_evidence"]
    by_type = {item["pattern_type"]: item for item in evidence}
    enable_secret_value = "$1$abc$verysecrethash"
    assert by_type["enable_secret"]["line_number"] == 2
    assert by_type["enable_secret"]["masked_value"] == "*" * (len(enable_secret_value) - 4) + "hash"
    assert by_type["enable_secret"]["sha256"] == hashlib.sha256(enable_secret_value.encode()).hexdigest()
    assert by_type["username_secret"]["line_number"] == 3
    for item in evidence:
        assert "verysecrethash" not in item["masked_value"]
        assert "anothersecret" not in item["masked_value"]


async def test_credential_evidence_is_empty_when_nothing_matches(fake_minio):
    file = FakeUploadFile("device.cfg", b"hostname router1\ninterface Gi0/1\n")

    result = await uploader.validate_and_store(file)

    assert result["credential_evidence"] == []


def test_mask_secret_fully_masks_short_values():
    assert uploader._mask_secret("abc") == "***"
    assert uploader._mask_secret("") == ""


def test_mask_secret_keeps_only_last_four_characters():
    assert uploader._mask_secret("hunter2verysecret") == "*" * 13 + "cret"


async def test_rewrites_already_stored_object_instead_of_rejecting(monkeypatch):
    # Dedup is now Postgres's job (see app.db.get_audit_run_id_by_hash),
    # checked by the caller before create_audit_run. validate_and_store
    # itself must always (re)write the content-addressed object in MinIO,
    # even if that hash already exists there — otherwise a partial failure
    # after a first successful write (DB/queue down) would permanently
    # brick retries of the exact same file.
    raw = b"hostname router1\ninterface Gi0/1\n"
    file_hash = hashlib.sha256(raw).hexdigest()
    client = make_fake_minio_client(existing_hash=file_hash)
    monkeypatch.setattr(uploader, "get_minio_client", lambda: client)
    file = FakeUploadFile("device.cfg", raw)

    result = await uploader.validate_and_store(file)

    assert result["file_hash"] == file_hash
    client.put_object.assert_called_once()


def test_redact_credentials_leaves_unrelated_lines_untouched():
    text = "hostname router1\ninterface Gi0/1\n description uplink to core\n"

    assert uploader.redact_credentials(text) == text


def test_redact_credentials_leaves_default_snmp_communities_visible():
    # "public"/"private" are well-known defaults, not secrets. Compliance
    # check CIS-NET-1.2.2 detects devices still using them — redacting
    # them here would destroy the only evidence that check needs.
    text = (
        "snmp-server community public RO\n"
        "snmp-server host 10.20.10.12 version 2c public\n"
    )

    redacted = uploader.redact_credentials(text)

    assert redacted == text
    assert "[REDACTED]" not in redacted


def test_redact_credentials_redacts_custom_snmp_community_everywhere():
    # A non-default community is a real secret and is reused as the
    # implicit auth token on `snmp-server host` lines, so it must be
    # redacted on both lines, not just the `community` line.
    text = (
        "snmp-server community s3cr3t-str1ng RO\n"
        "snmp-server host 10.1.1.1 version 2c s3cr3t-str1ng\n"
    )

    redacted = uploader.redact_credentials(text)

    assert "s3cr3t-str1ng" not in redacted
    assert redacted.count("[REDACTED]") == 2
