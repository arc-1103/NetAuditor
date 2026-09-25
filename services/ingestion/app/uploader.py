"""
File validation, credential redaction, SHA-256 dedup, MinIO storage.
"""
import hashlib
import io
import os
import re

import magic
from minio import Minio

MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
ALLOWED_EXTENSIONS = os.getenv("ALLOWED_EXTENSIONS", ".cfg,.txt,.conf").split(",")
# Config uploads must sniff as plain text — blocks binaries/scripts masquerading
# behind an allowed extension.
ALLOWED_MIME_TYPES = {"text/plain"}

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "raw-configs")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

_minio_client = None

# Line-oriented patterns for common network-device secret formats, each
# paired with a short label identifying the kind of credential. Each
# pattern keeps the directive/type tokens and redacts only the trailing
# secret value, so the surrounding config structure stays intact for
# parsing downstream.
CREDENTIAL_PATTERNS = [
    ("enable_secret", re.compile(r"(?im)^(\s*enable\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)\s*$")),
    ("username_secret", re.compile(r"(?im)^(\s*username\s+\S+(?:\s+\S+)*?\s+(?:secret|password)\s+(?:\d+\s+)?)(\S+)\s*$")),
    ("plain_password", re.compile(r"(?im)^(\s*password\s+(?:\d+\s+)?)(\S+)\s*$")),
    ("psk_key", re.compile(r"(?im)^(\s*(?:wpa-psk|pre-shared-key|key)\s+(?:ascii|hex)?\s*)(\S+)\s*$")),
]

# "public"/"private" are well-known SNMP defaults, not secrets — compliance
# check CIS-NET-1.2.2 needs them left visible in the text to ever fire.
_DEFAULT_SNMP_COMMUNITIES = {"public", "private"}


def redact_credentials(text: str) -> str:
    redacted = text
    # Any non-default community is a real secret and is also reused as the
    # implicit auth token on `snmp-server host ... <community>` lines, so
    # redact it everywhere it appears, not just on the `community` line.
    custom_communities = {
        m.group(1)
        for m in re.finditer(r"(?im)^\s*snmp-server\s+community\s+(\S+)", redacted)
        if m.group(1).lower() not in _DEFAULT_SNMP_COMMUNITIES
    }
    for community in custom_communities:
        redacted = re.sub(rf"(?<!\S){re.escape(community)}(?!\S)", "[REDACTED]", redacted)
    for _label, pattern in CREDENTIAL_PATTERNS:
        redacted = pattern.sub(lambda m: m.group(1) + "[REDACTED]", redacted)
    return redacted


def _mask_secret(value: str) -> str:
    """Last 4 characters only — enough for a human to confirm which secret
    a finding refers to (e.g. across two findings, or against a known-weak
    password list by hash) without ever reconstructing it. A secret under 4
    characters is masked completely rather than partially revealed in full."""
    if len(value) < 4:
        return "*" * len(value) if value else ""
    return "*" * (len(value) - 4) + value[-4:]


def capture_credential_evidence(text: str) -> list[dict]:
    """Evidence captured from the RAW (pre-redaction) text — see
    docs/ArchitecturalChanges.md §2. Never the raw secret itself: only a
    trailing-4-char mask, the line it was found on, and a SHA-256 of the
    real value so a reviewer can confirm two findings share a secret, or
    check it against a known-weak-password hash list later."""
    evidence = []
    for pattern_type, pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(2)
            evidence.append(
                {
                    "pattern_type": pattern_type,
                    "line_number": text.count("\n", 0, match.start()) + 1,
                    "masked_value": _mask_secret(value),
                    "sha256": hashlib.sha256(value.encode()).hexdigest(),
                }
            )
    return evidence


def get_minio_client() -> Minio:
    global _minio_client
    if _minio_client is None:
        _minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        if not _minio_client.bucket_exists(MINIO_BUCKET):
            _minio_client.make_bucket(MINIO_BUCKET)
    return _minio_client


async def validate_and_store(file) -> dict:
    max_bytes = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    chunks = []
    total = 0
    while chunk := await file.read(min(1024 * 1024, max_bytes + 1 - total)):
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"File exceeds {MAX_UPLOAD_SIZE_MB}MB limit")
        chunks.append(chunk)
    contents = b"".join(chunks)

    ext = os.path.splitext(file.filename)[1]
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension {ext} not allowed")

    mime_type = magic.from_buffer(contents, mime=True)
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File content type '{mime_type}' is not a plain-text config")

    file_hash = hashlib.sha256(contents).hexdigest()
    object_name = f"{file_hash}{ext}"
    storage_path = f"{MINIO_BUCKET}/{object_name}"

    client = get_minio_client()

    decoded_text = contents.decode("utf-8", errors="replace")
    credential_evidence = capture_credential_evidence(decoded_text)
    redacted_text = redact_credentials(decoded_text)
    redacted_bytes = redacted_text.encode("utf-8")
    client.put_object(
        MINIO_BUCKET,
        object_name,
        io.BytesIO(redacted_bytes),
        length=len(redacted_bytes),
        content_type="text/plain",
    )

    return {
        "file_hash": file_hash,
        "storage_path": storage_path,
        "original_filename": file.filename,
        "raw_text": redacted_text,
        "credential_evidence": credential_evidence,
    }
