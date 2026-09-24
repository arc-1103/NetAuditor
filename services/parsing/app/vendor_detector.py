from __future__ import annotations

import re
from collections.abc import Iterable

from .models import DeviceContext, VendorDetection

# Best-effort labels only — see worker.py. Vendor identity no longer gates
# whether a device reaches Compliance; an unrecognized vendor is not the
# same thing as an unparseable one, and the two used to be conflated here.
PATTERNS = [
    (
        "cisco",
        "IOS-XE",
        0.96,
        (
            r"(?im)^\s*version\s+\d+\.\d+",
            r"(?im)^\s*service\s+timestamps\s+debug",
            r"(?im)^\s*ip\s+ssh\s+version\s+2",
        ),
    ),
    (
        "juniper",
        "JunOS",
        0.97,
        (
            r"(?im)^\s*set\s+system\s+services\s+ssh",
            r"(?im)^\s*set\s+system\s+host-name\s+\S+",
            r"(?im)^\s*set\s+version\s+\S+",
            r"(?im)^\s*interfaces\s*\{",
        ),
    ),
    (
        "paloalto",
        "PAN-OS",
        0.97,
        (
            r"(?im)^\s*set\s+deviceconfig",
            r"(?im)^\s*set\s+network\s+interface",
            r"(?im)^\s*set\s+deviceconfig\s+system\s+type",
            r"(?im)^\s*set\s+deviceconfig\s+system\s+hostname",
        ),
    ),
    (
        "arista",
        "EOS",
        0.96,
        (
            r"(?im)^\s*!\s*Arista",
            r"(?im)^\s*daemon\s+TerminAttr",
            r"(?im)^\s*management\s+api\s+http-commands",
            r"(?im)^\s*management\s+api\s+gnmi",
        ),
    ),
]


def detect_vendor(text: str) -> VendorDetection:
    """Detect identity from one text sample. The worker calls this on job context."""
    scores: list[tuple[float, str, str, list[str]]] = []

    for vendor, os_name, base_confidence, patterns in PATTERNS:
        evidence = [pattern for pattern in patterns if re.search(pattern, text)]
        if evidence:
            score = min(0.99, base_confidence + 0.01 * max(0, len(evidence) - 1))
            scores.append((score, vendor, os_name, evidence))

    if not scores:
        return VendorDetection("unknown", None, None, None, None, 0.0, ())

    scores.sort(key=lambda item: (item[0], item[1]), reverse=True)
    score, vendor, os_name, evidence = scores[0]

    if len(scores) > 1 and scores[1][0] >= score - 0.03:
        return VendorDetection(
            "unknown",
            None,
            None,
            None,
            None,
            max(0.0, score - 0.25),
            tuple(evidence),
        )

    version = _extract_version(text, vendor)
    hostname = _extract_hostname(text, vendor)
    return VendorDetection(vendor, os_name, version, hostname, None, score, tuple(evidence))


def detect_job_context(
    chunks: Iterable[dict],
    *,
    max_context_chars: int = 12000,
) -> DeviceContext:
    """Detect device identity once from a bounded deterministic job-level sample."""
    texts = [str(chunk.get("text", "")) for chunk in sorted(chunks, key=lambda item: item["index"])]
    context_parts: list[str] = []
    used = 0

    for text in texts:
        if used >= max_context_chars:
            break
        remaining = max_context_chars - used
        if len(text) <= remaining:
            part = text
        else:
            part = text[:remaining]
        if part:
            context_parts.append(part)
            used += len(part)

    detection = detect_vendor("\n\n".join(context_parts))
    return DeviceContext(
        vendor=detection.vendor,
        os=detection.os,
        os_version=detection.os_version,
        raw_hostname=detection.raw_hostname,
        hardware_model=detection.hardware_model,
        confidence=detection.confidence,
        evidence=detection.evidence,
    )


def _extract_version(text: str, vendor: str) -> str | None:
    patterns = {
        "cisco": r"(?im)^\s*version\s+([0-9A-Za-z.\-]+)",
        "juniper": r"(?im)^\s*set\s+version\s+([0-9A-Za-z.\-]+)",
        "paloalto": r"(?im)^\s*set\s+deviceconfig\s+system\s+sw-version\s+([0-9A-Za-z.\-]+)",
        "arista": r"(?im)^\s*version\s+([0-9A-Za-z.\-]+)",
    }
    pattern = patterns.get(vendor)
    match = re.search(pattern, text) if pattern else None
    return match.group(1) if match else None


def _extract_hostname(text: str, vendor: str) -> str | None:
    patterns = {
        "cisco": r"(?im)^\s*hostname\s+(\S+)",
        "juniper": r"(?im)^\s*set\s+system\s+host-name\s+(\S+)",
        "paloalto": r"(?im)^\s*set\s+deviceconfig\s+system\s+hostname\s+(\S+)",
        "arista": r"(?im)^\s*hostname\s+(\S+)",
    }
    pattern = patterns.get(vendor)
    match = re.search(pattern, text) if pattern else None
    return match.group(1) if match else None
