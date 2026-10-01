"""
Best-effort hardware identity (model, serial number, extra version sources)
pulled from configuration text.

Patterns are tried against any config regardless of the detected vendor
(same vendor-agnostic rule as the compliance policy): each matches a widely
used way devices print their identity — Cisco's `license udi pid ... sn ...`
line, FortiOS's `#config-version=` header, and generic `Serial Number:` /
`Model:` lines found in config headers and pasted `show` output. A config that
carries none of these simply yields None; nothing is guessed.
"""

import re

_UDI = re.compile(r"(?im)^\s*license\s+udi\s+pid\s+(\S+)\s+sn\s+(\S+)")
_FORTI_HEADER = re.compile(r"(?m)^#config-version=([A-Za-z0-9]+)-(\d+\.\d+\.\d+)")
_SERIAL_PATTERNS = (
    re.compile(r"(?im)^\s*[!#]?\s*(?:chassis\s+|system\s+)?serial[\s_-]*(?:number|no\.?|#)\s*[:=]\s*([A-Za-z0-9._-]{4,40})\s*$"),
    re.compile(r"(?im)^\s*set\s+serial[-_]?number\s+\"?([A-Za-z0-9._-]{4,40})\"?\s*$"),
    re.compile(r"(?im)^\s*[!#]?\s*processor\s+board\s+id\s+([A-Za-z0-9._-]{4,40})\s*$"),
)
_MODEL_PATTERNS = (
    re.compile(r"(?im)^\s*[!#]?\s*(?:hardware\s+)?model(?:\s+(?:number|name))?\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._ /-]{1,40}?)\s*$"),
    re.compile(r"(?im)^\s*[!#]?\s*(?:platform|hardware)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._ /-]{1,40}?)\s*$"),
)


def extract_identity(text: str) -> dict[str, str | None]:
    """{"hardware_model", "serial_number", "header_version"} — each None when absent."""
    model = serial = header_version = None

    udi = _UDI.search(text)
    if udi:
        model, serial = udi.group(1), udi.group(2)

    forti = _FORTI_HEADER.search(text)
    if forti:
        model = model or forti.group(1)
        header_version = forti.group(2)

    if serial is None:
        for pattern in _SERIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                serial = match.group(1)
                break
    if model is None:
        for pattern in _MODEL_PATTERNS:
            match = pattern.search(text)
            if match:
                model = match.group(1).strip()
                break
    return {"hardware_model": model, "serial_number": serial, "header_version": header_version}
