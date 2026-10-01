"""
Clock-integrity check against the deployment's internal NTP / Stratum 1 source.

Audit evidence (ledger rows, reports, CEF events) is only as trustworthy as
the clock that stamped it. This measures how far this host's clock is from the
configured time source (SNTP, RFC 4330) so every report can state it, and so
operators see drift before it matters. Nothing here changes the clock.

NTP_SERVER      internal time source (host or IP); unset = "not configured"
NTP_MAX_OFFSET_SECONDS   drift above this is reported as DRIFT (default 1.0)
"""

import os
import socket
import struct
import time
from datetime import datetime, timezone

NTP_SERVER = os.getenv("NTP_SERVER", "").strip()
NTP_PORT = int(os.getenv("NTP_PORT", "123"))
MAX_OFFSET_SECONDS = float(os.getenv("NTP_MAX_OFFSET_SECONDS", "1.0"))
_NTP_EPOCH_OFFSET = 2208988800  # seconds between 1900-01-01 and 1970-01-01


def _to_unix(seconds: int, fraction: int) -> float:
    return seconds - _NTP_EPOCH_OFFSET + fraction / 2**32


def _from_unix(timestamp: float) -> tuple[int, int]:
    whole = int(timestamp)
    return whole + _NTP_EPOCH_OFFSET, int((timestamp - whole) * 2**32)


def parse_response(packet: bytes, t0: float, t3: float) -> dict:
    """Offset/delay from a server reply (RFC 4330 §5). t0/t3 = local send/receive times."""
    if len(packet) < 48:
        raise ValueError("Short NTP reply")
    stratum = packet[1]
    if stratum == 0 or (packet[0] >> 6) == 3:
        raise ValueError("Time source is unsynchronised or sent a kiss-o'-death")
    t1 = _to_unix(*struct.unpack("!II", packet[32:40]))
    t2 = _to_unix(*struct.unpack("!II", packet[40:48]))
    return {
        "offset_seconds": ((t1 - t0) + (t2 - t3)) / 2,
        "delay_seconds": (t3 - t0) - (t2 - t1),
        "stratum": stratum,
    }


def query(server: str, port: int = 123, timeout: float = 3.0) -> dict:
    request = bytearray(48)
    request[0] = 0x23  # LI 0, version 4, mode 3 (client)
    t0 = time.time()
    request[40:48] = struct.pack("!II", *_from_unix(t0))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(bytes(request), (server, port))
        packet, _ = sock.recvfrom(512)
    return parse_response(packet, t0, time.time())


def status() -> dict:
    """{"state": OK | DRIFT | UNAVAILABLE | NOT_CONFIGURED, ...} — never raises."""
    checked_at = datetime.now(timezone.utc).isoformat()
    if not NTP_SERVER:
        return {"state": "NOT_CONFIGURED", "checked_at": checked_at}
    try:
        result = query(NTP_SERVER, NTP_PORT)
    except (OSError, ValueError) as exc:
        return {"state": "UNAVAILABLE", "server": NTP_SERVER, "checked_at": checked_at, "detail": type(exc).__name__}
    state = "OK" if abs(result["offset_seconds"]) <= MAX_OFFSET_SECONDS else "DRIFT"
    return {"state": state, "server": NTP_SERVER, "checked_at": checked_at, "max_offset_seconds": MAX_OFFSET_SECONDS, **result}


def describe(result: dict) -> str:
    """One line for the report's integrity section."""
    state = result["state"]
    if state == "NOT_CONFIGURED":
        return "Time synchronization was not verified: no internal time source (NTP_SERVER) is configured."
    if state == "UNAVAILABLE":
        return f"Time synchronization could not be verified: {result['server']} did not answer."
    offset_ms = result["offset_seconds"] * 1000
    verdict = "within tolerance" if state == "OK" else "OUTSIDE tolerance — timestamps in this report may be inaccurate"
    return f"Clock checked against {result['server']} (stratum {result['stratum']}) at {result['checked_at']}: offset {offset_ms:+.1f} ms, {verdict}."
