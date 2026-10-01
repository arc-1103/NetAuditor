import socket
import struct
import threading
import time

import pytest

from app import timesync


def server_reply(skew: float = 0.0, stratum: int = 1, mode: int = 4):
    """A fake NTP server whose clock is `skew` seconds ahead of ours."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve():
        data, addr = sock.recvfrom(512)
        now = time.time() + skew
        reply = bytearray(48)
        reply[0] = (0 << 6) | (4 << 3) | mode
        reply[1] = stratum
        reply[32:40] = struct.pack("!II", *timesync._from_unix(now))
        reply[40:48] = struct.pack("!II", *timesync._from_unix(now))
        sock.sendto(bytes(reply), addr)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_offset_is_measured_against_the_server_clock():
    result = timesync.query("127.0.0.1", server_reply(skew=2.0))
    assert result["offset_seconds"] == pytest.approx(2.0, abs=0.25) and result["stratum"] == 1


def test_status_states(monkeypatch):
    monkeypatch.setattr(timesync, "NTP_SERVER", "127.0.0.1")
    monkeypatch.setattr(timesync, "NTP_PORT", server_reply(skew=0.0))
    assert timesync.status()["state"] == "OK"
    monkeypatch.setattr(timesync, "NTP_PORT", server_reply(skew=30.0))
    drift = timesync.status()
    assert drift["state"] == "DRIFT" and "OUTSIDE" in timesync.describe(drift)
    monkeypatch.setattr(timesync, "NTP_PORT", 1)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: (_ for _ in ()).throw(OSError("blocked")))
    assert timesync.status()["state"] == "UNAVAILABLE"


def test_not_configured_is_reported_honestly(monkeypatch):
    monkeypatch.setattr(timesync, "NTP_SERVER", "")
    result = timesync.status()
    assert result["state"] == "NOT_CONFIGURED" and "not verified" in timesync.describe(result)


def test_unsynchronised_server_is_rejected():
    packet = bytearray(48)
    packet[1] = 0  # stratum 0 = kiss-of-death / unsynchronised
    with pytest.raises(ValueError):
        timesync.parse_response(bytes(packet), 0.0, 0.0)
