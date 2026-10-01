import asyncio

import pytest

from app import collector
from app.collector import CollectorError


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(collector, "ENABLED", True)
    monkeypatch.setattr(collector, "ALLOWED_CIDRS", ["10.20.0.0/16"])


def run(coro):
    return asyncio.run(coro)


def test_disabled_by_default_blocks_even_a_valid_target(monkeypatch):
    monkeypatch.setattr(collector, "ENABLED", False)
    with pytest.raises(CollectorError, match="disabled"):
        run(collector.collect_config("10.20.0.5", 22, "cisco_ios", "u", "p"))


def test_enabled_without_an_allowlist_contacts_nothing(monkeypatch):
    monkeypatch.setattr(collector, "ENABLED", True)
    monkeypatch.setattr(collector, "ALLOWED_CIDRS", [])
    with pytest.raises(CollectorError, match="COLLECTOR_ALLOWED_CIDRS"):
        run(collector.collect_config("10.20.0.5", 22, "cisco_ios", "u", "p"))


@pytest.mark.parametrize("host", ["192.168.1.1", "169.254.169.254", "127.0.0.1"])
def test_targets_outside_the_allowed_networks_are_refused(enabled, host):
    with pytest.raises(CollectorError, match="outside"):
        run(collector.collect_config(host, 22, "cisco_ios", "u", "p"))


@pytest.mark.parametrize("host", ["bad host;rm -rf", "a b", "-flag", "host/../x"])
def test_malformed_hosts_are_rejected(enabled, host):
    with pytest.raises(CollectorError):
        run(collector.collect_config(host, 22, "cisco_ios", "u", "p"))


def test_unknown_device_type_and_method_are_rejected(enabled):
    with pytest.raises(CollectorError, match="Unsupported"):
        run(collector.collect_config("10.20.0.5", 22, "nonexistent_os", "u", "p"))
    with pytest.raises(CollectorError, match="method"):
        run(collector.collect_config("10.20.0.5", 22, "cisco_ios", "u", "p", method="telnet"))


def test_collected_text_becomes_an_upload_the_pipeline_can_read(enabled, monkeypatch):
    seen = {}

    def fake_fetch(host, port, device_type, username, password):
        seen.update(host=host, device_type=device_type, password=password)
        return "hostname edge1\nip ssh version 2\n"

    monkeypatch.setitem(collector._FETCHERS, "netmiko", fake_fetch)
    upload = run(collector.collect_config("10.20.0.5", 22, "cisco_ios", "admin", "s3cret"))
    assert upload.filename.startswith("10.20.0.5-") and upload.filename.endswith(".cfg")
    assert run(upload.read(5)) == b"hostn" and run(upload.read(-1)).startswith(b"ame edge1")
    assert run(upload.read(10)) == b"" and seen["device_type"] == "cisco_ios"


def test_library_errors_never_leak_connection_details(enabled, monkeypatch):
    def boom(*args):
        raise RuntimeError("auth failed for admin with password s3cret on 10.20.0.5")

    monkeypatch.setitem(collector._FETCHERS, "netmiko", boom)
    with pytest.raises(CollectorError) as exc:
        run(collector.collect_config("10.20.0.5", 22, "cisco_ios", "admin", "s3cret"))
    assert "s3cret" not in str(exc.value) and "RuntimeError" in str(exc.value)


def test_empty_configuration_is_an_error(enabled, monkeypatch):
    monkeypatch.setitem(collector._FETCHERS, "netmiko", lambda *a: "  \n")
    with pytest.raises(CollectorError, match="empty"):
        run(collector.collect_config("10.20.0.5", 22, "cisco_ios", "u", "p"))
