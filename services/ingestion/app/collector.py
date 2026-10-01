"""
Automated configuration collection (Netmiko / NAPALM) — the online half of
NetAudit's dual-ingest design. The offline half is the manual file upload,
which remains the only path in air-gapped deployments.

Safety defaults:
* Off unless COLLECTOR_ENABLED=true, so an air-gapped deployment cannot reach
  out to devices even if the endpoint is called.
* Only targets inside COLLECTOR_ALLOWED_CIDRS (comma-separated) are contacted;
  with no allow-list configured nothing is. This stops the endpoint being
  used to probe arbitrary hosts.
* Credentials are used for one connection and never stored or logged.
* Collected text then goes through the same validate_and_store path as an
  upload (MIME check, credential redaction, hashing, dedup, audit record).

Netmiko is required (see requirements.txt); NAPALM is optional (`pip install napalm`).
"""

import asyncio
import ipaddress
import os
import re
import socket
from datetime import datetime, timezone

ENABLED = os.getenv("COLLECTOR_ENABLED", "false").lower() == "true"
ALLOWED_CIDRS = [c.strip() for c in os.getenv("COLLECTOR_ALLOWED_CIDRS", "").split(",") if c.strip()]
TIMEOUT_SECONDS = int(os.getenv("COLLECTOR_TIMEOUT_SECONDS", "30"))

# Netmiko device_type -> the command that prints the running configuration.
DEVICE_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "cisco_asa": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration | display set",
    "fortinet": "show full-configuration",
    "paloalto_panos": "show config running",
}
# device_type -> NAPALM driver name (only platforms NAPALM ships a driver for).
NAPALM_DRIVERS = {
    "cisco_ios": "ios", "cisco_xe": "ios", "cisco_nxos": "nxos_ssh",
    "arista_eos": "eos", "juniper_junos": "junos",
}
_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class CollectorError(Exception):
    """Raised with a message that is safe to show the caller."""


class TextUpload:
    """Adapts collected text to the file interface validate_and_store reads."""

    def __init__(self, filename: str, text: str):
        self.filename = filename
        self._data = text.encode("utf-8")

    async def read(self, size: int = -1) -> bytes:
        chunk, self._data = (self._data, b"") if size < 0 else (self._data[:size], self._data[size:])
        return chunk


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    if not _HOSTNAME.match(host):
        raise CollectorError("Host must be an IP address or a plain hostname")
    try:
        return [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
    except OSError:
        raise CollectorError("Host could not be resolved") from None


def check_target(host: str, port: int) -> None:
    if not ENABLED:
        raise CollectorError("Automated collection is disabled in this deployment (air-gapped mode); upload the configuration file instead")
    if not 1 <= port <= 65535:
        raise CollectorError("Port out of range")
    if not ALLOWED_CIDRS:
        raise CollectorError("No COLLECTOR_ALLOWED_CIDRS configured, so no device may be contacted")
    networks = [ipaddress.ip_network(c, strict=False) for c in ALLOWED_CIDRS]
    addresses = _resolve(host)
    if not addresses or not all(any(a in n for n in networks) for a in addresses):
        raise CollectorError("Target is outside the allowed collection networks")


def _fetch_netmiko(host: str, port: int, device_type: str, username: str, password: str) -> str:
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise CollectorError("netmiko is not installed") from exc
    connection = ConnectHandler(
        device_type=device_type, host=host, port=port, username=username, password=password,
        conn_timeout=TIMEOUT_SECONDS, auth_timeout=TIMEOUT_SECONDS,
    )
    try:
        return connection.send_command(DEVICE_COMMANDS[device_type], read_timeout=TIMEOUT_SECONDS * 4)
    finally:
        connection.disconnect()


def _fetch_napalm(host: str, port: int, device_type: str, username: str, password: str) -> str:
    driver_name = NAPALM_DRIVERS.get(device_type)
    if driver_name is None:
        raise CollectorError(f"NAPALM has no driver for {device_type}; use method=netmiko")
    try:
        from napalm import get_network_driver
    except ImportError as exc:
        raise CollectorError("napalm is not installed") from exc
    device = get_network_driver(driver_name)(host, username, password, timeout=TIMEOUT_SECONDS, optional_args={"port": port})
    device.open()
    try:
        return device.get_config(retrieve="running")["running"]
    finally:
        device.close()


_FETCHERS = {"netmiko": _fetch_netmiko, "napalm": _fetch_napalm}


async def collect_config(host: str, port: int, device_type: str, username: str, password: str, method: str = "netmiko") -> TextUpload:
    if device_type not in DEVICE_COMMANDS:
        raise CollectorError(f"Unsupported device_type; choose one of {sorted(DEVICE_COMMANDS)}")
    if method not in _FETCHERS:
        raise CollectorError("method must be 'netmiko' or 'napalm'")
    check_target(host, port)
    try:
        text = await asyncio.to_thread(_FETCHERS[method], host, port, device_type, username, password)
    except CollectorError:
        raise
    except Exception as exc:  # library errors can echo connection details; report only the class
        raise CollectorError(f"Could not collect from {host}: {type(exc).__name__}") from None
    if not text or not text.strip():
        raise CollectorError("The device returned an empty configuration")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return TextUpload(f"{host}-{stamp}.cfg", text)
