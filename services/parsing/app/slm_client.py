from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .models import DeviceContext, SLMResult


class SLMError(RuntimeError):
    pass


class SLMTimeout(SLMError):
    pass


REVERSE_TRANSLATE_SCHEMA = {
    "type": "object",
    "required": ["reconstructed_cli"],
    "properties": {"reconstructed_cli": {"type": "string"}},
}


class OllamaSLMClient:
    def __init__(
        self,
        host: str,
        model: str,
        *,
        timeout_seconds: float = 60.0,
        mock: bool = False,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.mock = mock

    async def generate(
        self,
        prompt: str,
        config_text: str,
        schema: dict[str, Any],
        *,
        device_context: DeviceContext,
    ) -> SLMResult:
        if self.mock:
            return self._mock_response(config_text, device_context)

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0},
            # Not every Ollama version reports per-token logprobs on this
            # endpoint; asking for them is harmless when unsupported (the
            # field is just absent from the response) and lets
            # _extract_mean_logprob compute the active-learning signal when
            # it is available.
            "logprobs": True,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.host}/api/generate", json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.TimeoutException as exc:
            raise SLMTimeout("Ollama request timed out") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise SLMError(f"Ollama request failed: {exc}") from exc

        raw = body.get("response")
        if not isinstance(raw, str):
            raise SLMError("Ollama response did not contain a string 'response' field")

        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SLMError("Ollama returned invalid JSON") from exc

        if not isinstance(value, dict):
            raise SLMError("Ollama JSON response must be an object")
        return SLMResult(value=value, mean_logprob=_extract_mean_logprob(body))

    async def reverse_translate(self, baseline_json: dict[str, Any], device_context: DeviceContext) -> str:
        """Agent B of the multi-agent reverse-translation check
        (app/reverse_translation.py): reconstruct plausible vendor CLI from
        ONLY the normalized JSON — no access to the original config text.
        Re-running forward extraction on the result and diffing against the
        original candidate is what verifies the round trip lost no data.
        """
        if self.mock:
            return self._mock_reverse_translate(baseline_json)

        prompt = (
            "You are reconstructing plausible vendor CLI configuration from a "
            "normalized JSON security baseline. You do not have access to the "
            "original configuration text — reconstruct only from the JSON "
            "fields below, in syntax typical for the given vendor/OS.\n\n"
            f"Vendor: {device_context.vendor}\nOS: {device_context.os or 'unknown'}\n\n"
            f"JSON baseline:\n{json.dumps(baseline_json, indent=2)}\n\n"
            "Respond with reconstructed_cli."
        )
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": REVERSE_TRANSLATE_SCHEMA,
            "options": {"temperature": 0},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.host}/api/generate", json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.TimeoutException as exc:
            raise SLMTimeout("Ollama reverse-translation request timed out") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise SLMError(f"Ollama reverse-translation request failed: {exc}") from exc

        raw = body.get("response")
        if not isinstance(raw, str):
            raise SLMError("Ollama response did not contain a string 'response' field")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SLMError("Ollama returned invalid JSON for reverse translation") from exc

        cli = value.get("reconstructed_cli") if isinstance(value, dict) else None
        if not isinstance(cli, str):
            raise SLMError("Ollama reverse-translation response missing 'reconstructed_cli'")
        return cli

    def _mock_reverse_translate(self, baseline_json: dict[str, Any]) -> str:
        """Deterministic inverse of _mock_response's own patterns, so the
        mock round trip (forward -> reverse -> forward again) recovers the
        same fields without a real model. Proves the plumbing; it is not a
        stand-in for genuine vendor-CLI reconstruction fidelity, the same
        way the rest of this mock isn't a stand-in for real extraction.
        """
        lines: list[str] = []

        hostname = (baseline_json.get("device") or {}).get("raw_hostname")
        if hostname:
            lines.append(f"hostname {hostname}")

        ssh = baseline_json.get("ssh") or {}
        if ssh.get("enabled") and ssh.get("version"):
            lines.append(f"ip ssh version {ssh['version']}")

        telnet_enabled = (baseline_json.get("telnet") or {}).get("enabled")
        if telnet_enabled == "DISABLED":
            lines.append("no transport input telnet")
        elif telnet_enabled == "ENABLED":
            lines.append("transport input telnet")

        if (baseline_json.get("aaa") or {}).get("password_encryption") == "ENABLED":
            lines.append("service password-encryption")

        http_enabled = (baseline_json.get("services") or {}).get("http_server_enabled")
        if http_enabled == "DISABLED":
            lines.append("no ip http server")
        elif http_enabled == "ENABLED":
            lines.append("ip http server")

        for host in (baseline_json.get("logging") or {}).get("syslog_hosts") or []:
            lines.append(f"logging host {host}")

        ntp = baseline_json.get("ntp") or {}
        for server in ntp.get("servers") or []:
            lines.append(f"ntp server {server}")
        if ntp.get("authentication_enabled"):
            lines.append("ntp authenticate")

        if (baseline_json.get("banners") or {}).get("login_banner_present"):
            lines.append("banner login")

        return "\n".join(lines)

    def _mock_response(self, text: str, context: DeviceContext) -> SLMResult:
        """Deterministic extraction of only facts observable in this chunk.

        Every pattern here is tried unconditionally, regardless of
        `context.vendor` — a real SLM doesn't need to be told the vendor's
        name to recognize "ssh version 2" or "set system host-name", and
        gating extraction on a regex-recognized vendor string is exactly the
        kind of hardcoding that fails on anything the fingerprinter has
        never seen. Confidence reflects how much of this chunk was actually
        understood (how many fields were found), not whether the vendor was
        named — an unrecognized vendor that still yields real fields should
        not be penalized the way a chunk with genuinely nothing in it is.
        """
        result: dict[str, Any] = {
            "schema_version": "1.0.0",
            "device": {
                "detected_vendor": context.vendor,
                "detected_os": context.os,
                "detected_os_version": context.os_version,
                "detected_hardware_model": context.hardware_model,
            },
        }
        fields_found = 0

        hostname = (
            _first_match(text, r"(?im)^\s*hostname\s+(\S+)")
            or _first_match(text, r"(?im)^\s*set\s+system\s+host-name\s+(\S+)")
            or _first_match(text, r"(?im)^\s*set\s+deviceconfig\s+system\s+hostname\s+(\S+)")
        )
        if hostname:
            result["device"]["raw_hostname"] = hostname
            fields_found += 1

        ssh_version = _first_match(text, r"(?im)^\s*ip\s+ssh\s+version\s+([12])\s*$")
        if ssh_version:
            result["ssh"] = {"enabled": True, "version": ssh_version}
            fields_found += 1

        if re.search(r"(?im)^\s*no\s+transport\s+input\s+telnet\b", text):
            result["telnet"] = {"enabled": "DISABLED"}
            fields_found += 1
        elif re.search(r"(?im)^\s*transport\s+input\s+telnet\b", text):
            result["telnet"] = {"enabled": "ENABLED"}
            fields_found += 1

        if re.search(r"(?im)^\s*service\s+password-encryption\b", text):
            result["aaa"] = {"password_encryption": "ENABLED"}
            fields_found += 1

        if re.search(r"(?im)^\s*no\s+ip\s+http\s+server\b", text):
            result["services"] = {"http_server_enabled": "DISABLED"}
            fields_found += 1
        elif re.search(r"(?im)^\s*ip\s+http\s+server\b", text):
            result["services"] = {"http_server_enabled": "ENABLED"}
            fields_found += 1

        if re.search(r"(?im)^\s*logging\s+host\s+(\S+)", text):
            hosts = re.findall(r"(?im)^\s*logging\s+host\s+(\S+)", text)
            result["logging"] = {"syslog_enabled": True, "syslog_hosts": hosts}
            fields_found += 1

        if re.search(r"(?im)^\s*ntp\s+server\s+(\S+)", text):
            servers = re.findall(r"(?im)^\s*ntp\s+server\s+(\S+)", text)
            result["ntp"] = {"enabled": True, "servers": servers}
            if re.search(r"(?im)^\s*ntp\s+authenticate\b", text):
                result["ntp"]["authentication_enabled"] = True
            fields_found += 1

        if re.search(r"(?im)^\s*banner\s+login\b", text):
            result["banners"] = {"login_banner_present": True}
            fields_found += 1

        # Topology facts for GraphRAG (services/compliance/app/graph_client.py).
        # Deliberately excluded from fields_found/parsing_confidence: that
        # score gates whether a baseline is trusted enough to reach
        # Compliance's CIS/NIST/STIG evaluation, and topology has no bearing
        # on that verdict — it only feeds blast-radius tracing once a finding
        # already exists.
        topology = _extract_topology(text)
        if topology:
            result["topology"] = topology

        confidence = min(0.95, 0.5 + 0.15 * fields_found) if fields_found else 0.20
        result["device"]["parsing_confidence"] = confidence

        # No real decoder runs in mock mode, so there are no real token
        # logprobs. Deriving a plausible mean_logprob from the same
        # fields-found signal as parsing_confidence keeps the active-learning
        # gate in worker.py exercisable under USE_MOCK_SLM=true (the default)
        # without claiming a precision mock logprobs don't have.
        return SLMResult(value=result, mean_logprob=confidence - 1.0)


def _first_match(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _extract_topology(text: str) -> dict[str, Any]:
    """Best-effort interface/adjacency extraction for the GraphRAG topology
    graph. Illustrative, not exhaustive — like the rest of this mock, a
    pattern that doesn't match a given vendor's syntax just means that
    device contributes no topology facts, not a parse failure.
    """
    interfaces: list[dict[str, Any]] = []
    for block in re.finditer(r"(?im)^interface\s+(\S+)\s*\n((?:^[ \t]+.*\n?)*)", text):
        iface: dict[str, Any] = {"name": block.group(1)}
        body = block.group(2)

        ip_match = re.search(r"(?im)^\s*ip\s+address\s+(\S+)\s+(\S+)", body)
        if ip_match:
            iface["ip_address"], iface["subnet_mask"] = ip_match.group(1), ip_match.group(2)

        desc_match = re.search(r"(?im)^\s*description\s+(.+)$", body)
        if desc_match:
            iface["description"] = desc_match.group(1).strip()

        if re.search(r"(?im)^\s*shutdown\s*$", body):
            iface["enabled"] = False

        interfaces.append(iface)

    routing_neighbors: list[dict[str, Any]] = []
    for match in re.finditer(r"(?im)^\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)", text):
        routing_neighbors.append(
            {"protocol": "bgp", "neighbor_ip": match.group(1), "remote_asn": int(match.group(2))}
        )

    local_asn = _first_match(text, r"(?im)^\s*router\s+bgp\s+(\d+)")
    if local_asn:
        for neighbor in routing_neighbors:
            neighbor["local_asn"] = int(local_asn)

    bgp_peers = {n["neighbor_ip"] for n in routing_neighbors}
    for match in re.finditer(r"(?im)^\s*neighbor\s+(\S+)\s*$", text):
        if match.group(1) not in bgp_peers:
            routing_neighbors.append({"protocol": "ospf", "neighbor_ip": match.group(1)})

    topology: dict[str, Any] = {}
    if interfaces:
        topology["interfaces"] = interfaces
    if routing_neighbors:
        topology["routing_neighbors"] = routing_neighbors
    return topology


def _extract_mean_logprob(body: dict[str, Any]) -> float | None:
    """Best-effort extraction of a mean token logprob from an Ollama
    response. Tolerates the field being absent (older/unsupporting server
    versions) as well as either a flat list of floats or a list of
    {"logprob": float} entries, since Ollama's logprobs response shape for
    /api/generate is not yet stable across versions.
    """
    raw = body.get("logprobs")
    if not isinstance(raw, list) or not raw:
        return None

    values: list[float] = []
    for entry in raw:
        if isinstance(entry, (int, float)):
            values.append(float(entry))
        elif isinstance(entry, dict) and isinstance(entry.get("logprob"), (int, float)):
            values.append(float(entry["logprob"]))

    return sum(values) / len(values) if values else None
