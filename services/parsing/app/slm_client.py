from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .models import DeviceContext


class SLMError(RuntimeError):
    pass


class SLMTimeout(SLMError):
    pass


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
    ) -> dict[str, Any]:
        if self.mock:
            return self._mock_response(config_text, device_context)

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0},
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
        return value

    def _mock_response(self, text: str, context: DeviceContext) -> dict[str, Any]:
        """Deterministic extraction of only facts observable in this chunk."""
        lower = text.lower()
        result: dict[str, Any] = {
            "schema_version": "1.0.0",
            "device": {
                "detected_vendor": context.vendor,
                "detected_os": context.os,
                "detected_os_version": context.os_version,
                "detected_hardware_model": context.hardware_model,
                "parsing_confidence": 0.85 if context.vendor != "unknown" else 0.20,
            },
        }

        hostname = _first_match(text, r"(?im)^\s*hostname\s+(\S+)")
        if hostname:
            result["device"]["raw_hostname"] = hostname
        elif context.vendor == "juniper":
            hostname = _first_match(text, r"(?im)^\s*set\s+system\s+host-name\s+(\S+)")
            if hostname:
                result["device"]["raw_hostname"] = hostname
        elif context.vendor == "paloalto":
            hostname = _first_match(text, r"(?im)^\s*set\s+deviceconfig\s+system\s+hostname\s+(\S+)")
            if hostname:
                result["device"]["raw_hostname"] = hostname

        ssh_version = _first_match(text, r"(?im)^\s*ip\s+ssh\s+version\s+([12])\s*$")
        if ssh_version:
            result["ssh"] = {"enabled": True, "version": ssh_version}

        if re.search(r"(?im)^\s*no\s+transport\s+input\s+telnet\b", text):
            result["telnet"] = {"enabled": "DISABLED"}
        elif re.search(r"(?im)^\s*transport\s+input\s+telnet\b", text):
            result["telnet"] = {"enabled": "ENABLED"}

        if re.search(r"(?im)^\s*service\s+password-encryption\b", text):
            result["aaa"] = {"password_encryption": "ENABLED"}

        if re.search(r"(?im)^\s*no\s+ip\s+http\s+server\b", text):
            result["services"] = {"http_server_enabled": "DISABLED"}
        elif re.search(r"(?im)^\s*ip\s+http\s+server\b", text):
            result["services"] = {"http_server_enabled": "ENABLED"}

        if re.search(r"(?im)^\s*logging\s+host\s+(\S+)", text):
            hosts = re.findall(r"(?im)^\s*logging\s+host\s+(\S+)", text)
            result["logging"] = {"syslog_enabled": True, "syslog_hosts": hosts}

        if re.search(r"(?im)^\s*ntp\s+server\s+(\S+)", text):
            servers = re.findall(r"(?im)^\s*ntp\s+server\s+(\S+)", text)
            result["ntp"] = {"enabled": True, "servers": servers}
            if re.search(r"(?im)^\s*ntp\s+authenticate\b", text):
                result["ntp"]["authentication_enabled"] = True

        if re.search(r"(?im)^\s*banner\s+login\b", text):
            result["banners"] = {"login_banner_present": True}

        return result


def _first_match(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None
