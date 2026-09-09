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
