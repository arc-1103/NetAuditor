import pytest

from app.models import DeviceContext
from app.slm_client import OllamaSLMClient, SLMError


@pytest.mark.asyncio
async def test_mock_slm_uses_job_vendor_context_and_does_not_invent_cisco():
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("cisco", "IOS-XE", "17.9.3", None, None, 0.96)
    result = await client.generate(
        "prompt",
        "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0",
        {},
        device_context=context,
    )
    assert result.value["device"]["detected_vendor"] == "cisco"
    assert result.value["device"]["detected_os"] == "IOS-XE"
    assert "ssh" not in result.value


@pytest.mark.asyncio
async def test_mock_slm_extracts_fields_regardless_of_recognized_vendor():
    """Extraction patterns are no longer gated on context.vendor — an
    unrecognized vendor that still matches known syntax should get credit
    for it, since a real SLM doesn't need the vendor's name to read
    "set system host-name" or "ip ssh version 2"."""
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("unknown", None, None, None, None, 0.0)
    result = await client.generate(
        "prompt",
        "set system host-name edge01\nip ssh version 2\nbanner login\n",
        {},
        device_context=context,
    )

    assert result.value["device"]["raw_hostname"] == "edge01"
    assert result.value["ssh"] == {"enabled": True, "version": "2"}
    assert result.value["banners"] == {"login_banner_present": True}
    assert result.value["device"]["parsing_confidence"] > 0.5
    assert result.mean_logprob == result.value["device"]["parsing_confidence"] - 1.0


@pytest.mark.asyncio
async def test_mock_slm_confidence_reflects_fields_found_not_vendor_name():
    client = OllamaSLMClient("http://unused", "model", mock=True)
    known_vendor_empty_chunk = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate(
        "prompt",
        "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0",
        {},
        device_context=known_vendor_empty_chunk,
    )

    assert result.value["device"]["parsing_confidence"] == 0.20
    assert result.mean_logprob == pytest.approx(-0.80)


@pytest.mark.asyncio
async def test_mock_slm_extracts_topology_without_counting_it_as_a_compliance_field():
    """GraphRAG topology facts (interfaces, routing neighbors) are extracted
    for the graph, but must not move parsing_confidence — that score gates
    the CIS/NIST/STIG compliance verdict, which topology has no bearing on."""
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate(
        "prompt",
        "interface GigabitEthernet0/0\n"
        " description uplink to core\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        "router bgp 65000\n"
        " neighbor 10.0.0.2 remote-as 65001\n",
        {},
        device_context=context,
    )

    interfaces = result.value["topology"]["interfaces"]
    assert interfaces == [
        {
            "name": "GigabitEthernet0/0",
            "ip_address": "10.0.0.1",
            "subnet_mask": "255.255.255.0",
            "description": "uplink to core",
        }
    ]
    assert result.value["topology"]["routing_neighbors"] == [
        {"protocol": "bgp", "neighbor_ip": "10.0.0.2", "remote_asn": 65001, "local_asn": 65000}
    ]
    # Same fields_found (0) as the plain interface+ip chunk above — topology
    # extraction is not a compliance field.
    assert result.value["device"]["parsing_confidence"] == 0.20


@pytest.mark.asyncio
async def test_mock_slm_omits_topology_key_when_nothing_found():
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate("prompt", "hostname edge01\n", {}, device_context=context)

    assert "topology" not in result.value


@pytest.mark.asyncio
async def test_invalid_ollama_response(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "not json"}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("app.slm_client.httpx.AsyncClient", FakeClient)
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    with pytest.raises(SLMError):
        await client.generate("prompt", "config", {}, device_context=context)


def _fake_ollama_client(monkeypatch, response_body: dict):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return response_body

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("app.slm_client.httpx.AsyncClient", FakeClient)


@pytest.mark.asyncio
async def test_generate_extracts_mean_logprob_when_backend_reports_it(monkeypatch):
    _fake_ollama_client(
        monkeypatch,
        {
            "response": '{"schema_version": "1.0.0", "device": {"parsing_confidence": 0.9}}',
            "logprobs": [{"logprob": -0.1}, {"logprob": -0.3}, -0.2],
        },
    )
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate("prompt", "config", {}, device_context=context)
    assert result.mean_logprob == pytest.approx(-0.2)


@pytest.mark.asyncio
async def test_generate_mean_logprob_is_none_when_backend_omits_it(monkeypatch):
    """An Ollama version that doesn't report logprobs must not be treated as
    low confidence — no signal is not the same as a bad signal."""
    _fake_ollama_client(
        monkeypatch,
        {"response": '{"schema_version": "1.0.0", "device": {"parsing_confidence": 0.9}}'},
    )
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    result = await client.generate("prompt", "config", {}, device_context=context)
    assert result.mean_logprob is None


# ── reverse_translate (Agent B of multi-agent reverse translation) ───
@pytest.mark.asyncio
async def test_mock_reverse_translate_inverts_the_mock_forward_extraction():
    """The mock round trip must be internally consistent: what the mock
    reverse-translates from a candidate must be recoverable by the mock
    forward extractor again, so the fidelity gate is exercisable under
    USE_MOCK_SLM=true without a real model."""
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)
    candidate = {
        "device": {"raw_hostname": "EDGE-RTR"},
        "ssh": {"enabled": True, "version": "2"},
        "telnet": {"enabled": "DISABLED"},
        "banners": {"login_banner_present": True},
    }

    reconstructed_cli = await client.reverse_translate(candidate, context)
    roundtrip = await client.generate("prompt", reconstructed_cli, {}, device_context=context)

    assert roundtrip.value["device"]["raw_hostname"] == "EDGE-RTR"
    assert roundtrip.value["ssh"] == {"enabled": True, "version": "2"}
    assert roundtrip.value["telnet"] == {"enabled": "DISABLED"}
    assert roundtrip.value["banners"] == {"login_banner_present": True}


@pytest.mark.asyncio
async def test_mock_reverse_translate_produces_nothing_for_an_empty_candidate():
    client = OllamaSLMClient("http://unused", "model", mock=True)
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)

    assert await client.reverse_translate({"device": {}}, context) == ""


@pytest.mark.asyncio
async def test_reverse_translate_parses_the_ollama_response(monkeypatch):
    _fake_ollama_client(
        monkeypatch,
        {"response": '{"reconstructed_cli": "ip ssh version 2\\nno transport input telnet"}'},
    )
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)

    cli = await client.reverse_translate({"ssh": {"enabled": True, "version": "2"}}, context)

    assert cli == "ip ssh version 2\nno transport input telnet"


@pytest.mark.asyncio
async def test_reverse_translate_rejects_a_response_missing_reconstructed_cli(monkeypatch):
    _fake_ollama_client(monkeypatch, {"response": "{}"})
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)

    with pytest.raises(SLMError):
        await client.reverse_translate({"ssh": {"enabled": True}}, context)


@pytest.mark.asyncio
async def test_reverse_translate_rejects_non_json_response(monkeypatch):
    _fake_ollama_client(monkeypatch, {"response": "not json"})
    client = OllamaSLMClient("http://ollama", "model")
    context = DeviceContext("cisco", "IOS-XE", None, None, None, 0.96)

    with pytest.raises(SLMError):
        await client.reverse_translate({"ssh": {"enabled": True}}, context)
