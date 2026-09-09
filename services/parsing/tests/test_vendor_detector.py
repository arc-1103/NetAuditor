from app.vendor_detector import detect_job_context, detect_vendor


def test_cisco_detection():
    result = detect_vendor("hostname r1\nversion 17.9.3\nip ssh version 2")
    assert result.vendor == "cisco"
    assert result.os == "IOS-XE"
    assert result.raw_hostname == "r1"
    assert result.hardware_model is None


def test_juniper_detection():
    result = detect_vendor("set system host-name edge01\nset system services ssh")
    assert result.vendor == "juniper"


def test_paloalto_detection():
    result = detect_vendor("set deviceconfig system hostname fw01")
    assert result.vendor == "paloalto"


def test_arista_detection():
    result = detect_vendor("! Arista\nmanagement api gnmi")
    assert result.vendor == "arista"


def test_unknown_detection():
    result = detect_vendor("random configuration text")
    assert result.vendor == "unknown"
    assert result.confidence == 0.0


def test_job_level_detection_survives_fingerprint_free_later_chunks():
    chunks = [
        {"index": 0, "text": "hostname EDGE-RTR\nversion 17.9.3\nip ssh version 2"},
        {"index": 1, "text": "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"},
        {"index": 2, "text": "ip access-list extended MGMT\n permit ip any any"},
    ]
    context = detect_job_context(chunks)
    assert context.vendor == "cisco"
    assert context.confidence >= 0.96
    assert context.os == "IOS-XE"
    assert context.raw_hostname == "EDGE-RTR"
    assert context.hardware_model is None
