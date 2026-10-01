from app.device_identity import extract_identity
from app.vendor_detector import detect_vendor


def test_cisco_udi_line_gives_model_and_serial():
    text = "hostname edge\nlicense udi pid C9300-24T sn FCW2233L0AB\nip ssh version 2\n"
    identity = extract_identity(text)
    assert identity["hardware_model"] == "C9300-24T" and identity["serial_number"] == "FCW2233L0AB"


def test_fortios_header_gives_model_and_version():
    text = "#config-version=FGT60F-7.2.5-FW-build1517-230213:opmode=0:vdom=0\nconfig system global\n set hostname fw1\nend\n"
    identity = extract_identity(text)
    assert identity["hardware_model"] == "FGT60F" and identity["header_version"] == "7.2.5"
    detection = detect_vendor(text)
    assert detection.vendor == "fortinet" and detection.os_version == "7.2.5" and detection.hardware_model == "FGT60F"


def test_generic_serial_and_model_lines():
    text = "! Serial Number: JN12345ABC\n! Model: MX204\nset system host-name r1\n"
    identity = extract_identity(text)
    assert identity["serial_number"] == "JN12345ABC" and identity["hardware_model"] == "MX204"


def test_absent_identity_is_none_not_guessed():
    assert extract_identity("hostname r1\nip ssh version 2\n") == {"hardware_model": None, "serial_number": None, "header_version": None}


def test_serial_reaches_the_device_context():
    from app.vendor_detector import detect_job_context
    context = detect_job_context([{"index": 0, "text": "version 15.2\nhostname r1\nlicense udi pid ISR4331 sn FDO1234ABCD\nip ssh version 2\n"}])
    assert context.serial_number == "FDO1234ABCD" and context.hardware_model == "ISR4331"
