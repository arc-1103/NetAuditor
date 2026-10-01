from app.scoring import control_results
from app.version_guidance import guidance_for

PASSWORDS = [{"control_id": "CIS-NET-1.5.1", "severity": "HIGH"}]


def notes(version, vendor="cisco", findings=PASSWORDS):
    return guidance_for({"vendor": vendor, "os_version": version}, findings)


def test_newer_release_gets_the_scrypt_note_and_older_gets_the_upgrade_note():
    new = notes("16.9")["CIS-NET-1.5.1"]
    assert len(new) == 1 and "algorithm-type scrypt" in new[0]
    old = notes("12.4(24)T")["CIS-NET-1.5.1"]
    assert len(old) == 1 and "predates scrypt" in old[0]
    assert notes("15.3(3)M")["CIS-NET-1.5.1"][0] == new[0]  # boundary is inclusive of 15.3


def test_unknown_version_shows_no_version_bounded_note():
    assert notes(None) == {}


def test_unversioned_rule_applies_without_a_version_and_only_to_its_vendor():
    ssh = [{"control_id": "CIS-NET-1.1.1"}]
    assert "CIS-NET-1.1.1" in notes(None, findings=ssh)
    assert notes(None, vendor="juniper", findings=ssh) == {}


def test_notes_only_appear_for_failing_controls():
    assert notes("16.9", findings=[{"control_id": "CIS-NET-1.8.1"}]) == {}


def test_control_results_marks_every_control_pass_or_fail():
    rows = control_results(PASSWORDS)
    assert rows[0]["result"] == "FAIL" and rows[0]["control_id"] == "CIS-NET-1.5.1"
    assert sum(r["result"] == "PASS" for r in rows) == len(rows) - 1
