from app import pdf_service

RUN_ID = "11111111-1111-1111-1111-111111111111"


def sample_data():
    return {
        "id": RUN_ID, "original_filename": "router.cfg", "file_hash": "a" * 64,
        "status": "EVALUATED", "findings": [{
            "control_id": "CIS-IOS-1.1.1", "framework": "CIS", "title": "SSH v2 required",
            "severity": "HIGH", "evidence": "ssh.version = 1", "risk_score": 20,
            "remediation": "ios_ssh_v2_fix.j2",
        }],
        "remediations": [{
            "control_id": "CIS-IOS-1.1.1", "script": "ip ssh version 2",
            "preflight_status": "SAFE", "risk_flags": [], "approval_status": "APPROVED",
        }],
    }


def test_summary_counts_and_scores():
    summary = pdf_service.summarize(sample_data()["findings"])
    assert summary["compliance_score"] == 80
    assert summary["by_severity"]["HIGH"] == 1


def test_html_contains_evidence_and_approved_script():
    html = pdf_service.render_html(sample_data())
    assert "SSH v2 required" in html
    assert "ssh.version = 1" in html
    assert "ip ssh version 2" in html
    assert "APPROVED" in html


def test_generates_real_pdf(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_service, "OUTPUT_DIR", tmp_path)
    output = pdf_service.generate_pdf(RUN_ID, sample_data())
    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 1000


def test_json_export_is_self_contained_and_machine_readable():
    report = pdf_service.build_json_report(sample_data())
    assert report["schema_version"] == "1.0.0"
    assert report["audit_run"]["file_hash"] == "a" * 64
    assert report["summary"]["compliance_score"] == 80
    assert report["findings"][0]["control_id"] == "CIS-IOS-1.1.1"


def test_cef_export_contains_identity_hash_and_evidence():
    cef = pdf_service.render_cef(sample_data())
    assert cef.startswith("CEF:0|No Talks IC|NetAudit Engine|1.0|")
    assert "CIS-IOS-1.1.1" in cef
    assert "fileHash=" + "a" * 64 in cef
    assert "ssh.version \\= 1" in cef
