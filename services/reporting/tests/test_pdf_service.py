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


def test_html_flags_agentic_rag_remediation_and_shows_rollback():
    """A machine-synthesized proposal must never look like a reviewed
    template in the report — see the safety design in
    services/remediation/app/main.py and README.md."""
    data = sample_data()
    data["remediations"][0].update(
        source="agentic_rag",
        rollback_script="no ip ssh version 2",
        preflight_status="RISK_FLAGS",
        approval_status="PENDING",
    )
    html = pdf_service.render_html(data)

    assert "AI-synthesized remediation" in html
    assert "no ip ssh version 2" in html


def test_html_does_not_flag_a_template_remediation_as_ai_synthesized():
    html = pdf_service.render_html(sample_data())
    assert "AI-synthesized remediation" not in html


def test_html_shows_blast_radius_device_count():
    data = sample_data()
    data["findings"][0]["blast_radius"] = ["b" * 64, "c" * 64]
    html = pdf_service.render_html(data)
    assert "2 device(s)" in html


def test_integrity_section_does_not_make_a_blanket_no_ai_claim():
    """The report must not claim every remediation came from a
    version-controlled template once the agentic RAG fallback exists."""
    html = pdf_service.render_html(sample_data())
    assert "AI does not decide compliance or generate free-form device commands" not in html


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
