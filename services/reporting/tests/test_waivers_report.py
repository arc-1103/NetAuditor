import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import waivers as w
from app.scoring import control_results, summarize

sys.modules.setdefault("weasyprint", types.SimpleNamespace(HTML=object))  # not installed on dev machines
from app import pdf_service  # noqa: E402

NOW = datetime.now(timezone.utc)
KEY = w.device_key("cisco", "edge1")


def waiver(days=20):
    event = {"id": "w1", "audit_run_id": "r", "control_id": "CIS-NET-1.1.2", "event_type": w.GRANTED, "actor": "admin@netaudit.local",
             "created_at": (NOW - timedelta(days=1)).isoformat(),
             "payload": {"waiver_id": "w1", "device_key": KEY, "reason": "Isolated legacy system, mission 4417",
                         "expires_at": (NOW + timedelta(days=days)).isoformat(), "ticket": "CHG-88"}}
    return w.evaluate([event], NOW)


FINDINGS = [
    {"control_id": "CIS-NET-1.1.2", "framework": "CIS", "title": "Telnet on", "severity": "CRITICAL", "evidence": "telnet", "risk_score": 40, "blast_radius": []},
    {"control_id": "CIS-NET-1.8.1", "framework": "CIS", "title": "No syslog", "severity": "MEDIUM", "evidence": "log", "risk_score": 10, "blast_radius": []},
]


def report(findings):
    return {"id": "r", "status": "EVALUATED", "file_hash": "a" * 64, "device": {"vendor": "cisco"}, "security_flags": [],
            "findings": findings, "remediations": []}


def test_the_reporting_copy_is_identical_to_the_compliance_source():
    source = Path(__file__).resolve().parents[2] / "compliance" / "app" / "waivers.py"
    assert source.read_bytes() == Path(w.__file__).read_bytes()


def test_waived_finding_is_listed_with_approver_and_expiry_and_leaves_the_score():
    annotated = w.annotate(FINDINGS, waiver(), KEY)
    counting, waived = w.split(annotated)
    assert summarize(counting)["compliance_score"] > summarize(FINDINGS)["compliance_score"]
    html = pdf_service.render_html(report(annotated))
    assert "Waived Findings (Accepted Risk)" in html and "Isolated legacy system, mission 4417" in html
    assert "admin@netaudit.local" in html and "CHG-88" in html and "WAIVED</b> until" in html
    assert "No remediation is planned while the waiver is in force" in html
    assert "Generate and validate" in html  # the un-waived finding still gets its remediation section


def test_no_waivers_means_no_waiver_section_and_unchanged_behaviour():
    html = pdf_service.render_html(report(w.annotate(FINDINGS, [], KEY)))
    assert "Waived Findings" not in html and "WAIVED" not in html


def test_a_lapsed_waiver_is_explained_and_the_finding_counts_again():
    lapsed = w.annotate(FINDINGS, waiver(days=-3), KEY)
    assert all(f["waiver"] is None for f in lapsed)
    html = pdf_service.render_html(report(lapsed))
    assert "expired" in html and "Waived Findings" not in html


def test_control_results_report_waived_separately_from_fail_and_pass():
    rows = control_results(w.annotate(FINDINGS, waiver(), KEY))
    results = {r["control_id"]: r["result"] for r in rows}
    assert results["CIS-NET-1.1.2"] == "WAIVED" and results["CIS-NET-1.8.1"] == "FAIL" and results["CIS-NET-1.2.2"] == "PASS"
    order = [r["result"] for r in rows]
    assert order.index("FAIL") < order.index("WAIVED") < order.index("PASS")


def test_json_report_carries_the_waivers_and_both_scores():
    data = report(w.annotate(FINDINGS, waiver(), KEY))
    body = pdf_service.build_json_report(data)
    assert len(body["waived"]) == 1 and body["waived"][0]["waiver"]["granted_by"] == "admin@netaudit.local"
    assert body["summary"]["total_findings"] == 1
