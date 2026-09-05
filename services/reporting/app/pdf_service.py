import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

TEMPLATE_DIR = Path(__file__).parents[1] / "html_templates"
OUTPUT_DIR = Path(os.getenv("PDF_OUTPUT_DIR", "/data/reports"))
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def summarize(findings: list[dict]) -> dict:
    counts = Counter(str(f.get("severity", "")).upper() for f in findings)
    risk = sum(int(f.get("risk_score", 0)) for f in findings)
    return {
        "total_findings": len(findings),
        "by_severity": {level: counts[level] for level in SEVERITY_ORDER},
        "risk_score": risk,
        "compliance_score": max(0, 100 - risk),
    }


def render_html(report_data: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    template = env.get_template("audit_report.html")
    remediations = {item["control_id"]: item for item in report_data.get("remediations", [])}
    return template.render(
        run=report_data,
        findings=report_data.get("findings", []),
        remediations=remediations,
        summary=summarize(report_data.get("findings", [])),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def build_json_report(report_data: dict) -> dict:
    """Machine-readable report suitable for archival or SIEM ingestion."""
    return {
        "schema_version": "1.0.0",
        "product": "NetAudit Engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_run": {
            key: report_data.get(key)
            for key in ("id", "original_filename", "file_hash", "status", "created_at", "updated_at")
        },
        "summary": summarize(report_data.get("findings", [])),
        "findings": report_data.get("findings", []),
        "remediations": report_data.get("remediations", []),
    }


def _cef_escape(value: object) -> str:
    return str(value or "").replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")


def render_cef(report_data: dict) -> str:
    """One CEF event per failed control for ingestion by a local SIEM."""
    severity = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}
    lines = []
    for finding in report_data.get("findings", []):
        control = _cef_escape(finding.get("control_id"))
        title = _cef_escape(finding.get("title"))
        extension = " ".join([
            f"externalId={_cef_escape(report_data.get('id'))}",
            f"fileHash={_cef_escape(report_data.get('file_hash'))}",
            f"cs1={_cef_escape(finding.get('framework'))}", "cs1Label=Framework",
            f"cs2={_cef_escape(finding.get('evidence'))}", "cs2Label=Evidence",
            f"cs3={_cef_escape(finding.get('remediation'))}", "cs3Label=RemediationTemplate",
        ])
        lines.append(
            f"CEF:0|No Talks IC|NetAudit Engine|1.0|{control}|{title}|"
            f"{severity.get(str(finding.get('severity', '')).upper(), 5)}|{extension}"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def generate_pdf(audit_run_id: str, report_data: dict) -> Path:
    safe_id = str(UUID(audit_run_id))
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / f"netaudit-{safe_id}.pdf"
    HTML(string=render_html(report_data), base_url=str(TEMPLATE_DIR)).write_pdf(output)
    return output


if __name__ == "__main__":
    sample_id = "00000000-0000-0000-0000-000000000001"
    path = generate_pdf(sample_id, {"id": sample_id, "original_filename": "demo.cfg", "findings": [], "remediations": []})
    print(path)
