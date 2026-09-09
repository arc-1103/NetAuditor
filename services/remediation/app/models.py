from typing import Any, Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    control_id: str
    framework: str = "CIS"
    title: str
    severity: str
    evidence: str = ""
    # Required but nullable, not defaulted: contracts/compliance_finding.schema.json's
    # `remediation` is always present on a real finding — a string, or
    # explicitly null when the vendor has no committed .j2 template (the
    # agentic RAG fallback in app/rag_remediation.py handles that case). A
    # request that omits this key outright is a malformed/buggy caller, not
    # "no template" — it must be rejected with a 422, not silently defaulted
    # to None and routed into the agentic RAG fallback the caller never
    # asked for.
    remediation: str | None


class GenerateRequest(BaseModel):
    audit_run_id: str
    finding: Finding
    device: dict[str, Any] = Field(default_factory=dict)
    variables: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    approved: bool
    audit_run_id: str | None = None
    comment: str | None = Field(default=None, max_length=1000)


class PreflightResult(BaseModel):
    status: Literal["SAFE", "RISK_FLAGS", "UNAVAILABLE"]
    risk_flags: list[str] = Field(default_factory=list)
    engine: str


class RemediationProposal(BaseModel):
    audit_run_id: str
    control_id: str
    template_name: str
    script: str
    preflight: PreflightResult
    approval_status: Literal["PENDING", "APPROVED", "REJECTED"] = "PENDING"
    # Set only when source == "agentic_rag" — the mandatory inverse script an
    # operator runs if the remediation drops network connectivity. Template
    # proposals have no rollback script; the template itself is trusted,
    # version-controlled CLI, not a synthesized change to revert.
    rollback_script: str | None = None
    # "template": rendered from a version-controlled .j2 file (the default,
    # safety-model-preserving path). "agentic_rag": SLM-synthesized via
    # app/rag_remediation.py, used only when no template exists for this
    # control's vendor.
    source: Literal["template", "agentic_rag"] = "template"

