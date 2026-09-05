from typing import Any, Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    control_id: str
    framework: str = "CIS"
    title: str
    severity: str
    evidence: str = ""
    remediation: str


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

