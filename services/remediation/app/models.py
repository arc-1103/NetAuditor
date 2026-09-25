from typing import Any, Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    control_id: str
    framework: str = "CIS"
    title: str
    severity: str
    evidence: str = ""
    # GraphRAG blast radius (services/compliance/app/graph_client.py) —
    # device ids reachable from this finding's device. Passed through by the
    # caller (already present on the finding object GET /audit-runs/{id}
    # returns) rather than re-fetched here, since this service has no
    # topology client of its own.
    #
    # None (not passed) is deliberately distinct from [] (confirmed zero):
    # app/decision.py treats an unknown blast radius as the conservative
    # case, not as "0 reachability changes" — a caller that forgets to pass
    # this must never accidentally make a proposal look more auto-apply-
    # eligible than an honest "we don't know" would.
    blast_radius: list[str] | None = None
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


class Decision(BaseModel):
    """docs/Additional-Features.md §2's classification for this proposal —
    advisory only, see app/decision.py. risk/blast_radius_count are echoed
    back so app/approval_matrix.py (§7) can enforce role permissions
    against the same values this classification used."""
    action: Literal["BLOCK", "DUAL_APPROVAL", "SINGLE_APPROVAL", "AUTO_APPLY"]
    rule_id: str
    ruleset_version: str
    reason: str = ""
    risk: Literal["LOW", "MEDIUM", "HIGH"]
    blast_radius_count: int


class RemediationProposal(BaseModel):
    audit_run_id: str
    control_id: str
    template_name: str
    script: str
    preflight: PreflightResult
    decision: Decision | None = None
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

