"""
Agentic RAG remediation fallback.

Used by app/main.py's POST /remediation/generate only when a compliance
finding's `remediation` field is null — the vendor has no committed .j2
template (services/compliance/policies/generic/generic_level1.rego's
`remediation_templates` table has no row for it). Every finding WITH a
template stays on the deterministic app/template_engine.py path unchanged;
this module never touches that path, per the service's safety model — see
README.md.

Flow:
  1. Remediation Index Query — look up vendor manual excerpts indexed under
     this exact [control_id, vendor, OS] key (app/manual_provider.py).
  2. Contextual CLI Synthesis — feed whatever excerpts came back to the SLM
     as grounding context (app/slm_client.py).
  3. Rollback Generation — require the SLM to return both the remediation
     CLI and an inverse rollback script.

`RemediationResult.grounded` is False when no manual context was found —
app/main.py turns that, and a missing rollback_cli, into a mandatory
RISK_FLAGS preflight result rather than SAFE, so an ungrounded or
rollback-less synthesis can never look safer than it is.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.manual_provider import RemediationManualProvider
from app.slm_client import OllamaSLMClient, SLMError


class RemediationSynthesisError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemediationResult:
    remediation_cli: str
    unified_diff: str
    rollback_cli: str
    grounded: bool


def _build_prompt(
    vendor: str,
    os_name: str | None,
    control_id: str,
    title: str,
    evidence: str,
    manual_context: list[str],
) -> str:
    context_block = "\n\n".join(manual_context) if manual_context else "(no vendor manual excerpt found)"
    return (
        "You are a network remediation assistant. Given a failed compliance "
        "control and vendor manual context, produce the CLI commands that "
        "fix it, a unified diff of the configuration change, and a mandatory "
        "rollback script that reverts the device to its pre-remediation "
        "state if applying this change drops network connectivity.\n\n"
        f"Vendor: {vendor}\n"
        f"OS: {os_name or 'unknown'}\n"
        f"Control: {control_id} - {title}\n"
        f"Evidence: {evidence}\n\n"
        f"Vendor manual context:\n{context_block}\n\n"
        "Respond with remediation_cli, unified_diff, and rollback_cli."
    )


async def synthesize_remediation(
    *,
    vendor: str,
    os_name: str | None,
    control_id: str,
    title: str,
    evidence: str,
    manual_provider: RemediationManualProvider,
    slm_client: OllamaSLMClient,
) -> RemediationResult:
    manual_context = await manual_provider.lookup(vendor, os_name, control_id)
    prompt = _build_prompt(vendor, os_name, control_id, title, evidence, manual_context)

    try:
        raw = await slm_client.synthesize(prompt)
    except SLMError as exc:
        raise RemediationSynthesisError(str(exc)) from exc

    remediation_cli = str(raw.get("remediation_cli") or "").strip()
    if not remediation_cli:
        raise RemediationSynthesisError("SLM did not produce a remediation_cli")

    return RemediationResult(
        remediation_cli=remediation_cli,
        unified_diff=str(raw.get("unified_diff") or "").strip(),
        rollback_cli=str(raw.get("rollback_cli") or "").strip(),
        grounded=bool(manual_context),
    )
