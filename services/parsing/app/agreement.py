"""
Deterministic-vs-SLM agreement scoring — docs/action.md Phase 2, building
docs/Suggestions.md item 7's "Agreement: 98%" per-field trust signal.

Compares the SLM's final merged baseline against
app/deterministic_extractor.py's independent partial extraction, field by
field, reusing app/reverse_translation.py's leaf_facts() flattening — the
same "diff two SecurityBaseline-shaped structures fact by fact" job that
module already does for its own round-trip fidelity check, so this is one
diffing approach with two callers, not two that could drift apart.

Only fields the deterministic extractor actually returned a value for are
compared — its own "no signal" abstentions (see its module docstring)
never count as disagreements, and never inflate or deflate the score
either way. That's what makes `agreement` distinct from `parsing_confidence`
(the SLM's own self-reported number, see app/worker.py): this is an
external check against an independent source, silent on anything that
source didn't observe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.reverse_translation import leaf_facts


@dataclass
class AgreementResult:
    # None (not 0.0) means "no comparison was possible" — the deterministic
    # extractor abstained on every field for this job (unsupported vendor
    # or a config with none of its scoped fields present). Distinct from
    # 0.0, which means "we compared N fields and none of them matched."
    agreement: float | None
    compared_fields: int
    agreed_fields: int
    disagreements: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "agreement": self.agreement,
            "compared_fields": self.compared_fields,
            "agreed_fields": self.agreed_fields,
            "disagreements": self.disagreements,
        }


def compute_agreement(slm_baseline: dict[str, Any], deterministic_partial: dict[str, Any]) -> AgreementResult:
    """slm_baseline: the SLM's merged baseline for the job (or a single
    chunk's candidate). deterministic_partial: app.deterministic_extractor's
    output — a partial SecurityBaseline-shaped dict, possibly `{}`.
    """
    deterministic_facts = leaf_facts(deterministic_partial)
    if not deterministic_facts:
        return AgreementResult(agreement=None, compared_fields=0, agreed_fields=0)

    slm_facts = leaf_facts(slm_baseline)
    agreed_facts = deterministic_facts & slm_facts
    # "deterministic:" prefix distinguishes these from merge.py's existing
    # same-SLM chunk-disagreement conflict paths in the shared conflicts list
    # (see app/worker.py's wiring) — one list, two distinguishable sources.
    disagreements = sorted(f"deterministic:{path}" for path, _value in (deterministic_facts - slm_facts))

    compared = len(deterministic_facts)
    agreed = len(agreed_facts)
    return AgreementResult(
        agreement=agreed / compared,
        compared_fields=compared,
        agreed_fields=agreed,
        disagreements=disagreements,
    )
