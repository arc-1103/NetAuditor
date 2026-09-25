"""
AI Interpretation Trust Layer — docs/Suggestions.md item 7, docs/action.md
Phase 3.

Composes the per-field "SLM says X, TextFSM says Y, do they agree" view the
doc's own mockup shows, entirely from data Phase 1/2 already persisted: the
SLM's full merged baseline (audit_runs.baseline_snapshot) and the
deterministic cross-check's partial extraction
(audit_runs.deterministic_baseline — services/parsing's
app/deterministic_extractor.py output). No new comparison logic beyond a
plain field-by-field diff — a read/reshape view, the same style as
app/main.py's existing /provenance composition.

Silent on any field the deterministic extractor abstained on — same "no
signal is not a wrong answer" rule that module itself follows, so a vendor
this cross-check doesn't cover yet returns an empty `fields` list, not a
false wall of disagreements.
"""

import json
from typing import Any


def _flatten(data: dict, prefix: str = "") -> dict[str, Any]:
    """Nested dict -> {dotted.path: value}. List values are kept whole
    (not descended into) since a list of ACL entries/IKE policies doesn't
    map onto a single scalar "field" the way ssh.version does."""
    flat: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def _values_agree(slm_value: Any, deterministic_value: Any) -> bool:
    if isinstance(deterministic_value, list) and isinstance(slm_value, list):
        # Order-independent, key-order-independent — canonical JSON per
        # item, compared as sets, same reasoning as
        # services/parsing/app/reverse_translation.py's leaf-fact diff.
        to_set = lambda items: {json.dumps(item, sort_keys=True) for item in items}
        return to_set(slm_value) == to_set(deterministic_value)
    return slm_value == deterministic_value


def build_trust_view(slm_baseline: dict | None, deterministic_baseline: dict | None, parser_agreement: float | None) -> dict:
    """slm_baseline: audit_runs.baseline_snapshot. deterministic_baseline:
    audit_runs.deterministic_baseline (possibly None/{} — an unsupported
    vendor, or the cross-check disabled)."""
    slm_flat = _flatten(slm_baseline or {})
    det_flat = _flatten(deterministic_baseline or {})

    fields = []
    for path in sorted(det_flat):
        deterministic_value = det_flat[path]
        slm_value = slm_flat.get(path)
        agree = _values_agree(slm_value, deterministic_value)
        fields.append({
            "field": path,
            "slm_value": slm_value,
            "deterministic_value": deterministic_value,
            "agree": agree,
            "source": "agreement" if agree else "disagreement",
        })

    return {
        "parser_agreement": parser_agreement,
        "fields_compared": len(fields),
        "fields": fields,
    }
