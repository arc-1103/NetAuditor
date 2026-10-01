"""Rule-based guardrails for the RAG path: sanitize queries, quarantine
retrieved documents, and check generated output.

What this is, honestly: pattern rules, not an LLM safety classifier. It is not
NeMo Guardrails or Llama Guard (each needs its own model and, for an
air-gapped site, a second download). The rules catch the common, blunt
attacks; they cannot catch a paraphrase they have never seen. They are one
layer next to the structural defences: the model's output is schema-validated
JSON, OPA (not the model) decides every verdict, and agentic-RAG fixes are
never approvable.

The patterns are plain alternations with no nested quantifiers, so the guard
cannot itself be ReDoSed. `services/remediation/app/guardrails.py` is an
identical copy (a test enforces it).
"""
import re

_INJECTION = re.compile(
    r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?)"
    r"|disregard (all |any |the )?(previous|prior|above)"
    r"|you are (now|no longer)"
    r"|system prompt"
    r"|new instructions?:"
    r"|(^|\s)(assistant|system)\s*:"
    r"|</?(s|system|instructions?)>"
    r"|reveal (your|the) (prompt|instructions)"
    r"|(output|print|send|leak|exfiltrate|dump) (all |any |the |your )?(system )?(credentials|passwords?|secrets?|api keys?|tokens?|private keys?)"
    r"|output (only )?\{",
    re.IGNORECASE,
)

# Generated CLI must never pull data off the box or carry key material.
_EXFIL = re.compile(
    r"\b(curl|wget|tftp|scp|sftp|ftp|nc|ncat)\b[^\n]*(://|\b\d{1,3}(\.\d{1,3}){3}\b)"
    r"|copy (running|startup)-config (tftp|ftp|scp|http)"
    r"|BEGIN [A-Z ]*PRIVATE KEY",
    re.IGNORECASE,
)

REDACTED = "[removed by NetAudit guardrail]"
MAX_QUERY_CHARS = 8000


def injection_hits(text: str) -> list[str]:
    return [m.group(0).strip() for m in _INJECTION.finditer(text or "")]


def sanitize_query(text: str) -> tuple[str, list[str]]:
    """Returns (clean_text, flags). Matching phrases are replaced; nothing else changes."""
    text = (text or "")[:MAX_QUERY_CHARS]
    hits = injection_hits(text)
    return _INJECTION.sub(REDACTED, text), [f"query injection pattern removed: {h!r}" for h in hits]


def quarantine(results: dict) -> tuple[dict, int]:
    """Drop every retrieved document (or one whose metadata) carries an
    injection pattern. Returns (results, number quarantined). A poisoned
    mapping is withheld whole rather than edited, since an edited
    instruction is still attacker-shaped."""
    ids = (results.get("ids") or [[]])[0]
    docs = (results.get("documents") or [[]])[0]
    metas = (results.get("metadatas") or [[None] * len(ids)])[0]
    keep = [
        i for i in range(len(ids))
        if not injection_hits(docs[i] if i < len(docs) else "")
        and not any(injection_hits(str(v)) for v in (metas[i] or {}).values())
    ]
    if len(keep) == len(ids):
        return results, 0
    out = dict(results)
    for key in ("ids", "documents", "metadatas", "distances", "fusion_scores", "rerank_scores"):
        if results.get(key):
            out[key] = [[results[key][0][i] for i in keep]]
    return out, len(ids) - len(keep)


def check_output(text: str) -> list[str]:
    """Reasons generated text must not be shown as a fix. Empty = clean."""
    reasons = [f"injection text in output: {h!r}" for h in injection_hits(text)]
    reasons += [f"data-exfiltration pattern in output: {m.group(0)[:60]!r}" for m in _EXFIL.finditer(text or "")]
    return reasons
