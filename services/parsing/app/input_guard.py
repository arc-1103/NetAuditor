"""
Ingress guard for device configuration text, applied before any regex parser
or language model sees it.

Configs are attacker-influenced input (a banner or description can say
anything), and two parser weaknesses follow from that:

* ReDoS — a very long crafted line can make a backtracking regex run for
  minutes. Lines are capped, and context detection runs in a subprocess that
  is killed on a hard deadline (same approach as slm_client.PARSE_TIMEOUT_SECONDS).
* Prompt injection — text such as "ignore previous instructions" inside a MOTD
  banner must never reach the model as an instruction. Matching lines are
  replaced by a neutral comment; line numbers are preserved, so evidence
  locations stay correct, and every change is reported as a security flag.

This narrows the attack surface; it is not a substitute for the container
sandboxing in docker-compose.yml (seccomp, dropped capabilities, read-only
root, resource limits), which limits the damage if a parser is exploited.
"""

import os
import re
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import TimeoutError as ProcessTimeoutError
from typing import Any, Callable

MAX_LINE_CHARS = int(os.getenv("MAX_LINE_CHARS", "2000"))
BOUNDED_TIMEOUT_SECONDS = float(os.getenv("PARSE_TIMEOUT_SECONDS", "5.0"))

# Deliberately simple substring-ish patterns (no nested quantifiers), so the
# guard itself cannot be ReDoSed.
_INJECTION = re.compile(
    r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?)"
    r"|disregard (all |any |the )?(previous|prior|above)"
    r"|you are (now|no longer)"
    r"|system prompt"
    r"|new instructions?:"
    r"|(^|\s)(assistant|system)\s*:"
    r"|</?(s|system|instructions?)>"
    r"|reveal (your|the) (prompt|instructions)"
    r"|output (only )?\{",
    re.IGNORECASE,
)
REDACTION = "! [removed by NetAudit input guard: possible prompt injection]"


class ParseSandboxTimeout(Exception):
    pass


def sanitize_chunks(chunks: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (clean_chunks, flags). Never drops or reorders lines."""
    flags: list[dict[str, Any]] = []
    clean = []
    for chunk in chunks:
        out_lines = []
        for offset, line in enumerate(str(chunk.get("text", "")).split("\n")):
            where = {"chunk": chunk.get("index"), "line_in_chunk": offset + 1}
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
                flags.append({**where, "kind": "line_truncated", "limit": MAX_LINE_CHARS})
            if _INJECTION.search(line):
                flags.append({**where, "kind": "possible_prompt_injection"})
                line = REDACTION
            out_lines.append(line)
        clean.append({**chunk, "text": "\n".join(out_lines)})
    return clean, flags


_executor = ProcessPoolExecutor(max_workers=1)


def _reset_executor() -> None:
    global _executor
    old, _executor = _executor, ProcessPoolExecutor(max_workers=1)
    try:
        for proc in old._processes.values():  # type: ignore[attr-defined]
            proc.kill()
    except Exception:
        pass
    old.shutdown(wait=False, cancel_futures=True)


def run_bounded(fn: Callable[..., Any], *args: Any, timeout: float | None = None) -> Any:
    """Runs a module-level function in a worker process and kills it if it
    overruns. Arguments and result must be picklable."""
    future = _executor.submit(fn, *args)
    try:
        return future.result(timeout or BOUNDED_TIMEOUT_SECONDS)
    except ProcessTimeoutError as exc:
        _reset_executor()
        raise ParseSandboxTimeout(f"{getattr(fn, '__name__', 'parser')} exceeded the hard deadline") from exc
