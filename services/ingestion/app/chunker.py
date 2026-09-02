"""
Splits a raw config into logical blocks before handoff to Parsing.
Currently a naive fixed-size line splitter. Blueprint Sec 3.1 calls for
an AST-ish/textfsm block-boundary-aware chunker (e.g. splitting on
`interface`/`!` boundaries) instead of a flat line count — that text is
not in this lane's scoped blueprint extract, so it's not implemented yet.
"""

def chunk_config(raw_text: str, max_lines: int = 500) -> list[str]:
    lines = raw_text.splitlines()
    return ["\n".join(lines[i:i + max_lines]) for i in range(0, len(lines), max_lines)]
