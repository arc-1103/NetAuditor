"""
Splits a raw config into logical blocks before handoff to Parsing.
Currently a naive fixed-size line splitter. Blueprint Sec 3.1 calls for
an AST-ish/textfsm block-boundary-aware chunker (e.g. splitting on
`interface`/`!` boundaries) instead of a flat line count — that text is
not in this lane's scoped blueprint extract, so it's not implemented yet.
"""

_TRUNCATION_MARKER = "...[truncated]"


def chunk_config(raw_text: str, max_lines: int = 500, max_line_length: int = 2000) -> list[str]:
    # A file within the overall upload size cap (uploader.py's
    # MAX_UPLOAD_SIZE_MB) can still contain one pathologically long single
    # line (e.g. no newlines at all). That line would otherwise land whole
    # inside one chunk and reach every regex pattern in the parser's mock
    # extraction at full length — same threat class as the file-level MB
    # cap, just at line granularity (docs/ArchitecturalChanges.md §3).
    lines = [
        line if len(line) <= max_line_length else line[:max_line_length] + _TRUNCATION_MARKER
        for line in raw_text.splitlines()
    ]
    return ["\n".join(lines[i:i + max_lines]) for i in range(0, len(lines), max_lines)]
