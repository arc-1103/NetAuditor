"""
Splits a raw config into chunks for Parsing, along the config's own
indentation hierarchy instead of a flat line count.

A block is a column-0 line plus every indented line under it (an `interface`
and its `ip access-group`, a Fortinet `config ... end` with its `edit`s). A
block is never cut across two chunks, so a child command always reaches the
model, and the Learning queue's embedding, together with its parent. A block
larger than `max_lines` is split at its next indent level and the parent
header line is repeated at the top of every piece.

It needs no vendor knowledge: only indentation. A config with no indentation
(every line is its own block) chunks exactly like the old fixed-size splitter.
"""

_TRUNCATION_MARKER = "...[truncated]"
# Column-0 lines that close the block above rather than open a new one.
_TERMINATORS = {"!", "#", "exit", "end", "quit", "}", "exit-address-family"}
_MAX_SECTIONS = 10


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _blocks(lines: list[str]) -> list[list[str]]:
    blocks: list[list[str]] = []
    for line in lines:
        starts_block = line.strip() and _indent(line) == 0 and line.strip() not in _TERMINATORS
        if starts_block or not blocks:
            blocks.append([line])
        else:
            blocks[-1].append(line)
    return blocks


def _split_block(block: list[str], max_lines: int) -> list[list[str]]:
    """Pieces of an oversized block, each led by the repeated parent header."""
    header, body = block[0], block[1:]
    room = max(1, max_lines - 1)
    indents = [_indent(line) for line in body if line.strip()]
    child_indent = min(indents) if indents else 0
    units: list[list[str]] = []
    for line in body:
        if line.strip() and _indent(line) == child_indent or not units:
            units.append([line])
        else:
            units[-1].append(line)
    pieces: list[list[str]] = []
    current: list[str] = []
    for unit in units:
        # a single child still too big is cut by lines; the header still leads each cut
        for start in range(0, len(unit), room) if len(unit) > room else [0]:
            part = unit[start:start + room]
            if current and len(current) + len(part) > room:
                pieces.append([header] + current)
                current = []
            current += part
    if current:
        pieces.append([header] + current)
    return pieces


def chunk_hierarchical(raw_text: str, max_lines: int = 500, max_line_length: int = 2000) -> list[dict]:
    """[{"text": str, "sections": [top-level header lines in the chunk]}]"""
    # A single pathologically long line would otherwise reach every regex in
    # the parser at full length (docs/ArchitecturalChanges.md §3).
    lines = [
        line if len(line) <= max_line_length else line[:max_line_length] + _TRUNCATION_MARKER
        for line in raw_text.splitlines()
    ]
    groups: list[list[list[str]]] = []  # chunks, each a list of blocks
    current: list[list[str]] = []
    size = 0
    for block in _blocks(lines):
        for piece in _split_block(block, max_lines) if len(block) > max_lines else [block]:
            if current and size + len(piece) > max_lines:
                groups.append(current)
                current, size = [], 0
            current.append(piece)
            size += len(piece)
    if current:
        groups.append(current)
    return [
        {
            "text": "\n".join(line for block in group for line in block),
            "sections": [b[0].strip() for b in group if b[0].strip() and b[0].strip() not in _TERMINATORS][:_MAX_SECTIONS],
        }
        for group in groups
    ]


def chunk_config(raw_text: str, max_lines: int = 500, max_line_length: int = 2000) -> list[str]:
    return [c["text"] for c in chunk_hierarchical(raw_text, max_lines, max_line_length)]
