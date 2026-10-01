"""
Merkle tree over ledger events (SHA-256, domain-separated).

leaf = H(0x00 || event bytes), node = H(0x01 || left || right). An odd node at
a level is promoted unchanged, and the leaf count is committed in the signed
seal header, so a verifier knows the exact tree shape.
"""

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt = [_node(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
        if len(current) % 2:
            nxt.append(current[-1])
        levels.append(nxt)
    return levels


def root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError("A Merkle tree needs at least one leaf")
    return _levels(leaves)[-1][0]


def proof(leaves: list[bytes], index: int) -> list[dict]:
    """Sibling hashes from leaf to root: [{"hash": hex, "side": "left"|"right"}]."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    steps = []
    for level in _levels(leaves)[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            steps.append({"hash": level[sibling].hex(), "side": "left" if sibling < index else "right"})
        index //= 2
    return steps


def verify_proof(leaf: bytes, steps: list[dict], expected_root: bytes) -> bool:
    current = leaf
    for step in steps:
        sibling = bytes.fromhex(step["hash"])
        current = _node(sibling, current) if step["side"] == "left" else _node(current, sibling)
    return current == expected_root
