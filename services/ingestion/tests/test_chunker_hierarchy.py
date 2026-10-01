"""Hierarchical chunking: a child command never leaves its parent block."""
from app.chunker import chunk_hierarchical


def cfg(n_acl):
    return "hostname r1\n!\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n" + "".join(
        f" ip access-group RULE{i} in\n" for i in range(n_acl)) + "!\ninterface Gi0/2\n shutdown\n!\n"


def test_acl_line_stays_with_its_interface_across_a_size_boundary():
    # flat splitting at 6 lines would cut Gi0/1 after its address line
    chunks = chunk_hierarchical(cfg(3), max_lines=6)
    for c in chunks:
        lines = c["text"].splitlines()
        for i, line in enumerate(lines):
            if line.startswith(" ip access-group"):
                assert any(l.startswith("interface Gi0/1") for l in lines[:i])


def test_blocks_are_never_split_when_they_fit():
    chunks = chunk_hierarchical(cfg(2), max_lines=6)
    assert sum(c["text"].count("interface Gi0/2") for c in chunks) == 1
    gi1 = next(c for c in chunks if "interface Gi0/1" in c["text"])
    assert "RULE0" in gi1["text"] and "RULE1" in gi1["text"]


def test_oversized_block_repeats_its_parent_header_in_every_piece():
    chunks = chunk_hierarchical(cfg(10), max_lines=5)
    pieces = [c for c in chunks if "access-group" in c["text"]]
    assert len(pieces) > 1
    assert all(c["text"].splitlines()[0] == "interface Gi0/1" for c in pieces)
    assert all(len(c["text"].splitlines()) <= 5 for c in chunks)
    joined = "\n".join(c["text"] for c in pieces)
    assert all(f"RULE{i} in" in joined for i in range(10))  # nothing lost


def test_sections_list_the_top_level_headers():
    chunks = chunk_hierarchical(cfg(1), max_lines=500)
    assert chunks[0]["sections"] == ["hostname r1", "interface Gi0/1", "interface Gi0/2"]


def test_fortinet_style_config_end_blocks_stay_whole():
    text = "config system interface\n    edit port1\n        set allowaccess http\n    next\nend\nconfig system ntp\n    set ntpsync enable\nend\n"
    chunks = chunk_hierarchical(text, max_lines=5)
    assert len(chunks) == 2
    assert chunks[0]["text"].startswith("config system interface") and chunks[0]["text"].endswith("end")


def test_unindented_config_chunks_like_the_old_flat_splitter():
    text = "\n".join(f"set line{i}" for i in range(1250))
    assert [len(c["text"].splitlines()) for c in chunk_hierarchical(text, max_lines=500)] == [500, 500, 250]
