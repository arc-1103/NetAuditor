"""Unit tests for app.chunker's fixed-size line splitter."""
from app.chunker import chunk_config


def test_splits_into_blocks_of_max_lines():
    text = "\n".join(f"line{i}" for i in range(1250))

    chunks = chunk_config(text, max_lines=500)

    assert len(chunks) == 3
    assert chunks[0].splitlines()[0] == "line0"
    assert chunks[0].splitlines()[-1] == "line499"
    assert chunks[1].splitlines()[0] == "line500"
    assert chunks[2].splitlines() == [f"line{i}" for i in range(1000, 1250)]


def test_exact_multiple_of_max_lines_has_no_trailing_empty_block():
    text = "\n".join(f"line{i}" for i in range(1000))

    chunks = chunk_config(text, max_lines=500)

    assert len(chunks) == 2


def test_empty_input_yields_no_blocks():
    assert chunk_config("", max_lines=500) == []


def test_default_max_lines_is_500():
    text = "\n".join(f"line{i}" for i in range(501))

    chunks = chunk_config(text)

    assert len(chunks) == 2
