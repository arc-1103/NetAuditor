"""
Presence of this file anchors pytest's import root at services/ingestion/,
so `tests/*.py` can `from app import ...` without installing the package.
"""
import sys
import types

# python-magic wraps libmagic via ctypes; on a dev machine without the
# system library installed (notably Windows without libmagic DLLs on
# PATH), `import magic` itself can hang or fail. Unit tests shouldn't
# depend on that system library being present, so install a stub before
# anything imports app.uploader — individual tests still override
# `magic.from_buffer` per-case via monkeypatch.
if "magic" not in sys.modules:
    fake_magic = types.ModuleType("magic")
    fake_magic.from_buffer = lambda data, mime=False: "text/plain"
    sys.modules["magic"] = fake_magic
