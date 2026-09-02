"""
Tests for scripts/check_env.sh. It's a bash script, so these drive it via
subprocess against a scratch directory built to mimic the parts of the
repo layout it inspects (root .env.example/.env, gateway/, services/*/,
frontend/) rather than touching the real repo's env files.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = (Path(__file__).parent.parent / "check_env.sh").resolve()

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH")


def run_check_env(repo_root: Path) -> subprocess.CompletedProcess:
    # check_env.sh prints UTF-8 (including ✅/❌); force that decoding
    # explicitly rather than relying on the platform's default locale
    # codec (cp1252 on Windows, which can't decode those bytes).
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )


def write(path: Path, content: str) -> None:
    # bash reads these files raw; Path.write_text's default newline
    # translation turns \n into \r\n on Windows, which the script's
    # `read` loop doesn't strip. Force LF so fixtures behave like the
    # checked-out-on-Linux files check_env.sh actually expects.
    path.write_text(content, newline="\n")


def scaffold(repo_root: Path) -> None:
    (repo_root / "gateway").mkdir(parents=True)
    (repo_root / "frontend").mkdir(parents=True)
    (repo_root / "services" / "ingestion").mkdir(parents=True)

    write(repo_root / ".env.example", "FOO=1\nBAR=2\n")
    write(repo_root / "gateway" / ".env.example", "JWT_SECRET=changeme\n")
    write(repo_root / "frontend" / ".env.local.example", "NEXT_PUBLIC_USE_MOCK_API=true\n")
    write(repo_root / "services" / "ingestion" / ".env.example", "MAX_UPLOAD_SIZE_MB=10\n")


@pytest.fixture
def repo_root(tmp_path):
    scaffold(tmp_path)
    return tmp_path


def test_passes_when_every_env_file_present_and_in_sync(repo_root):
    write(repo_root / ".env", "FOO=1\nBAR=2\n")
    write(repo_root / "gateway" / ".env", "JWT_SECRET=changeme\n")
    write(repo_root / "frontend" / ".env.local", "NEXT_PUBLIC_USE_MOCK_API=true\n")
    write(repo_root / "services" / "ingestion" / ".env", "MAX_UPLOAD_SIZE_MB=10\n")

    result = run_check_env(repo_root)

    assert result.returncode == 0
    assert "All env files present and in sync" in result.stdout


def test_fails_when_an_env_file_is_missing(repo_root):
    write(repo_root / "gateway" / ".env", "JWT_SECRET=changeme\n")
    write(repo_root / "frontend" / ".env.local", "NEXT_PUBLIC_USE_MOCK_API=true\n")
    write(repo_root / "services" / "ingestion" / ".env", "MAX_UPLOAD_SIZE_MB=10\n")
    # root .env deliberately left missing

    result = run_check_env(repo_root)

    assert result.returncode == 1
    assert "MISSING: .env" in result.stdout


def test_fails_when_an_env_file_is_missing_a_key(repo_root):
    write(repo_root / ".env", "FOO=1\n")  # missing BAR
    write(repo_root / "gateway" / ".env", "JWT_SECRET=changeme\n")
    write(repo_root / "frontend" / ".env.local", "NEXT_PUBLIC_USE_MOCK_API=true\n")
    write(repo_root / "services" / "ingestion" / ".env", "MAX_UPLOAD_SIZE_MB=10\n")

    result = run_check_env(repo_root)

    assert result.returncode == 1
    assert "DRIFT: .env is missing key 'BAR'" in result.stdout


def test_ignores_comments_and_blank_lines_in_example(repo_root):
    write(repo_root / ".env.example", "# a comment\n\nFOO=1\nBAR=2\n")
    write(repo_root / ".env", "FOO=1\nBAR=2\n")
    write(repo_root / "gateway" / ".env", "JWT_SECRET=changeme\n")
    write(repo_root / "frontend" / ".env.local", "NEXT_PUBLIC_USE_MOCK_API=true\n")
    write(repo_root / "services" / "ingestion" / ".env", "MAX_UPLOAD_SIZE_MB=10\n")

    result = run_check_env(repo_root)

    assert result.returncode == 0
