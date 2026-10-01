import pytest

import seed


def test_pick_selects_secret_like_names_only():
    env = {"JWT_SECRET": "a", "MINIO_ROOT_PASSWORD": "b", "DATABASE_URL": "postgresql://u:p@h/db", "PORT": "8000", "EMPTY_KEY": ""}
    assert set(seed.pick(env, [])) == {"JWT_SECRET", "MINIO_ROOT_PASSWORD", "DATABASE_URL"}


def test_explicit_keys_must_exist():
    with pytest.raises(SystemExit):
        seed.pick({"A": "1"}, ["B"])
    assert seed.pick({"A": "1"}, ["A"]) == {"A": "1"}


def test_read_env_ignores_comments_and_strips_quotes(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# c\nA="x y"\nB=2\n\nbad line\n')
    assert seed.read_env(f) == {"A": "x y", "B": "2"}
