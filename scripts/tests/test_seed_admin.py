"""
Tests for scripts/seed_admin.py. The Postgres engine is faked — these
tests verify the INSERT is shaped correctly and the password is actually
hashed, not that a real database accepted the write.
"""
import seed_admin


class FakeConnection:
    def __init__(self):
        self.executed = []

    async def execute(self, statement, params=None):
        self.executed.append((str(statement), params))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class FakeEngine:
    def __init__(self):
        self.connection = FakeConnection()

    def begin(self):
        return self.connection


async def test_main_seeds_the_default_admin_with_a_verifiable_hash(monkeypatch, capsys):
    fake_engine = FakeEngine()
    monkeypatch.setattr(seed_admin, "create_async_engine", lambda dsn: fake_engine)

    await seed_admin.main()

    assert len(fake_engine.connection.executed) == 1
    statement, params = fake_engine.connection.executed[0]
    assert "INSERT INTO users" in statement
    assert "ON CONFLICT (email) DO NOTHING" in statement
    assert params["email"] == "admin@netaudit.local"
    assert seed_admin.pwd_context.verify("changeme", params["hash"])
    assert not seed_admin.pwd_context.verify("wrong-password", params["hash"])

    assert "Seeded admin@netaudit.local" in capsys.readouterr().out


async def test_main_never_stores_the_plaintext_password(monkeypatch):
    fake_engine = FakeEngine()
    monkeypatch.setattr(seed_admin, "create_async_engine", lambda dsn: fake_engine)

    await seed_admin.main()

    _, params = fake_engine.connection.executed[0]
    assert params["hash"] != "changeme"
