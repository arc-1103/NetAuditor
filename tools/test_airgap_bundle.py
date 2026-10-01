import zipfile

import pytest

import airgap_bundle as ab


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setitem(ab.DESTINATIONS, "policies", tmp_path / "install" / "policies")
    monkeypatch.setitem(ab.DESTINATIONS, "templates", tmp_path / "install" / "templates")
    src = tmp_path / "build" / "templates"
    src.mkdir(parents=True)
    (src / "x_fix.j2").write_text("set thing\n")
    ab.keygen(tmp_path / "keys")
    bundle = tmp_path / "update.zip"
    ab.pack(tmp_path / "keys" / "bundle_signing.key", bundle, [src])
    return tmp_path, bundle


def test_valid_bundle_installs_and_backs_up(env):
    tmp, bundle = env
    files, _ = ab.verify(tmp / "keys" / "bundle_signing.pub", bundle)
    ab.install(files)
    ab.install(files)
    assert (tmp / "install" / "templates" / "x_fix.j2").read_text() == "set thing\n"
    assert (tmp / "install" / "templates" / "x_fix.j2.bak").exists()


def test_wrong_key_is_rejected(env, tmp_path):
    _, bundle = env
    ab.keygen(tmp_path / "other")
    with pytest.raises(ab.BundleError, match="Signature"):
        ab.verify(tmp_path / "other" / "bundle_signing.pub", bundle)


def test_tampered_file_or_extra_file_is_rejected(env):
    tmp, bundle = env
    pub = tmp / "keys" / "bundle_signing.pub"
    tampered = tmp / "tampered.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(tampered, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            zout.writestr(item.filename, b"rm -rf /\n" if item.filename.endswith(".j2") else data)
    with pytest.raises(ab.BundleError, match="Hash mismatch"):
        ab.verify(pub, tampered)
    extra = tmp / "extra.zip"
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(extra, "w") as zout:
        for item in zin.infolist():
            zout.writestr(item.filename, zin.read(item.filename))
        zout.writestr("templates/evil.j2", b"x")
    with pytest.raises(ab.BundleError, match="not in the signed manifest"):
        ab.verify(pub, extra)
