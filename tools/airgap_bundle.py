"""
Signed update bundles for the air-gapped network.

  keygen  <dir>                      one-time, on the trusted build host
  pack    <key> <out.zip> <src>...   build host: bundle files + signed manifest
  import  <pubkey> <bundle.zip>      air-gapped host: verify, then install

A bundle is a zip of files plus manifest.json (path -> sha256) and
manifest.sig (Ed25519 over the manifest bytes). `import` refuses anything
whose signature, file hashes or paths don't check out, and only writes into
the two allow-listed destinations, so a tampered or mis-routed USB payload
can't overwrite arbitrary files.
"""

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
# bundle path prefix -> install directory (the only places an import may write)
DESTINATIONS = {
    "policies": ROOT / "services" / "compliance" / "policies",
    "templates": ROOT / "services" / "remediation" / "templates",
}
ALLOWED_SUFFIXES = {".rego", ".j2", ".json", ".yaml", ".yml"}


class BundleError(Exception):
    pass


def keygen(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    (out_dir / "bundle_signing.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (out_dir / "bundle_signing.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pack(key_path: Path, out_zip: Path, sources: list[Path]) -> None:
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    files: dict[str, bytes] = {}
    for src in sources:
        bundle_prefix, base = src.name, src
        if bundle_prefix not in DESTINATIONS:
            raise BundleError(f"{src}: folder must be named one of {sorted(DESTINATIONS)}")
        for path in sorted(p for p in base.rglob("*") if p.is_file() and p.suffix in ALLOWED_SUFFIXES):
            files[f"{bundle_prefix}/{path.relative_to(base).as_posix()}"] = path.read_bytes()
    manifest = json.dumps({
        "created": datetime.now(timezone.utc).isoformat(),
        "files": {name: _sha256(data) for name, data in sorted(files.items())},
    }, sort_keys=True).encode()
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", manifest)
        z.writestr("manifest.sig", key.sign(manifest))
        for name, data in files.items():
            z.writestr(name, data)


def verify(pub_path: Path, bundle: Path) -> tuple[dict[str, bytes], dict]:
    """Returns (files, manifest) only if everything checks out."""
    pub = serialization.load_pem_public_key(pub_path.read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        raise BundleError("Trusted key must be an Ed25519 public key")
    with zipfile.ZipFile(bundle) as z:
        names = set(z.namelist())
        if not {"manifest.json", "manifest.sig"} <= names:
            raise BundleError("Bundle has no signed manifest")
        manifest_bytes = z.read("manifest.json")
        try:
            pub.verify(z.read("manifest.sig"), manifest_bytes)
        except InvalidSignature:
            raise BundleError("Signature does not match the trusted key — bundle rejected") from None
        manifest = json.loads(manifest_bytes)
        declared = manifest["files"]
        extra = names - set(declared) - {"manifest.json", "manifest.sig"}
        if extra:
            raise BundleError(f"Bundle contains files not in the signed manifest: {sorted(extra)}")
        files: dict[str, bytes] = {}
        for name, digest in declared.items():
            parts = PurePosixPath(name).parts
            if len(parts) < 2 or parts[0] not in DESTINATIONS or ".." in parts or name.startswith("/"):
                raise BundleError(f"Refusing unsafe or unknown path: {name}")
            if PurePosixPath(name).suffix not in ALLOWED_SUFFIXES:
                raise BundleError(f"Refusing file type: {name}")
            data = z.read(name)
            if _sha256(data) != digest:
                raise BundleError(f"Hash mismatch for {name} — bundle rejected")
            files[name] = data
    return files, manifest


def install(files: dict[str, bytes]) -> list[str]:
    installed = []
    for name, data in files.items():
        prefix, _, rel = name.partition("/")
        target = DESTINATIONS[prefix] / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            shutil.copy2(target, target.with_name(target.name + ".bak"))
        target.write_bytes(data)
        installed.append(str(target))
    return installed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen").add_argument("out_dir", type=Path)
    p = sub.add_parser("pack")
    p.add_argument("key", type=Path); p.add_argument("out", type=Path); p.add_argument("sources", nargs="+", type=Path)
    i = sub.add_parser("import")
    i.add_argument("pubkey", type=Path); i.add_argument("bundle", type=Path)
    i.add_argument("--dry-run", action="store_true", help="verify only, install nothing")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "keygen":
            keygen(args.out_dir)
            print(f"Wrote bundle_signing.key (keep offline) and bundle_signing.pub to {args.out_dir}")
        elif args.cmd == "pack":
            pack(args.key, args.out, args.sources)
            print(f"Wrote signed bundle {args.out}")
        else:
            files, manifest = verify(args.pubkey, args.bundle)
            print(f"Signature OK — {len(files)} file(s), created {manifest['created']}")
            if not args.dry_run:
                for path in install(files):
                    print(f"  installed {path}")
                print("Restart OPA and rebuild the remediation image to load the new files.")
    except (BundleError, zipfile.BadZipFile, KeyError, ValueError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
