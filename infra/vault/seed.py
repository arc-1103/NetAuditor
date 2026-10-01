"""
Copies a service's secret-looking settings from its .env file into Vault.

  VAULT_ADDR=http://vault:8200 VAULT_TOKEN=... python seed.py gateway gateway/.env
  python seed.py gateway gateway/.env JWT_SECRET DATABASE_URL     # explicit keys

Without explicit keys it picks variables whose names contain PASSWORD, SECRET,
TOKEN, KEY or end in DATABASE_URL (they embed a password). Prints key names
only, never values. After seeding, remove those lines from the .env file.
"""

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

SECRET_NAME = re.compile(r"(PASSWORD|SECRET|TOKEN|KEY)|DATABASE_URL$", re.IGNORECASE)


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def pick(env: dict[str, str], explicit: list[str]) -> dict[str, str]:
    if explicit:
        missing = [k for k in explicit if k not in env]
        if missing:
            raise SystemExit(f"Not in the env file: {', '.join(missing)}")
        return {k: env[k] for k in explicit}
    return {k: v for k, v in env.items() if v and SECRET_NAME.search(k)}


def write(addr: str, token: str, mount: str, service: str, values: dict[str, str]) -> None:
    req = urllib.request.Request(
        f"{addr.rstrip('/')}/v1/{mount}/data/netaudit/{service}",
        data=json.dumps({"data": values}).encode(),
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10).read()


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    service, env_path, explicit = argv[1], Path(argv[2]), argv[3:]
    addr, token = os.getenv("VAULT_ADDR"), os.getenv("VAULT_TOKEN")
    if not (addr and token):
        print("Set VAULT_ADDR and VAULT_TOKEN first.", file=sys.stderr)
        return 2
    values = pick(read_env(env_path), explicit)
    if not values:
        print("No secret-looking variables found.")
        return 1
    write(addr, token, os.getenv("VAULT_MOUNT", "secret"), service, values)
    print(f"Wrote {len(values)} secret(s) for {service}: {', '.join(sorted(values))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
