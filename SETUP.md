# Running NetAudit Engine — Setup Guide

**For SIH 26155 evaluators.** This guide takes you from a clean machine to a
working NetAudit Engine on **macOS**, **Windows** or **Linux**.

Everything runs locally on your own machine. There is no cloud account, no API
key and no internet dependency after the first image download — the system is
designed for air-gapped operation.

---

## What you will be able to do

After setup you can upload a raw network-device configuration file and watch the
full pipeline run:

```
Configuration -> secret redaction -> local AI extraction -> schema validation
             -> deterministic OPA verdict -> preflighted remediation
             -> human approval -> versioned evidence report
```

The compliance verdict is produced by deterministic policy, not by the model.
Sample configurations for five vendors are included in `demo/`.

---

## Choose a path

| Path | Time | Needs | When to use |
|---|---|---|---|
| **[A — Full system](#path-a--full-system-recommended)** | 15–25 min first run | Docker Desktop, 8 GB RAM | Recommended. Real backend, real verdicts, full evidence trail. |
| **[B — Dashboard only](#path-b--dashboard-only-no-docker)** | 3 min | Node.js 22 | If Docker cannot be installed or will not start. Deterministic walkthrough, clearly labelled as fallback. |
| **[C — Source review](#path-c--source-review-and-test-suites)** | 10 min | Python 3.12, Node 22 | To inspect code and run the test suites without the stack. |

If you have limited time: **Path A, steps 1–5.** Five commands.

---

## Prerequisites

| | macOS | Windows 11 | Linux |
|---|---|---|---|
| Containers | Docker Desktop | Docker Desktop, **WSL 2 backend** | Docker Engine + `docker-compose-plugin` |
| Shell for setup scripts | Terminal (`bash`/`zsh`) | **Git Bash** (comes with Git for Windows) | any shell |
| Git | `brew install git` | Git for Windows | distro package |
| Python (host helper scripts) | 3.12 or newer | 3.12 or newer | 3.12 or newer |
| Node.js (Path B / C only) | 22 or newer | 22 or newer | 22 or newer |

Confirm the toolchain:

```bash
docker compose version     # must report v2.x or newer
git --version
python3 --version
```

### Windows: read this first

1. In Docker Desktop, enable **Settings → General → Use the WSL 2 based engine**,
   and allow it at least **8 GB** under **Settings → Resources**.
2. The repository's setup scripts are bash scripts. Run them from **Git Bash**,
   not PowerShell or `cmd`. Right-click the project folder → *Open Git Bash
   here*. PowerShell alternatives are given where it matters.
3. Windows often has `python` but not `python3`. If `python3 --version` fails in
   Git Bash, use `python` instead, or alias it once:
   ```bash
   echo "alias python3=python" >> ~/.bashrc && source ~/.bashrc
   ```
4. Clone to a path **without spaces**. Line endings need no action — the
   repository's `.gitattributes` pins every text file to LF, so Git for
   Windows' default `core.autocrlf=true` cannot hand you CRLF shell scripts.

### Linux

Add yourself to the `docker` group so no command below needs `sudo`:

```bash
sudo usermod -aG docker $USER      # then log out and back in
```

---

## Path A — Full system (recommended)

### Step 1 — Clone and prepare configuration

```bash
git clone <repository-url> NetAuditor
cd NetAuditor
./scripts/setup_demo.sh
```

This one script copies every `.env.example` to a real `.env` (project root,
`gateway/`, each service under `services/`, and `frontend/.env.local`), then
generates two fresh random secrets: a `JWT_SECRET` for login tokens and a
`SERVICE_JWT_SECRET` for signed service-to-service calls. Nothing existing is
overwritten, so re-running it is safe.

It finishes by running `scripts/check_env.sh`, which fails loudly if any
configuration key is missing. Expect:

```
✅ All env files present and in sync with their .env.example.
Environment ready. Start with: docker compose up --build -d
```

Docker Compose **refuses to start** without `SERVICE_JWT_SECRET`. If the script
reported that `openssl` was unavailable, set it yourself:

```bash
python3 -c "import secrets; print('SERVICE_JWT_SECRET=' + secrets.token_hex(32))" >> .env
```

<details>
<summary><b>PowerShell equivalent of step 1</b> (if you cannot use Git Bash)</summary>

```powershell
Copy-Item .env.example .env
Copy-Item gateway\.env.example gateway\.env
Copy-Item frontend\.env.local.example frontend\.env.local
Get-ChildItem services -Directory | ForEach-Object {
  $src = Join-Path $_.FullName '.env.example'
  if (Test-Path $src) { Copy-Item $src (Join-Path $_.FullName '.env') }
}
$jwt = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
(Get-Content gateway\.env) -replace '^JWT_SECRET=.*', "JWT_SECRET=$jwt" |
  Set-Content gateway\.env -Encoding utf8
$svc = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
Add-Content .env "SERVICE_JWT_SECRET=$svc" -Encoding utf8
```
</details>

### Step 2 — Start the system

```bash
docker compose up --build -d
```

The first run downloads base images and builds seven Python services plus the
dashboard. **Allow 15–25 minutes** on a typical connection; subsequent starts
take seconds.

This brings up the **evaluation core**: PostgreSQL, Redis, MinIO object storage,
the OPA policy engine, the seven application services, the API gateway and the
operations dashboard. It deliberately does **not** start a local language model,
so it fits comfortably in 8 GB of RAM.

The optional components are off by default and can be added individually:

```bash
docker compose --profile advanced up -d   # Neo4j topology graph, Batfish, vector store
docker compose --profile model up -d      # Ollama + Qwen2.5 7B  (needs ~12 GB RAM)
docker compose --profile iam up -d        # Keycloak enterprise identity
docker compose --profile secrets up -d    # HashiCorp Vault
docker compose --profile time up -d       # NTP, trusted time for ledger seals
```

On a 16 GB laptop running everything simultaneously, add the memory-capped
overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml \
  --profile advanced --profile model up -d
```

### Step 3 — Wait until the system reports ready

```bash
python3 scripts/wait_for_stack.py
```

This polls the two host-facing endpoints until both answer, then prints:

```
NetAudit presentation endpoints are ready.
```

Default timeout is five minutes; override with `NETAUDIT_STARTUP_TIMEOUT`.

### Step 4 — Create the login account

The database schema is created automatically the first time the data volume is
initialised. Only the user account needs to be added.

PostgreSQL is **not exposed to your host machine** — it sits on an isolated
internal network, which is part of the security design. The seeding script
therefore runs *inside* a container that is already on that network:

```bash
docker compose cp scripts/seed_admin.py gateway:/tmp/seed_admin.py
docker compose exec gateway python /tmp/seed_admin.py
```

Expected output:

```
Seeded admin@netaudit.local. Password source: NETAUDIT_ADMIN_PASSWORD
```

**Credentials:** `admin@netaudit.local` / `changeme`

These are local-prototype credentials only. To choose your own, add
`-e NETAUDIT_ADMIN_PASSWORD=yourpassword` to the `exec` command above. The
script refuses the default password whenever `APP_ENV` is not `development` or
`test`.

### Step 5 — Open and evaluate

Open **<http://localhost:3000>**, log in, and upload `demo/cisco_insecure.cfg`.

| What | Where |
|---|---|
| Operations dashboard | http://localhost:3000 |
| Gateway API | http://localhost:8000 |
| Interactive API documentation | http://localhost:8000/docs |
| Health endpoint | http://localhost:8000/health |
| TLS front end (self-signed certificate) | https://localhost:443 |

`demo/DEMO_SCRIPT.md` contains a four-minute guided narration of exactly what to
click and what each screen demonstrates. The `demo/` folder holds fixtures for
Cisco, Fortinet, Juniper, Palo Alto and Arista, in both insecure and hardened
variants, so you can compare pass and fail verdicts on the same control set.

### Step 6 — Managing the running system

```bash
docker compose ps                  # health status of every component
docker compose logs -f gateway     # follow one component's logs
docker compose restart parsing     # restart one component
docker compose down                # stop, preserving all data
docker compose down -v             # stop and erase all data (clean slate)
```

If you later pull repository updates that add database migrations, apply them to
the existing volume:

```bash
./scripts/apply_migrations.sh
```

A brand-new installation does not need this — the initial schema is already
complete.

---

## Path B — Dashboard only (no Docker)

A deterministic, fixture-driven walkthrough of the interface. No backend, no
database, no container runtime. Use it if Docker cannot be installed on the
evaluation machine.

**macOS, Linux, or Git Bash on Windows:**

```bash
cd frontend
npm ci
npm run demo
```

**PowerShell or cmd on Windows** (`npm run demo` uses Unix-only syntax):

```powershell
cd frontend
npm ci
$env:NEXT_PUBLIC_USE_MOCK_API = "true"
npm run dev
```

Open <http://localhost:3000> and upload any accepted configuration file. The
dashboard **labels fallback mode explicitly on screen**, so a fallback result
can never be mistaken for a live compliance verdict.

Optionally, to show a genuine local language model explaining a finding, run this
in a second terminal:

```bash
./scripts/start_live_qwen.sh
```

The first run downloads the Qwen2.5-Coder 0.5B model weights. An
"Ask Qwen to explain" button then appears in the findings drawer. The model
explains a finding in plain language; it does not produce or change the verdict.

---

## Path C — Source review and test suites

To inspect the code and run the automated checks without starting the full
system:

```bash
pip install -r scripts/requirements-dev.txt
./scripts/verify.sh
```

`verify.sh` validates all demo fixtures, checks every JSON contract schema, runs
each service's test suite in an isolated process (the services intentionally
share the Python package name `app`), type-checks and builds the dashboard, and
validates the Compose file when Docker is available.

Individual gates, if you want to run just one:

```bash
python3 demo/verify_fixtures.py                   # fixture integrity
(cd services/compliance && python3 -m pytest -q)  # one service's tests
(cd frontend && npm run typecheck)                # dashboard type safety
docker compose config --quiet                     # Compose validity
./scripts/check_env.sh                            # configuration drift
```

To work on a single service against real infrastructure:

```bash
docker compose up -d postgres redis minio opa     # infrastructure only

cd services/parsing
python3 -m venv .venv
source .venv/bin/activate                 # Windows Git Bash: source .venv/Scripts/activate
pip install -r requirements.txt
python3 -m pytest -q
```

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `set SERVICE_JWT_SECRET in .env` when starting | The root `.env` is missing that key. Re-run `./scripts/setup_demo.sh`, or append it using the Python one-liner in step 1. |
| `MISSING: …/.env` from `check_env.sh` | A configuration file was not copied. Re-run `./scripts/setup_demo.sh`. |
| `Docker daemon not running` | Start Docker Desktop (macOS/Windows) or `sudo systemctl start docker` (Linux). |
| `seed_admin.py`: connection refused | The script was run on the host. PostgreSQL is intentionally not published — use the two-command form in step 4. |
| Login stopped working after `down -v` | The data wipe removed the account. Repeat step 4. |
| `relation does not exist` | Schema predates a migration. Run `./scripts/apply_migrations.sh`. |
| `wait_for_stack.py` times out | Run `docker compose ps` to find the unhealthy component, then `docker compose logs <name>`. Usually a slow first build or a port conflict. |
| `port is already allocated` | Change `GATEWAY_PORT`, `FRONTEND_PORT` or `NGINX_PORT` in `.env`. |
| `npm run demo` fails on Windows | PowerShell cannot parse the inline environment prefix. Use the `$env:` form in Path B. |
| `$'\r': command not found` inside a container | A file escaped `.gitattributes` normalization. On a clean tree: `git add --renormalize . && git checkout -- .` |
| Out of memory, or the system becomes sluggish | Drop the `model` profile, or add `-f docker-compose.demo.yml` for the memory-capped overlay. |
| Nothing works, start clean | `docker compose down -v && docker compose up --build -d`, then repeat step 4. |

---

## Notes for evaluation

- The `changeme` values in `.env.example` exist for local prototype use only.
  Production startup **rejects** the known default `JWT_SECRET` outright.
- Only three ports cross the host boundary: the gateway (8000), the dashboard
  (3000) and the TLS front end (443). Every other component — database, object
  storage, policy engine, all seven services — stays on an isolated internal
  network.
- Uploaded configurations are size-bounded, MIME-checked, credential-redacted
  and SHA-256 fingerprinted before storage.
- Dashboard roles are `admin`, `operator` and read-only `auditor`.
- Low-confidence or invalid parsing is reported as `NEEDS_REVIEW` and is never
  shown as compliant. AI-synthesised remediation is permanently marked with
  `RISK_FLAGS` and cannot pass the normal approval gate.

Supporting documents: `README.md` (capability summary and scope claims),
`Architecture.md` (design),
`docs/THREAT_MODEL.md` (security analysis),
`docs/PRESENTATION_CLAIMS_CHECKLIST.md` (what the prototype does and does not
claim), and `docs/SUBMISSION_CHECKLIST.md` (submission index).
