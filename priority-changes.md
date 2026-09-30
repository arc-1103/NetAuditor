# Priority changes

## 1. "Generate safe fixes" fails: Ollama DNS resolution ("Temporary failure in name resolution")

**Symptom:** clicking "Generate safe fixes" on a finding with no `.j2` template (e.g. Juniper/Palo Alto vendors — see the agentic-RAG fallback added in [main.py](services/remediation/app/main.py)) returns:
```
{"detail":"Agentic RAG remediation synthesis failed: Ollama request failed: [Errno -3] Temporary failure in name resolution"}
```

**Root cause:** Docker network drift, not a code bug. `services/remediation` resolves Ollama via `OLLAMA_HOST=http://ollama:11434` (Docker's embedded DNS on the `audit-net` bridge network). Inspecting the running containers:

- `netaudit-remediation-1` is attached to `audit-net`, network ID `b141a1e7f0c6...` (created 2026-09-30 15:57, i.e. today).
- `netaudit-ollama-1` is attached to `audit-net`, network ID `d7dbf9de09fe...` — a network ID that **no longer exists** (`docker network inspect` on it returns "not found"). `netaudit-ollama-1` was created 2026-09-29 17:19, a day before the network was recreated.

So `audit-net` was torn down and recreated at some point after `ollama` last started, and `ollama` was never reconnected to the new network — it's now DNS-invisible to every other container, even though `docker ps`/`docker compose ps` still shows it "Up (healthy)". Any rebuild/restart of an individual service (`docker compose build <svc> && up -d <svc>`, as used for the remediation and frontend fixes earlier) recreates that service's network attachment on the current network, but does nothing for containers that weren't touched — which is how `ollama` was left behind on the stale network.

**Fix (not yet applied — infra/ops action, not a code change):**
```
docker compose up -d --force-recreate ollama
```
or `docker network connect audit-net netaudit-ollama-1` without a restart. Either reattaches `ollama` to the current `audit-net` so DNS resolution of `http://ollama:11434` works again from `remediation` (and any other service).

**Status: fixed (2026-09-30).** Ran `docker compose up -d --force-recreate ollama`. Verified `netaudit-ollama-1` now has an IP on the current `audit-net` and `netaudit-remediation-1` resolves `ollama` via DNS again.

**Longer-term fix worth considering:** nothing in the stack currently detects this class of drift — `ollama`'s own healthcheck only checks the process inside the container, not its reachability from peer containers. No code change proposed yet; flagging for discussion.
