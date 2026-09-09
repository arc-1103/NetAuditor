# Session Memory — Lessons for Future Contributors

Durable lessons from building active learning, multi-agent reverse
translation, GraphRAG, unsupervised anomaly detection, the agentic RAG
remediation fallback, and a RAG retrieval-scalability pass (2026-09-09).
This is a team-facing doc, not an AI tool's private memory — it exists so
the next person (human or otherwise) extending these lanes doesn't
rediscover the same gotchas the hard way.

## Design lessons

### A new feature can conflict with an existing invariant — find that before writing code

Two of the five features here ran straight into a documented design
decision from earlier in the project:

- Agentic RAG remediation conflicted with Remediation's stated safety
  model: *"No free-form AI command generation; all commands are
  version-controlled Jinja2 templates."*
- Anomaly detection conflicted with Compliance's stated determinism
  guarantee: *"the same normalized baseline always produces the same
  verdict."*

Neither got resolved by quietly working around the old rule or reinterpreting
it loosely. Both got resolved by keeping the new thing **structurally**
separate from what the old rule protects:

- An agentic-RAG proposal can never reach `preflight_status: SAFE` — it's
  gated at the type/status level, not by a comment saying "be careful with
  this."
- Anomaly detection lives in its own table (`configuration_anomalies`), not
  a column on `compliance_findings` — the separation is a schema fact, not
  a convention someone could violate by accident six months from now.

**The general lesson:** when a new feature request runs into an existing
`README.md` claim, docstring, or safety comment, that's a signal to stop and
design the reconciliation deliberately, not to route around it silently.
Grep for the invariant's exact wording before assuming it still holds the
way you think it does.

### "Optional enrichment degrades, never fails" is a load-bearing pattern here — copy it exactly

Every external dependency added by these features (Neo4j, Learning's
embedding/anomaly/manual-index endpoints) follows one shape:

```python
class XProvider(Protocol):
    async def method(self, ...): ...

class EmptyXProvider:          # no-op default
    async def method(self, ...): return <safe fallback>

class RealXProvider:           # actual implementation
    ...

def build_x_provider() -> XProvider:
    if not os.getenv("X_URL"):
        return EmptyXProvider()
    return RealXProvider(...)
```

The caller wraps the real call in `try/except`, logs a warning, and
degrades — it never lets an enrichment failure become an evaluation
failure. Get this pattern from `services/parsing/app/rag.py` or
`services/compliance/app/graph_client.py` when adding the next one; don't
reinvent it.

**The mistake this session actually made once:** building the real
provider eagerly at module import time (`_graph = build_topology_graph_provider()`
at module scope). A malformed config value then crashes the whole service
at startup — exactly the failure the pattern above exists to prevent. Build
lazily and memoize (`_get_x_provider()` checking `if _x is None`), and wrap
*that* construction in `try/except` too, not just the per-call use.

**A second mistake, made later while adding the exact-hash parse cache:** a
caught exception only helps if the failure actually raises one.
`redis-py`'s client has no default connect or socket timeout, so pointing
it at an unreachable Redis doesn't raise — it hangs. The first test run
against the newly-wired cache didn't finish inside a 120-second budget.
Every `try/except`-wrapped optional call in this pattern needs an
*explicit* timeout on the underlying client (`socket_connect_timeout`,
`socket_timeout` for redis-py; most HTTP clients in this codebase already
get this right via `httpx.AsyncClient(timeout=...)`, which is why the bug
showed up in the one place using a different client library instead). A
dependency that hangs is worse than one that raises, degraded fallback or
not — check what a client library's timeout defaults actually are before
trusting `try/except` alone to make it "optional."

### A new feature's suspected bottleneck often isn't the real one — check before optimizing

Before adding a RAG-scalability pass, the working assumption was that the
embedding model was reloading on every request (the classic ML-serving
mistake). It wasn't: `chromadb`'s own `SentenceTransformerEmbeddingFunction`
caches the loaded model in a class-level dict
(`models: Dict[str, Any] = {}`), so re-instantiating the wrapper object is
cheap regardless of how often it happens — confirmed by reading the
library's actual source rather than assuming. The real bottleneck was
mundane: a fresh `chromadb.HttpClient()` (which does a tenant/database
handshake over HTTP) built on every request instead of once. **Read the
dependency's source for the specific thing you suspect is slow before
designing around it** — the fix that matters is sometimes much smaller
(and different) than the one the initial guess would have produced.

### A "None" metadata value is not the same as "no value" — for ChromaDB specifically

ChromaDB rejects `None` in a metadata dict outright. Twice this session,
code stored `{"os": body.os}` where `body.os` could be `None`, and the
resulting validation error surfaced through a broad `except Exception` as
a misleading "ChromaDB unavailable" — a client-input bug disguised as an
infrastructure outage. The fix both times: normalize the missing value to
an explicit sentinel string (`"any"`, `"unknown"`) *before* it reaches
ChromaDB, never pass `None` in metadata. If you add a new ChromaDB
collection, check every field you write for this before it ships.

### A vector/graph identity that isn't reconciled against real identity will silently misbehave

GraphRAG's blast radius returned bare IP strings instead of device ids for
exactly one reason: a routing neighbor's placeholder node used the *same*
label (`Device`) and id shape (`id: <ip>`) as a real device, so two
independently-scanned devices that peer with each other never became one
graph identity. The fix was giving the placeholder its own distinct label
(`UnresolvedPeer`) and adding an explicit reconciliation step that runs on
every ingest. **The general lesson:** when a piece of data can be "known
partially" (an IP with no device attached yet) versus "known fully" (that
IP resolved to an actual scanned entity), give those two states visibly
different shapes — don't let "not yet resolved" and "genuinely is this
thing" share one representation. It's the kind of bug that looks fine in
every unit test with one device and only shows up once two real records
exist to collide.

## Infrastructure lessons

### `init.sql` is not a migration system — a new column/table needs a second file

`docker-entrypoint-initdb.d` scripts (which is what `infra/postgres/init.sql`
is) only run once, against an empty data volume. Adding a column to
`CREATE TABLE IF NOT EXISTS` in that file does nothing for a database that
already exists. This project has no migration framework, so the working
pattern established this session is: keep the column/table in `init.sql`
for fresh installs, *and* add an idempotent
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (or `CREATE TABLE IF NOT EXISTS`)
script under `infra/postgres/migrations/`, numbered in order, with a
comment pointing back at it from `init.sql`'s header. Document the `psql -f`
command in whichever service's README owns the change. Two migrations exist
there now as the reference examples.

### An official Docker image mapping env vars into its own config is a real footgun

The `neo4j` image maps every `NEO4J_`-prefixed environment variable it
receives into `neo4j.conf`, and refuses to start on one it doesn't
recognize — only `NEO4J_AUTH` is special-cased. Giving a service
`env_file: .env` (the shared root env file) when that file also defines
app-side variables with a matching prefix (here, `NEO4J_HOST`,
`NEO4J_BOLT_PORT`, etc., meant for *this codebase's* services to read via
`os.getenv`, not for the neo4j container itself) will crash-loop the
container. **When wiring a new official image into `docker-compose.yml`,
check what environment variables that specific image actually consumes**
(usually documented as "supported configuration" in its Docker Hub page) —
don't assume `env_file: .env` is harmless just because it's the existing
pattern for this project's own services.

## Process lessons

A `/code-review` pass on the finished work caught two High-severity bugs (the
blast-radius identity issue and the Neo4j crash-loop) that all of parsing's,
compliance's, and remediation's own test suites had missed — because the
tests exercised each provider in isolation with fakes, and neither bug is
visible without either two real, colliding records (blast radius) or an
actual container boot (the compose env-var mapping). **Fakes and mocks
prove the wiring is correct; they don't prove the real dependency behaves
the way the fake assumes it does.** Run the review pass before considering
a cross-service feature done, especially one that touches infra
(`docker-compose.yml`) or introduces a new kind of identity (graph nodes,
vector ids) that has to survive being merged with itself later.

**Re-read the whole function after a targeted edit that restructures
control flow, not just the diff.** Adding the parse-cache's hit/miss
branching to `_parse_chunk` was done as an edit that inserted the new
branch — and left the *old*, now-redundant gate-checking code sitting
directly after it, unreachable-looking but actually still executing
unconditionally on every call, including a future real cache hit where the
variable it referenced (`mean_logprob`) would never be assigned at all.
The bug was only caught because the test suite was run immediately
afterward and an assertion on call-count came out wrong; nothing about the
diff itself looked suspicious in isolation. When an edit changes a
function's control flow (adding a branch, an early return, a new
if/else), read the resulting function as a whole afterward — not just the
lines that changed — to check for exactly this kind of leftover.
