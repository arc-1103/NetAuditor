# Changes to be made

From `/code-review [xhigh] whole repo` (2026-09-24). All 12 items are now fixed and verified (tests added, regression proven by reverting each fix and confirming it fails, then restoring).

## High

1. ✅ **`services/compliance/app/worker.py:45`** — Each Celery task started a new event loop with `asyncio.run()`, but the async engine's asyncpg pool stayed bound to the first loop, breaking every task after the first. Fixed in `services/compliance/app/worker.py`, `services/parsing/app/worker.py`, and `services/learning/backend/app/unknown_handler.py` (all three had the same pattern): one persistent event loop per worker process, reused via `run_until_complete` instead of `asyncio.run`.
2. ✅ **`services/parsing/app/reverse_translation.py:26`** — GraphRAG `topology` is a top-level key, not a `device.*` leaf, so the existing exclusion list never caught it. Added `_TOP_LEVEL_KEYS_EXCLUDED_FROM_FIDELITY = {"topology"}`.
3. ✅ **`services/reporting/app/main.py:27`** — Added a `_require_evaluated` guard (422 for any status other than `EVALUATED`/`COMPLETE`) to all four reporting endpoints (`generate`, `preview`, `json`, `cef`). The same defect also existed one layer up in `services/compliance/app/main.py`'s `GET /audit-runs/{id}` (the live dashboard's data source) — fixed there too, plus a frontend guard in `page.tsx`/`types.ts` since `compliance_score` can now be `null`.

## Medium

4. ✅ **`gateway/app/main.py:110`** — Added the missing `vendor`/`os` fields to the gateway's `LearningMapRequest`, matching Learning's own model.
5. ✅ **`services/learning/backend/app/main.py:575`** — `peers.get("embeddings") or []` crashed on ChromaDB's numpy array (ambiguous truth value for 2+ elements). Replaced with an explicit `is not None` check.
6. ✅ **`services/ingestion/app/uploader.py:86`** — MinIO object existence was used as the dedup signal instead of the `audit_runs` table. Added `audit_run_exists_for_hash`, checked before any DB/queue side effect, so a partial failure is always retryable.
7. ✅ **`services/ingestion/app/uploader.py:34`** — "public"/"private" SNMP communities are no longer redacted (they're the exact evidence CIS-NET-1.2.2 needs); any other community string is now redacted everywhere it appears, including `snmp-server host ... <community>` lines.
8. ✅ **`services/remediation/app/main.py:58`** — `template_engine.py`'s `render_template` now rejects any caller-supplied variable containing a newline, closing the CLI-injection path. Added missing `! REVIEW:` markers to 4 templates that interpolate free-text variables.
9. ✅ **`services/parsing/app/merge.py:79`** — Added `_NEGATIVE_SCALARS = {False, "DISABLED"}`; on a scalar conflict, a later chunk's non-negative (risk-indicating) value now always survives over an earlier chunk's safe/negative one, regardless of file order. The conflict is still recorded.

## Low

10. ✅ **`services/parsing/app/slm_client.py:184`** — Added SNMP community, IKE/crypto encryption (Cisco + FortiOS block syntax), FortiOS telnet, FortiOS HTTP-admin-access, and negated `no service password-encryption` extraction to the mock parser. Verified end-to-end against the real `demo/cisco_insecure.cfg` and `demo/fortinet_insecure.conf` fixtures.
11. ✅ **`frontend/src/app/page.tsx:118`** — The metrics section now shows a "Not yet evaluated" placeholder instead of a fabricated ScoreRing/pass-rate when `compliance_score` is `null`.
12. ✅ **`services/learning/backend/app/main.py:357`** — `add_vendor_fingerprint` now stores the existing `UNKNOWN_OS` sentinel instead of a literal `None`, which ChromaDB rejected.

---

## Known pre-existing environment gaps (not caused by these fixes, confirmed identical on a clean `main` checkout)

- **gateway**: the full test suite fails to even build the FastAPI app (`OperationalMiddleware.__init__() got an unexpected keyword argument 'app'`) — a starlette/middleware version mismatch in this environment. The gateway fix (#4) was verified directly against the Pydantic model instead.
- **services/reporting**: `import app.main` fails because WeasyPrint can't load native `gobject-2.0-0` libraries on this Windows machine. The reporting fix (#3) was verified as isolated logic instead of via pytest.
- **services/parsing/tests/test_contracts.py::test_real_worker_pipeline_output_matches_actual_cross_lane_contract**: needs a live Redis connection, unrelated to any of these fixes.

Neither gap blocked verifying the actual fixes, but both are worth fixing properly (dependency pin / native library install) before relying on those two suites again.
