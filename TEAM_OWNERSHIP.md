# Team Ownership Map

Maps the C4 System_Boundary blocks (Blueprint §2.1) to ownership lanes so
work can proceed in parallel without two people editing the same service.

| Lane | Owns (folders) | Depends on (via contract, not code) |
|---|---|---|
| **Ingestion + Gateway** | `services/ingestion/`, `gateway/` | `services/schema/` (published types only) |
| **Parsing / SLM** | `services/parsing/`, `services/schema/` | Ollama container (mockable, `USE_MOCK_SLM=true`) |
| **Compliance / OPA** | `services/compliance/` | `services/schema/` output shape, not parsing internals |
| **Learning / RAG** | `services/learning/` | ChromaDB, `services/schema/` |
| **Remediation + Reporting** | `services/remediation/`, `services/reporting/` | Compliance's finding output shape (`contracts/`) |
| **Frontend / Dashboard** | `frontend/` | `contracts/` API shapes only — never blocks on backend being "done" |
| **Infra (shared, part-time)** | `infra/`, `docker-compose.yml`, root `.env.example` | Everyone — changes here need a heads-up in the team channel |

## Rule of thumb
If your change is only inside your own `services/<lane>/` folder, ship it.
If it touches `services/schema/` or anything in `contracts/`, that's a
cross-team change — open a PR, tag the other lane owners, don't just merge.

## Assign names here before you start
- Ingestion + Gateway: Aryan
- Parsing / SLM: ______________
- Compliance / OPA: ______________
- Learning / RAG: ______________
- Remediation + Reporting: ______________
- Frontend: ______________
