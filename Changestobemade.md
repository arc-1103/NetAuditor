# Changes to be made

From `/code-review [xhigh] whole repo` (2026-09-24). Nothing here has been fixed yet — this is a punch list to work through and confirm before editing.

## High

1. **`services/compliance/app/worker.py:45`** — Each Celery task starts a new event loop with `asyncio.run()`, but the database connection pool is created once per process and stays tied to the first loop. From the second task in a worker process on, `save_findings` fails and the run never reaches EVALUATED. The same problem breaks the parsing and learning workers. It also silently disables the parse cache and Neo4j enrichment, because those errors are swallowed.
2. **`services/parsing/app/reverse_translation.py:26`** — The round-trip accuracy check counts interface (topology) facts even though the comment says they are excluded, and the reverse step never rebuilds interfaces. Running the default mock on `demo/cisco_insecure.cfg` gives a score of 0.667, below the 0.7 threshold, so the demo run ends in NEEDS_REVIEW with no findings.
3. **`services/reporting/app/main.py:27`** — Report generation never checks the run's status. A NEEDS_REVIEW or unfinished run gets a report scoring 100/100 and is then marked COMPLETE, so an unaudited device looks fully compliant. Any reader role can trigger this.

## Medium

4. **`gateway/app/main.py:110`** — The gateway's learning-map request drops `vendor` and `os`, so every mapping an admin confirms is stored as vendor "unknown". Parsing searches by the real vendor, so it never finds these mappings and the learning loop has no effect for known vendors.
5. **`services/learning/backend/app/main.py:575`** — `peers.get("embeddings") or []` tests an array's truth value, which raises an error once a vendor/OS group has 2 or more stored configs. Anomaly detection then never produces a score.
6. **`services/ingestion/app/uploader.py:86`** — The file is stored in MinIO before the audit run is recorded and the parsing job is queued. If either of those fails, every retry of the same file is rejected as "already ingested".
7. **`services/ingestion/app/uploader.py:34`** — Redacting `snmp-server community public` hides "public" from the parser, so the critical default-community check (CIS-NET-1.2.2) can never fire for Cisco. Meanwhile the same community string leaks unredacted through the `snmp-server host ... public` line.
8. **`services/remediation/app/main.py:58`** — Variables supplied by the caller are inserted unescaped into fix templates, and several templates carry no review marker. Injected commands therefore pass preflight as SAFE and can be approved.
9. **`services/parsing/app/merge.py:79`** — When a config is split into chunks (over 500 lines), the first chunk's value wins on conflicts, and false/DISABLED counts as a real value. An earlier chunk's default can hide a later chunk's evidence (Telnet enabled, syslog configured), causing missed or false findings.

## Low

10. **`services/parsing/app/slm_client.py:184`** — The mock parser has no SNMP, IKE, `no service password-encryption` or FortiOS patterns. The Fortinet demo therefore always ends in NEEDS_REVIEW, and CIS-NET-1.2.2 and 1.3.1 are never produced, although `demo/expected-findings.json` requires them.
11. **`frontend/src/app/page.tsx:118`** — A NEEDS_REVIEW run shows a green 100/100 score and "11 of 11 checks passed".
12. **`services/learning/backend/app/main.py:357`** — Adding a vendor fingerprint without an OS stores an empty OS value, which ChromaDB rejects, so the request returns 503.

---

Ask before fixing any of these — propose the change, wait for a go-ahead, then edit.
