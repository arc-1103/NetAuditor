# Reporting service

Produces an audit-ready HTML preview and A4 PDF containing the run identity,
SHA-256 fingerprint, compliance score, severity breakdown, evidence, and the
current preflight/approval state of each remediation proposal.

## Run and test

```bash
cp .env.example .env
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --reload --port 8005
```

Useful endpoints:

- `POST /reports/generate` with `{"audit_run_id":"..."}` — render and record a PDF.
- `GET /reports/{id}/preview` — browser-friendly HTML preview.
- `GET /reports/{id}/download` — generated PDF.
- `GET /reports/{id}/json` — structured archive/SIEM export.
- `GET /reports/{id}/cef` — one CEF event per failed control.

PDF files are written beneath `PDF_OUTPUT_DIR` and persisted in the Compose
`reportdata` volume. A successful report updates the audit run to `COMPLETE`.
