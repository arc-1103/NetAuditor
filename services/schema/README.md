# NetAuditor shared schema

This package is the only home for `SecurityBaseline` and its sub-models.
Parsing and Compliance exchange the JSON shape through
`contracts/security_baseline.schema.json`.

Install locally:

```bash
cd services/schema
pip install -e .
pytest -q
```

Python 3.11 is the supported package runtime.
