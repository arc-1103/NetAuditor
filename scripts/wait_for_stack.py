#!/usr/bin/env python3
"""Wait for the two host-exposed presentation endpoints."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

ENDPOINTS = {
    "gateway": os.getenv("NETAUDIT_GATEWAY_HEALTH", "http://localhost:8000/health"),
    "frontend": os.getenv("NETAUDIT_FRONTEND_HEALTH", "http://localhost:3000"),
}
deadline = time.monotonic() + float(os.getenv("NETAUDIT_STARTUP_TIMEOUT", "300"))
pending = dict(ENDPOINTS)
while pending and time.monotonic() < deadline:
    for name, url in list(pending.items()):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status < 400:
                    print(f"ready: {name} ({url})")
                    pending.pop(name)
        except (urllib.error.URLError, TimeoutError):
            pass
    if pending:
        time.sleep(2)
if pending:
    raise SystemExit("Stack readiness timed out: " + json.dumps(pending))
print("NetAudit presentation endpoints are ready.")
