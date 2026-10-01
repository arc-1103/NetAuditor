# Time synchronization

Audit evidence (ledger rows, PDF and CEF reports) must carry trustworthy
timestamps. In an isolated network that needs its own time source.

## What to deploy

1. **A time source inside the boundary.** Best: a GPS/PPS-disciplined Stratum 1
   receiver. Acceptable: an internal Stratum 2 server fed from one. Edit
   `infra/ntp/chrony.conf` (refclock or `server` lines), then
   `docker compose --profile time up -d ntp`. The shipped file also has a
   `local stratum 10 orphan` fallback that keeps devices consistent with each
   other when no reference is reachable — consistent, not necessarily correct.
2. **Point everything at it:** network devices, servers, and the Docker host
   (containers share the host clock, so the host must sync to it).
3. **Tell NetAudit where it is:** set `NTP_SERVER=<address>` in `.env`.

## What NetAudit does with it

- `services/reporting/app/timesync.py` asks the time source for its time (SNTP)
  and computes this host's clock offset.
- Every PDF and JSON report states the result in its Integrity section: the
  source, stratum, offset, and whether it is within `NTP_MAX_OFFSET_SECONDS`
  (default 1 s). If no source is configured, or it does not answer, the report
  says so instead of implying the time was verified.
- The UI header shows a badge: TIME SYNCED, CLOCK DRIFT, TIME SOURCE DOWN or
  TIME NOT VERIFIED (`GET /api/time-status`).

## Limits

NetAudit measures and reports drift; it does not set the clock. Postgres
timestamps come from the database host's clock, so that host must sync to the
same source. The check is taken when a report is generated, not continuously —
run your normal NTP monitoring for ongoing assurance.
