# Forwarding events to a SIEM

The `siem-forwarder` service (Fluent Bit) receives the webhook events the
compliance and remediation services already emit (`VIOLATION_DETECTED`,
`REMEDIATION_PROPOSED`, `APPROVED`/`REJECTED`, `ROLLED_BACK`), converts each to
a CEF line, and prints it. Nothing leaves the host by default.

## Send to your SIEM

In `.env`:
```
SIEM_CONFIG=siem.conf
SIEM_HOST=<collector address>
SIEM_PORT=514
SIEM_MODE=tcp        # or udp
```
then `docker compose up -d siem-forwarder`. Events go as RFC 5424 syslog with
the CEF text as the message. CEF severity: CRITICAL 10, HIGH 8, MEDIUM 5, LOW 3;
rolled-back changes 6.

## Notes

- Events are pushed best-effort: if the forwarder is down, the webhook call
  fails quietly and the audit operation is not blocked. For guaranteed delivery,
  also collect the full CEF report from `GET /api/reports/{run}/cef`.
- Syslog here is unencrypted. For a collector across a network boundary, use a
  TLS-capable Fluent Bit output or an stunnel in front of the collector.
- Conversion lives in `infra/fluent-bit/cef.lua`.
