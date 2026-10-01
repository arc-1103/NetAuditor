# Importing CIS/STIG and patch updates into the air-gapped network

NetAudit verifies what arrives; the physical transfer is an operational control
that software cannot provide. Both halves are required.

## 1. Connected build host (outside the air gap)

1. One time: `python tools/airgap_bundle.py keygen <offline-dir>`. Keep
   `bundle_signing.key` offline (hardware token or safe). Publish only
   `bundle_signing.pub`.
2. Author or download the updated policy/template files, review them, then:
   `python tools/airgap_bundle.py pack <key> update.zip services/compliance/policies services/remediation/templates`
3. Record `sha256sum update.zip` in the change ticket.

## 2. Transfer across the gap (pick one, per your site policy)

- **Data diode** (one-way): send `update.zip` through the diode to a landing
  host inside the network.
- **Scanned media kiosk**: copy to new, write-once media; scan with an
  up-to-date malware engine on a dedicated kiosk that is not on either
  network; log the scan result in the ticket; hand over in person.

Container images and OS patches travel the same way (`docker save` / vendor
patch files). Verify their vendor hashes or signatures at the kiosk.

## 3. Air-gapped host

1. Check the ticket hash: `sha256sum update.zip`.
2. Verify without installing: `python tools/airgap_bundle.py import trusted/bundle_signing.pub update.zip --dry-run`
   The public key must already be on the host, installed from a separate,
   earlier channel than the bundle itself.
3. Install: same command without `--dry-run`. Old files are kept as `*.bak`.
4. Reload: `docker compose restart opa`, then
   `docker compose build remediation && docker compose up -d remediation`.
5. Run `docker exec netaudit-opa-1 /opa test /policies` and the remediation
   tests before using the new rules for a real audit.

## Getting device configurations into the ingest gate

Configuration files travel the same way as updates, in the other direction of
risk: they come from production devices, so treat them as untrusted input.

1. Export the configuration on the device side; do not install collectors on
   the isolated network.
2. Move the files across by data diode or scanned media (above). The path must
   end on a **landing directory on a host inside the boundary**, never a
   routable connection from outside.
3. Load them with `python tools/ingest_dropbox.py <landing-dir>` (uses a
   NetAudit operator account), which uploads each `.cfg/.conf/.txt` through the
   normal gateway, then moves it to `processed/` or `failed/`. Every file still
   passes the ingest gate's checks: extension, content type, size limit,
   credential redaction, and hash-based de-duplication.
4. The audit record stores each file's SHA-256, so the file that entered the
   gate can be matched to the one that left the device.

Where a site allows a management-network connection to devices, the online
collector (`COLLECTOR_ENABLED`, see docs/README) is the alternative; in strictly
air-gapped deployments it stays off.

## What the tool rejects

Wrong signing key, any modified file, any file not listed in the signed
manifest, absolute or `..` paths, unknown destination folders, and file types
other than `.rego .j2 .json .yaml .yml`.

## Not covered

Signing protects integrity and origin, not correctness: a signed but wrong
policy still loads. Review policies before signing them. Rotating the signing
key means distributing a new public key through a trusted channel.
