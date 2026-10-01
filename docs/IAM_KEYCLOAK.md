# Identity and access management with Keycloak

NetAudit can take identities and roles from Keycloak instead of its local
`users` table. The login form is unchanged: the gateway exchanges the
email/password with Keycloak, then verifies every request's Keycloak-signed
(RS256) token — signature, issuer, expiry, and that it was issued to the
`netaudit-web` client. Approvals and ledger entries use that verified user id.

## Turn it on

1. In `.env` set `KEYCLOAK_ADMIN_PASSWORD`, `KC_DEMO_PASSWORD` (initial password
   of the three demo users) and `AUTH_PROVIDER=keycloak`.
2. `docker compose --profile iam up -d keycloak gateway`
3. Sign in as `admin@`, `operator@` or `auditor@netaudit.local` with the
   `KC_DEMO_PASSWORD`. Manage users at the Keycloak console (port 8080 inside
   the network; publish it only for administration).

Unset `AUTH_PROVIDER` (default `local`) to go back to the users table.

## Roles

| Keycloak realm role | Can |
|---|---|
| `admin` | everything |
| `operator` | upload, generate and (low-risk) approve fixes |
| `auditor` | read audits and reports |

A user with several roles gets the highest. A Keycloak user with none of
these roles can sign in to Keycloak but every NetAudit call returns 403.

## Before production

- Run Keycloak with `start` (not `start-dev`), a Postgres database, TLS and a
  real hostname; set `sslRequired` to `external` or `all` in the realm.
- The login form uses the password grant so the existing UI keeps working.
  For SSO/MFA/smart-card login, move the frontend to the authorization-code
  flow with PKCE and let Keycloak show its own login page.
- Replace the demo users and the shared demo password.
- What this does not do: sign ledger rows. The ledger records the verified
  Keycloak user id, but rows themselves are not cryptographically signed.
