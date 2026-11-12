# Registry authentication

The registry supports OIDC-authenticated token administration and scoped personal
access tokens (PATs) for automation. This is an administration **API**, not an
interactive browser-login implementation. Obtain an ID token through your identity
provider's supported login client. The registry does not implement a redirect,
callback, cookie session, or password login.

## Configure an identity provider

Configure a dedicated OIDC client/audience for Q-Cap administration. Set all three:

| Environment variable | Meaning |
| --- | --- |
| `QCAP_REGISTRY_OIDC_ISSUER` | Exact HTTPS issuer URL advertising OIDC discovery and HTTPS JWKS |
| `QCAP_REGISTRY_OIDC_CLIENT_ID` | Required ID-token audience; use a dedicated Q-Cap client |
| `QCAP_REGISTRY_OIDC_ADMIN_SUBJECTS` | Comma-separated exact `sub` identifiers authorized to administer tokens |

Subjects are not email addresses, display names, or group claims. The verifier
checks signature, issuer, audience, expiry, and authorized party (`azp` when
present, required for multiple audiences). Discovery/JWKS requests require HTTPS
and have a 10-second timeout. Invalid/partial configuration, discovery failure,
or a corrupt token store aborts startup; they never turn authentication off.

Compose passes these environment variables through. Helm exposes
`auth.oidc.issuer`, `auth.oidc.clientID`, and `auth.oidc.adminSubjects`.
No OIDC client secret is stored: the registry verifies externally obtained ID
tokens and does not perform the interactive authorization-code exchange itself.

## Administer automation tokens

All `/admin/tokens` operations require `Authorization: Bearer <OIDC-ID-token>`.
PATs and the legacy shared token cannot administer tokens. Responses use
`Cache-Control: no-store`; do not record the bearer header or creation response
in proxy logs. Use HTTPS between callers and your registry ingress.

| Method and endpoint | Result |
| --- | --- |
| `POST /admin/tokens` | Create a token; plaintext `token` returned once |
| `GET /admin/tokens` | List token metadata, never token secrets or hashes |
| `DELETE /admin/tokens/<id>` | Revoke a token (204); unknown ID returns 404 |

Creation body (replace the expiry with a future RFC3339 timestamp no more than
90 days away):

```json
{
  "name": "publisher-job",
  "scopes": ["artifacts:write"],
  "expires_at": "2026-11-01T00:00:00Z"
}
```

Available scopes are `artifacts:write` and `revocations:write`. An empty scope
list, unsupported/duplicate scopes, empty name, expired or excessive lifetime,
unknown JSON fields, and oversized request bodies are rejected. An administrator
can list and revoke every token; the issuing subject is recorded. Removing that
  subject from the administrator configuration invalidates its PATs after restart.

Use the returned PAT with the existing CLI `--token` or
`QCAP_REGISTRY_TOKEN` input for `publish` and `publish-revocations`. No CLI changes
are needed. OIDC tokens are only accepted by the admin API; automation endpoints
require a PAT or the explicitly configured legacy shared token.

## Storage, rotation, and compatibility

- Tokens have 256-bit random secrets; only SHA-256 digests are persisted in
  `<store>/.auth/pats.json`. That path is not an artifact/download endpoint.
- State is persisted before successful creation/revocation responses and survives
  restart. The file uses mode 0600 on Unix; apply equivalent account ACLs on Windows.
- Token rotation is create replacement, update the client, then revoke the old ID.
  Expired records remain visible until deleted. There is no refresh-token mechanism.
- Persist and back up the entire registry volume, including `.auth`. Restoring an
  older backup can restore revoked tokens; reconcile/revoke them before reopening
  service. An issuer/client/subject configuration change requires restart. PATs
  are bound to their issuing OIDC issuer and client ID; changing either invalidates
  the old credentials, even if subject identifiers happen to match.
- Run **one registry process/replica per store**. Locks are process-local, not
  distributed. PAT state is not a multi-node identity database.
- Existing `QCAP_REGISTRY_TOKEN` remains an unscoped compatibility credential for
  both write routes. Remove it after PAT migration to remove that bypass of scope
  and expiry policy. It never grants admin access.
- With neither OIDC nor a legacy token configured, writes remain anonymous for
  local-demo compatibility. Never expose that mode to untrusted callers.
- Reads and health endpoints remain public. This increment does not implement
  per-artifact reader authorization, tenant isolation, browser sessions, audit-log
  infrastructure, or rate limiting. Use network/ingress controls as appropriate.

The registry requires Go 1.25+ for its OIDC library; CI/container builds use the
patched Go 1.27.3 toolchain. No live provider or production deployment is created
by enabling these code paths in the repository.
