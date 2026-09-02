# Capability Tokens

Capability tokens are separate signed JSON files that tell the current CLI which payload paths may be exported for a specific recipient identity.

They are not embedded in the `.qcap` archive.

## Current Token Shape

Current fields:

```json
{
  "cap_root": "blake3:<payload-merkle-root>",
  "allow": "read;path=reports/*;aud=<recipient-id>",
  "expires": "unix-seconds:9999999999",
  "signature": "<ed25519-signature-hex>",
  "public_key": "<issuer-public-key-hex>",
  "algorithm": "ed25519"
}
```

The current signed payload is:

```text
cap_root|allow|expires
```

This is a prototype serialization. It should become canonical structured signing before the format is treated as stable.

## What A Capability Currently Means

In the MVP, a capability can authorize:

- operation: currently only `read`
- audience: recipient identity id
- path: simple path pattern
- expiry: `unix-seconds:<ts>`

Example:

```bash
qcap grant dataset.qcap \
  --issuer issuer.identity.json \
  --audience <recipient-id> \
  --path "reports/*" \
  --expires unix-seconds:9999999999 \
  --out cap.json
```

## Enforcement

`qcap open` enforces capability checks before exporting files.

The CLI verifies:

- archive signature and Merkle root
- capability signature
- capability signer equals archive signer
- capability root equals archive root
- audience matches the local identity
- expiry has not passed
- requested paths match the allowed path caveat
- optional revocation list does not revoke the token

## Important Limitation

The current sealed archive uses one content key for the whole package. Path scoping is enforced by the CLI during export. It is not cryptographic per-path compartmentalization.

If Q-Cap needs hard cryptographic least privilege by path, the design should move to per-file keys, per-policy keys, or another compartmentalized key schedule.

## Path Patterns

Current path matching is deliberately simple:

- `*` matches all paths
- `reports/summary.txt` matches exactly that path
- `reports/*` matches paths with the `reports/` prefix
- `*.gpkg` matches paths with the `.gpkg` suffix

There is no complete glob grammar yet.

## Future Capability Model

Future versions may support:

- COSE or another standard token envelope
- embedded Trust Anchors
- multiple issuers
- delegated/attenuated capabilities
- structured caveats instead of string parsing
- richer selectors
- policy graph integration
- lens execution
- privacy budget controls

Those are not implemented in the current MVP.
