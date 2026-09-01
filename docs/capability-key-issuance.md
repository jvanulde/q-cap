# Capability Issuance

This document describes the implemented MVP behavior and the intended future trust-anchor model.

## Current MVP Model

In the current prototype, the same issuer key signs:

- the `.qcap` manifest
- capability tokens for that archive
- revocation lists for those capability tokens

`qcap open` rejects a capability unless the capability signer's public key matches the archive manifest signer's public key.

This is a deliberately small trust model. It closes the earlier self-signed-token hole, but it is not the final decentralized Trust Anchor design.

## Current Issuance Flow

1. The producer creates an issuer identity:

   ```bash
   qcap init --name issuer --out issuer.identity.json
   ```

2. The producer seals a package:

   ```bash
   qcap seal payload/ \
     --issuer issuer.identity.json \
     --recipient recipient.identity.json \
     --out dataset.qcap
   ```

3. The producer grants a capability for a recipient identity id:

   ```bash
   qcap grant dataset.qcap \
     --issuer issuer.identity.json \
     --audience <recipient-id> \
     --path "reports/*" \
     --expires unix-seconds:9999999999 \
     --out cap.json
   ```

4. The recipient opens the package:

   ```bash
   qcap open dataset.qcap \
     --cap cap.json \
     --identity recipient.identity.json \
     --out exported/
   ```

## Current Validity Rules

A capability is valid for an archive only when:

- the archive manifest signature verifies
- the archive payload Merkle root verifies
- the capability signature verifies
- the capability signer public key matches the archive manifest signer public key
- the capability `cap_root` equals the archive Merkle root
- the operation is `read`
- the audience equals the recipient identity id
- the expiry is supported and not expired
- the path caveat allows at least one payload file

## Current Revocation Flow

The issuer can create or update a signed revocation list:

```bash
qcap revoke \
  --cap cap.json \
  --issuer issuer.identity.json \
  --reason rotation \
  --out revocations.json
```

`qcap revoke` rejects an issuer that did not sign the capability.

`qcap open` only checks revocation when the caller provides a local revocation file or revocation URL:

```bash
qcap open dataset.qcap \
  --cap cap.json \
  --identity recipient.identity.json \
  --revocations revocations.json \
  --out exported/
```

Revocation is therefore soft and distribution-dependent in the MVP.

## Not Implemented Yet

The current prototype does not implement:

- embedded Trust Anchors
- multiple authorized issuers per capsule
- COSE signatures
- TLV sections
- key identifiers
- issuer metadata
- threshold issuance
- delegated issuance
- key rotation metadata
- mandatory revocation freshness checks

## Future Direction

The intended future model is for each capsule to declare one or more authorized issuer keys, then accept capability tokens signed by any valid Trust Anchor. That would support federated and offline issuance without requiring all tokens to be signed by the archive's original manifest signer.

That design still needs a concrete specification for:

- trust-anchor encoding
- canonical token signing
- key identifiers
- trust-anchor expiry and revocation
- rotation across immutable capsule versions
- multi-authority governance
- failure behavior when revocation status is stale or unavailable
