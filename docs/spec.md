# Q-Cap Prototype Specification

This document describes the current implemented prototype. It is not a stable public standard.

## Archive Layout

A `.qcap` file is currently a ZIP archive with this layout:

```text
manifest.json
payload/<relative payload paths>
meta/
signatures/manifest.sig.json
```

Payload paths must be relative UTF-8 paths. Absolute paths, empty paths, parent-directory components, root components, and platform prefixes are rejected when writing files.

## Manifest

`manifest.json` is serialized from the Rust `QcapManifest` struct.

Current fields:

- `schema_version`: prototype schema version string.
- `merkle_root`: BLAKE3 payload Merkle root as `blake3:<hex>`.
- `issuer`: optional issuer identifier. Current sealed archives use the first 16 hex characters of the issuer signing public key; this is a development shortcut, not a production identity model.
- `created_at`: currently `unix-seconds:<ts>`, despite older docs referring to RFC3339.
- `metadata`: free-form JSON object.
- `package_id`: random package identifier for sealed archives.
- `encrypted`: boolean.
- `files`: encrypted payload metadata entries.
- `recipients`: recipient key-wrap stanzas.
- `algorithms`: descriptive algorithm strings.

For encrypted payload files, `files[]` entries contain:

- `path`
- `size`
- `nonce`
- `ciphertext_hash`

Recipient stanzas contain:

- `recipient`: recipient encryption public key.
- `ephemeral_public_key`
- `nonce`
- `wrapped_key`
- `algorithm`

## Payload Merkle Root

The prototype computes a deterministic BLAKE3 Merkle root over all payload files.

Each leaf hash is:

```text
blake3(relative_path_bytes || 0x00 || file_contents)
```

Leaves are sorted by relative path. Parent nodes hash concatenated child digests. An odd leaf is promoted to the next level. The final value is encoded as `blake3:<hex>`.

For sealed archives, the Merkle root is computed over ciphertext payload files.

## Manifest Signature

New archives sign the serialized `manifest.json` bytes with ed25519.

`signatures/manifest.sig.json` contains:

- `merkle_root`
- `signature`
- `public_key`
- `algorithm`

The current manifest-signature algorithm string is:

```text
ed25519:manifest
```

Verification requires:

- the signature validates over the exact serialized manifest bytes in the archive
- the recomputed payload Merkle root equals `manifest.merkle_root`
- the recomputed payload Merkle root equals `signature.merkle_root`

Older root-only signatures are not the current write path.

## Encryption

Sealed archives use one random 32-byte content key per package.

Each payload file is encrypted with XChaCha20-Poly1305 using:

- key: package content key
- nonce: random 24-byte file nonce
- AAD: relative payload path bytes

The content key is wrapped for the recipient using:

- X25519 shared secret from an ephemeral sender key and recipient encryption key
- BLAKE3-derived wrapping key using domain separator `qcap-wrap-key-v1` and package id
- XChaCha20-Poly1305 with package id as AAD

Current limitation: path-level access is not cryptographically compartmentalized because the sealed package uses one content key.

## Capability Tokens

Current capability tokens are signed JSON objects, not macaroons and not COSE tokens.

Fields:

- `cap_root`: archive Merkle root.
- `allow`: operation and caveats encoded as a prototype string, for example `read;path=reports/*;aud=<identity-id>`.
- `expires`: currently `unix-seconds:<ts>`.
- `signature`: ed25519 signature.
- `public_key`: signing public key.
- `algorithm`: currently `ed25519`.

The signed payload is currently:

```text
cap_root|allow|expires
```

This delimiter format is a prototype detail and should be replaced by canonical structured signing before format stabilization.

`qcap open` accepts a capability only when:

- the capability signature verifies
- the capability public key matches the archive manifest signer public key
- `cap_root` matches the archive Merkle root
- the operation is `read`
- the audience matches the local identity id
- the expiry is valid and not expired
- at least one payload path is allowed

## Path Caveats

The current path matcher is intentionally small:

- `*` allows all paths
- exact path allows only that path
- suffix `*` means prefix match
- prefix `*` means suffix match

There is no formal glob grammar yet. Case sensitivity, Unicode normalization, escaping, deny rules, and precedence are not specified.

## Revocation Lists

Revocation is soft and optional.

`qcap open` checks revocations only when a revocation file or URL is supplied.

Revocation documents contain:

- `schema_version`
- `revoked`
- `signature`
- `public_key`
- `algorithm`

Each revoked entry contains:

- `cap_root`
- `capability_signature`
- `revoked_at`
- `reason`

The revocation list signature must validate, and the revocation list public key must match the archive manifest signer public key.

The Go development registry stores and serves revocation documents, but it does not currently validate the document signature or issuer binding on upload.

## Registry

The Go registry is a development file registry.

Implemented behavior:

- `GET /health`
- `GET /index.json`
- `GET /index`
- `POST /artifacts`
- `GET /artifacts/<name>`
- `POST /revocations/<issuer>/revocations.json`
- `GET /revocations/<issuer>/revocations.json`

When `QCAP_REGISTRY_TOKEN` is set, publish endpoints require `Authorization: Bearer <token>`.

The registry does not currently provide production authentication, reader authorization, manifest validation, namespace control, immutability guarantees, audit logs, object storage, Postgres indexing, Redis caching, OIDC, gRPC, or transparency logging.

## Compatibility Status

The current format is prototype-only. Do not rely on backward compatibility until canonical serialization, identity, trust-anchor, revocation freshness, and path-policy rules are stabilized.
