# MVP Notes: Current Core & CLI

This note reflects the current local prototype. Older task notes that described only the initial hash command are obsolete.

## qcap-core

`core/qcap-core` provides small building blocks used by the CLI:

- `manifest.rs`: manifest structs for package metadata, encrypted payload file metadata, and recipient key-wrap stanzas.
- `archive.rs`: ZIP archive creation with `manifest.json`, `payload/`, `meta/`, and `signatures/manifest.sig.json`.
- `payload_merkle.rs`: deterministic BLAKE3 Merkle root over payload files.
- `signatures.rs`: ed25519 signing and verification helpers. New archives sign serialized manifest bytes.
- `capabilities.rs`: MVP JSON capability tokens signed with ed25519.

The crate is useful for the prototype but is not yet a stable public SDK.

## qcap-cli

`core/qcap-cli` implements the current end-to-end demo workflow:

- `hash`: BLAKE3 demo hash
- `init`: create local development identity JSON
- `pack`: create plaintext signed `.qcap`
- `seal`: create encrypted signed `.qcap` for one recipient
- `verify`: verify manifest signature and payload Merkle root
- `inspect`: print archive summary
- `grant`: issue a signed capability token
- `open`: verify, authorize, decrypt, and export allowed files
- `revoke`: create/update a signed soft revocation list
- `publish` / `fetch`: push/pull artifacts through the dev registry
- `publish-revocations` / `fetch-revocations`: push/pull revocation lists
- `sample-geopackage`: create a tiny valid GeoPackage fixture

## Current Acceptance Coverage

Rust integration tests cover:

- pack then verify
- payload tamper rejection
- manifest metadata tamper rejection
- grant/open flow
- rejection of an untrusted capability signer
- rejection of a wrong revocation issuer
- revoked capability rejection
- sealed package path filtering
- byte-for-byte GeoPackage export preservation

Remaining test gaps include registry publish/fetch integration, path grammar edge cases, malicious ZIP entries, malformed recipient stanzas, expiry edge cases, and revocation freshness behavior.
