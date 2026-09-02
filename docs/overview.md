# Q-Cap Overview

Q-Cap is currently a working local prototype for encrypted, signed content packages with capability-gated export through the Rust CLI.

The implemented prototype proves a narrow but useful workflow:

- create local development identities
- seal a directory into an encrypted `.qcap` ZIP archive
- sign the serialized manifest
- verify the manifest signature and payload Merkle root
- publish and fetch artifacts through the local Go development registry
- issue signed capability tokens for an audience and path pattern
- open/export only paths allowed by the capability
- optionally check signed soft revocation lists

This repository should not yet be described as a hardened security product, stable open standard, complete SDK ecosystem, or production registry. For security assumptions and non-goals, see [threat-model.md](threat-model.md).

## Implemented Components

- `core/qcap-core`: Rust library for manifest structs, archive helpers, payload Merkle roots, signatures, and capability token helpers.
- `core/qcap-cli`: Rust CLI for `init`, `pack`, `seal`, `verify`, `inspect`, `grant`, `open`, `revoke`, `publish`, `fetch`, revocation publish/fetch, and sample GeoPackage generation.
- `services/qcap-registry`: local Go development registry for artifact storage, index serving, token-protected publishing, and revocation document serving.
- `sdks/ts`: TypeScript SDK stub only.
- `api/proto`: protobuf placeholder only.

## Current Security Model

The MVP uses:

- XChaCha20-Poly1305 for per-file encryption
- X25519-derived key wrapping for recipient content-key access
- BLAKE3 Merkle roots over payload files
- ed25519 signatures over serialized manifest bytes
- signed JSON capability tokens with `cap_root`, `allow`, `expires`, `signature`, `public_key`, and `algorithm`
- optional signed JSON revocation lists

`qcap open` currently accepts a capability only when:

- the archive verifies
- the capability signature verifies
- the capability signer matches the archive signer
- the capability root matches the archive Merkle root
- the operation is `read`
- the audience matches the local identity
- the expiry has not passed
- the path pattern allows at least one payload file
- any supplied revocation list is signed by the archive signer and does not revoke the capability

## Important Limits

- Path scoping is enforced by the CLI, not by per-path cryptographic keys.
- The archive currently uses one content key per sealed package.
- Revocation is soft and optional; callers must provide a revocation file or URL.
- There is no embedded Trust Anchor model yet.
- Current capability tokens are not macaroons and are not COSE tokens.
- There is no DP budget, policy graph, WASM lens runtime, vector index, or post-quantum/hybrid crypto implementation.
- Local identity JSON files contain raw development key material and are not production key storage.

## Direction

The intended direction is an artifact-centric data governance format: portable packages that can be mirrored openly while content access, verification, provenance, and policy are enforced close to the artifact.

To get there, the next major work should focus on:

- a real format specification
- continued threat-model review as implementation changes
- canonical signing rules
- a trust-anchor model
- key rotation and revocation freshness semantics
- a formal path policy grammar
- production registry validation and audit behavior
- actual SDKs
- external cryptographic review
