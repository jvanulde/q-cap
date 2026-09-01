# Historical MVP Implementation Brief

This file is historical context. It is not the current Q-Cap specification.

The original brief was used to guide the first MVP implementation pass when the repository still had only a minimal hash command and scaffolding. The implemented prototype has since moved beyond that state.

For current behavior, read:

- `docs/overview.md`
- `docs/spec.md`
- `docs/mvp-notes-core.md`
- `README.md`

## Current Prototype Summary

The current MVP includes:

- Rust core helpers for manifests, ZIP archives, payload Merkle roots, signatures, and capability tokens.
- Rust CLI commands for identity creation, pack, seal, verify, inspect, grant, open, revoke, publish/fetch, revocation publish/fetch, and sample GeoPackage generation.
- Go development registry for local artifact storage, index serving, token-protected publishing, and revocation document serving.
- TypeScript SDK stub.
- Protobuf placeholder.

## Differences From The Original Brief

The original brief referred to several ideas that are not current implemented behavior:

- macaroons-style capabilities
- RFC3339 expiry
- future TLV container evolution
- richer policy and selector systems
- WASM lenses

Current capability tokens are signed JSON objects. They are not macaroons and not COSE tokens.

Current expiry strings use `unix-seconds:<ts>`.

Current archive signatures cover serialized manifest bytes, and `qcap open` requires capability and revocation signers to match the archive signer.

## Current Open Work

The next implementation and documentation work should focus on:

- canonical manifest/token serialization
- a real trust-anchor model
- formal path policy grammar
- registry upload validation
- publish/fetch integration tests
- production key storage guidance
- license and citation cleanup
- actual SDK behavior

Keep this file only as a record of the early MVP direction. Do not use it as the source of truth for implementation.
