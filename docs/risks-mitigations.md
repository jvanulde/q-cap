# Risks & Mitigations

This document tracks risks for the current prototype and planned mitigations. It is not a normative security specification.

## Prototype Status Risk

**Risk:** Q-Cap can be mistaken for a hardened security product or stable file format.

**Current mitigation:** README and docs now describe the repository as a local prototype / MVP demo.

**Remaining work:** Publish a stable spec only after canonical serialization, identity, trust anchors, revocation freshness, path grammar, and registry behavior are defined.

## Capability Signer Trust

**Risk:** A capability signed by an arbitrary key could authorize access if issuer trust is not checked.

**Current mitigation:** `qcap open` now requires the capability signer public key to match the archive manifest signer public key.

**Remaining work:** Replace the single-signer shortcut with a real Trust Anchor model that can support multiple authorized issuers.

## Capability Token Serialization

**Risk:** Current capability signing uses a delimiter string (`cap_root|allow|expires`). This is fragile and not a stable protocol format.

**Current mitigation:** The docs now label this as prototype serialization.

**Remaining work:** Define canonical structured signing, likely with deterministic JSON, CBOR, or a standard token envelope.

## Path Authorization

**Risk:** Path authorization is simple prefix/suffix/exact matching. Ambiguous path rules can become authorization bugs.

**Current mitigation:** Payload writes reject absolute paths, parent-directory components, root components, platform prefixes, and empty paths.

**Remaining work:** Define a formal path grammar, escaping rules, Unicode normalization, case-sensitivity, deny precedence, and edge-case tests.

## Cryptographic Compartmentalization

**Risk:** The sealed package currently uses one content key. Path-scoped capabilities control CLI export, not cryptographic per-path access.

**Current mitigation:** Docs now describe current behavior as capability-gated export for intended recipients.

**Remaining work:** Decide whether Q-Cap needs hard per-path cryptographic least privilege. If yes, implement per-file keys, per-policy keys, or another compartmentalized key hierarchy.

## Manifest Authenticity

**Risk:** Signing only the Merkle root leaves non-root manifest metadata unauthenticated.

**Current mitigation:** New archives sign serialized manifest bytes, and tests reject manifest metadata tampering.

**Remaining work:** Define canonical serialization so signatures are stable across implementations.

## Revocation Semantics

**Risk:** Revocation is soft and optional. If a caller does not provide a revocation file or URL, revoked tokens are not checked.

**Current mitigation:** Revocation lists are signed, `qcap open` requires the revocation signer to match the archive signer, and `qcap revoke` rejects mismatched issuers.

**Remaining work:** Define freshness requirements, offline behavior, stale-list behavior, registry validation, and whether some deployments require fail-closed revocation checks.

## Development Key Storage

**Risk:** Local identity JSON files store raw private key material.

**Current mitigation:** Docs label identity JSON as development-only.

**Remaining work:** Add encrypted keyfiles, passphrase protection, KMS/HSM integration guidance, key rotation docs, and secret-scanning checks.

## Registry Trust

**Risk:** The Go registry is a development file server but could be mistaken for a trusted provenance service.

**Current mitigation:** Docs now call it a dev registry and describe what it does not validate.

**Remaining work:** Add upload validation, artifact immutability, namespace control, audit logs, issuer binding, reader auth if needed, durable object storage, and operational monitoring.

## SDK And Ecosystem Claims

**Risk:** The repo can imply SDK maturity that does not exist.

**Current mitigation:** README and docs state that the TypeScript SDK is a stub and Python is planned.

**Remaining work:** Decide MVP SDK scope. At minimum, implement inspect/verify in TypeScript or remove SDK positioning from MVP claims.

## Geospatial Claims

**Risk:** A one-point GeoPackage fixture can be overread as full geospatial interoperability.

**Current mitigation:** Docs describe the current demo as preserving a simple GeoPackage byte-for-byte.

**Remaining work:** Test larger GeoPackages, common GIS tools, rasters, GeoParquet/STAC metadata, and partial verification behavior.

## Supply Chain And Release Assurance

**Risk:** Security language can imply more release assurance than CI provides.

**Current mitigation:** CI now runs Rust tests, Go tests, and the TypeScript stub build.

**Remaining work:** Add CodeQL, dependency audit, SBOM generation, Trivy/image scanning if containers are introduced, signed releases, and release provenance.

## Future Design Risks

The following ideas remain future design work and should not be represented as implemented:

- embedded Trust Anchors
- COSE tokens
- TLV container sections
- policy graphs
- deterministic WASM lenses
- differential privacy budgets
- vector indexes
- post-quantum or hybrid cryptography
- append-only in-capsule updates
- multi-authority decentralized issuance
