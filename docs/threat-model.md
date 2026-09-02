# Q-Cap Prototype Threat Model

This document describes the security assumptions, attacker model, non-goals, and residual risks for the current Q-Cap prototype. It is not a formal security audit and does not claim production readiness.

## Scope

This threat model covers the implemented MVP flow:

- local development identities
- plaintext `pack` archives
- encrypted `seal` archives
- manifest and payload verification
- signed JSON capability tokens
- CLI-enforced path/audience/expiry checks
- optional signed revocation lists
- local Go development registry publish/fetch behavior

Future ideas such as embedded Trust Anchors, COSE tokens, macaroons, policy graphs, WASM lenses, differential privacy budgets, post-quantum crypto, production registry auth, KMS/HSM integration, and transparency logs are out of scope because they are not implemented.

## Assets

Q-Cap is intended to protect or preserve:

- payload confidentiality for sealed archives
- payload integrity through Merkle verification
- manifest authenticity through ed25519 signatures
- issuer identity for the current package signer
- recipient access to wrapped content keys
- capability intent: root, operation, path caveat, audience, and expiry
- revocation intent when callers supply a revocation source
- archive portability across storage and registry locations

The prototype does not protect:

- local identity JSON files at rest
- metadata confidentiality in `manifest.json`
- access decisions made by non-Q-Cap tooling that ignores capabilities
- revocation freshness unless the caller supplies and trusts a current revocation source
- per-path confidentiality after a recipient obtains the package content key

## Trust Boundaries

The main trust boundaries are:

- issuer identity file to generated archive
- recipient identity file to wrapped content-key access
- archive bytes loaded from disk or registry to verifier
- capability JSON loaded from disk to `qcap open`
- optional revocation JSON loaded from disk or URL to `qcap open`
- registry storage to CLI fetch/open behavior
- local filesystem export directory to caller-controlled environment

The CLI is part of the trusted computing base for the MVP. Path-scoped authorization depends on the CLI choosing which decrypted files to export.

## Trusted Components

The MVP assumes:

- Rust and Go runtime behavior is correct enough for the prototype
- cryptographic libraries implement XChaCha20-Poly1305, X25519, ed25519, and BLAKE3 correctly
- the local machine executing `qcap` is not compromised
- identity files are generated and stored by trusted operators
- users do not intentionally bypass the CLI export policy after obtaining decrypted content
- callers supply current revocation data when revocation matters

## Attacker Model

The MVP should resist these attacks:

- modifying payload files inside an archive without detection
- modifying signed manifest bytes without detection
- presenting a capability token signed by an unrelated key
- presenting a capability for a different archive root
- presenting an expired capability
- presenting a capability for the wrong audience
- opening files outside the capability path pattern through the current CLI
- presenting a revocation list signed by an unrelated key
- using path traversal entries to write outside the export directory
- publishing or serving corrupted archives that fail local verification

The MVP does not currently resist these attacks:

- compromise of issuer or recipient identity JSON files
- compromise of the machine running the CLI
- compromise of recipient after the package content key has been unwrapped
- an authorized recipient extracting all encrypted payloads with modified or alternate tooling
- stale revocation data, missing revocation data, or callers that do not check revocations
- malicious registry behavior beyond serving bytes that clients can verify
- registry namespace squatting or artifact replacement
- metadata disclosure through plaintext manifest fields
- collision or ambiguity from truncated development issuer identifiers
- cross-implementation canonicalization disagreements
- sophisticated side-channel attacks
- denial of service through large, malformed, or intentionally expensive archives

## Security Goals

For the current prototype, success means:

- sealed payload bytes cannot be decrypted without a wrapped content key for the recipient identity
- archive verification detects payload tampering
- archive verification detects signed manifest tampering
- `qcap open` rejects self-signed attacker capabilities for an existing archive
- `qcap open` only exports files allowed by the current path matcher
- `qcap open` rejects revoked capabilities when a valid revocation list is supplied
- the dev registry can be treated as untrusted storage for artifacts that clients verify locally

## Non-Goals

The prototype explicitly does not aim to provide:

- production-grade identity management
- production-grade key storage
- multi-issuer Trust Anchor governance
- cryptographic per-path least privilege
- mandatory online revocation checking
- registry-backed provenance guarantees
- stable cross-language format compatibility
- regulated-environment compliance on its own
- complete SDK coverage
- full geospatial interoperability certification

## Current Controls

Implemented controls include:

- XChaCha20-Poly1305 encryption for sealed payload files
- X25519-derived wrapping keys for recipient content-key access
- BLAKE3 Merkle root over payload files
- ed25519 signatures over serialized manifest bytes
- capability signature verification
- same-signer enforcement between archive signer, capability signer, and revocation signer
- capability root, audience, expiry, operation, and path checks
- optional signed revocation-list checks
- rejection of unsafe payload paths on export
- CI for Rust tests, Go tests, TypeScript stub build, and the PowerShell demo

## Residual Risks

Important residual risks remain:

- Same-signer enforcement is a temporary substitute for real Trust Anchors.
- Serialized JSON signing is not yet a canonical cross-language format.
- Capability token signing uses a delimiter payload, not structured canonical signing.
- Path caveats use simple matching rules rather than a formal policy grammar.
- Revocation is optional and freshness is undefined.
- The registry stores and serves data but does not validate trust semantics on upload.
- Local identity files store raw private keys.
- One package content key means path capabilities govern export behavior, not cryptographic separation.

## Review Checklist

Before broad external use, Q-Cap should have:

- canonical serialization for signed manifests and tokens
- a Trust Anchor and key-rotation design
- formal path policy grammar and negative tests
- revocation freshness and fail-open/fail-closed rules
- encrypted or externalized private-key storage
- registry validation and namespace rules
- dependency and release assurance checks
- external cryptographic design review

