# Changelog

All notable changes to Q-Cap are documented in this file.

Q-Cap follows [Semantic Versioning](https://semver.org/). Releases before 1.0 may introduce breaking changes between minor versions.

## [Unreleased]

### Added

- Automated tagged-release builds for native CLI archives and the multi-architecture registry image, including SHA-256 checksums, SPDX/CycloneDX SBOMs, keyless Cosign signatures, and GitHub provenance/SBOM attestations.

## [0.2.0] - 2026-09-28

This is a pre-release milestone for the working local prototype. The `.qcap` format, CLI output, registry API, and SDK interfaces are not yet stable.

### Added

- End-to-end CLI flows for identity initialization, packing, sealing, verification, inspection, capability grants, authorized opening, revocation, and registry publication/fetch.
- Signed manifest verification, BLAKE3 payload Merkle validation, per-file XChaCha20-Poly1305 encryption, recipient key wrapping, signed capability tokens, and signed soft revocation lists.
- A Go development registry with archive validation, atomic persistence, revocation distribution, seeded demo artifacts, and integration coverage.
- Container, Docker Compose, and single-replica Kubernetes Helm deployment assets for the development registry.
- A prototype threat model, format documentation, deployment guidance, and security-risk documentation.
- CI coverage for Rust, Go, TypeScript, the Windows demo, registry integration, and deployment checks.
- CodeQL analysis, Trivy repository and image scanning, and SPDX/CycloneDX image SBOM artifacts.

### Changed

- Hardened issuer binding, authorized path export, revocation checks, registry upload validation, overwrite safety, and concurrent index updates.
- Clarified that Q-Cap remains a prototype rather than a stable format, production registry, or audited security product.

### Known limitations

- Local identity files contain unencrypted development key material; Argon2id-protected keyfiles and KMS/HSM integration are not implemented.
- Capability serialization is prototype-only and does not yet provide canonical structured signing or attenuation.
- The registry lacks production authentication, namespace ownership, distributed storage, audit logging, and horizontal scaling.
- The TypeScript package is a stub, and Python bindings are not implemented.
- Release signing and provenance are not yet implemented.

[Unreleased]: https://github.com/jvanulde/q-cap/compare/0.2.0...HEAD
[0.2.0]: https://github.com/jvanulde/q-cap/compare/0.1.0...0.2.0
