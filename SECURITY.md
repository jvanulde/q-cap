# Security Policy

Q-Cap is security-first software. This document explains how to report vulnerabilities and how we handle them.

## Reporting a Vulnerability

- **Do not open a public issue.**
- Preferred: open a **Private Security Advisory** in GitHub → *Security* → *Advisories* → *Report a vulnerability*.
- Or contact the maintainer.
- Please include:
  - Affected commit/release and environment (OS, versions)
  - Impact and likelihood (what an attacker gains)
  - Reproduction steps or PoC (minimal if possible)
  - Suggested fix/mitigations (if any)

We will acknowledge **within 3 business days** and provide a triage update **within 7 business days**.

## Supported Versions

We provide security fixes for:
- `main` (development head)
- The **latest released minor** (for example, `v0.Y.*` after `v0.(Y+1).0` releases)

Older lines receive fixes at the maintainers’ discretion.

## Response Targets (SLOs)

| Severity  | Target to Mitigate/Release |
|-----------|-----------------------------|
| Critical  | 7 days                      |
| High      | 30 days                     |
| Medium    | 60 days                     |
| Low       | 90 days                     |

Severity is based on CVSS + real-world exploitability in Q-Cap’s context (crypto/key-mgmt features can elevate severity).

## Scope

**In scope**
- Q-Cap repositories and default configurations
- The sample **qcap-registry** service
- Packaging/crypto logic (manifest, Merkle, capabilities)

**Out of scope**
- Social engineering, physical access
- Volumetric DDoS without a concrete protocol flaw
- Third-party services (AWS/GCP/etc.) except where Q-Cap misuses them
- Dependency CVEs with no exploitable impact on Q-Cap usage

## Safe Harbor (Good-Faith Research)

We will not pursue or support legal action for **good-faith** security research that:
- Avoids privacy violations and service degradation
- Respects data and access limitations
- Gives us a reasonable chance to remediate before public disclosure

## Coordinated Disclosure

We prefer **coordinated disclosure**. By default we publish an advisory and credit reporters (opt-out available). We’ll request CVEs as appropriate.

## Secrets & Key Management

- Never commit secrets. Use environment or secret stores (GitHub Actions secrets, cloud KMS, parameter stores).
- Rotate credentials if exposure is suspected.
- Local private keys must be encrypted (Argon2id) and stored outside the repo.
- Production issuer keys should live in **KMS/HSM**; document rotation and access controls.

## Cryptography Notes (MVP)

- AEAD: XChaCha20-Poly1305
- Hash/Merkle: BLAKE3
- Signatures: ed25519
- Capabilities: macaroons with caveats (expiry, audience, paths, purpose)

Changes to these primitives will be announced in the changelog and release notes.

## Accessibility & Inclusion

Security reports are welcome in **English or French**. When describing impacts, consider diverse user contexts (e.g., accessibility, connectivity limits) so we can prioritize effectively.

*Last updated: 2025-09-17*
