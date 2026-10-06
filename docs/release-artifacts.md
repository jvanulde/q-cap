# Release artifacts and verification

Q-Cap releases after `0.2.0` are built by
[`release.yml`](../.github/workflows/release.yml) from a canonical `X.Y.Z` tag.
The existing `0.2.0` pre-release remains source-only; artifacts are not added
to an already published tag after the fact.

## Published artifacts

Each release publishes native `qcap` CLI archives for:

- Linux x86-64
- Linux ARM64
- Windows x86-64
- macOS x86-64
- macOS ARM64

Every CLI archive has:

- a `.sha256` checksum;
- SPDX JSON and CycloneDX JSON SBOMs;
- a `.sigstore.json` keyless Cosign signature bundle;
- GitHub build-provenance and SBOM attestations.

The workflow also publishes a multi-architecture registry image for
`linux/amd64` and `linux/arm64`:

```text
ghcr.io/jvanulde/qcap-registry:<version>
```

Release assets include the immutable image digest and standalone SPDX and
CycloneDX SBOMs. The image digest is signed with keyless Cosign and has
BuildKit provenance/SBOM attestations plus GitHub provenance/SBOM attestations
attached in GHCR.

Version tags are intentionally the only human-readable release image tags.
Q-Cap does not publish `latest` while the project remains a pre-1.0 prototype.

## Verify a CLI archive

First verify the checksum from the directory containing the archive and its
`.sha256` file:

```bash
sha256sum --check qcap-0.3.0-linux-x86_64.tar.gz.sha256
```

Then verify the Sigstore bundle. Replace the version and platform as needed:

```bash
cosign verify-blob qcap-0.3.0-linux-x86_64.tar.gz \
  --bundle qcap-0.3.0-linux-x86_64.tar.gz.sigstore.json \
  --certificate-identity \
    https://github.com/jvanulde/q-cap/.github/workflows/release.yml@refs/tags/0.3.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify GitHub build provenance independently:

```bash
gh attestation verify qcap-0.3.0-linux-x86_64.tar.gz \
  --repo jvanulde/q-cap
```

These checks prove that the archive was produced and signed by the tagged
Q-Cap release workflow. They do not make the prototype format or CLI a stable,
audited security product.

## Verify the registry image

Read the digest from `qcap-registry-<version>.digest.txt` and use the complete
digest reference rather than trusting a mutable tag:

```bash
image=ghcr.io/jvanulde/qcap-registry@sha256:<digest>

cosign verify "$image" \
  --certificate-identity \
    https://github.com/jvanulde/q-cap/.github/workflows/release.yml@refs/tags/0.3.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "oci://$image" --repo jvanulde/q-cap
```

The package must be public in GHCR for anonymous pulls. On the first publish,
the repository owner should verify the package is linked to `jvanulde/q-cap`,
inherits its access policy, and has public visibility before announcing it.

## Maintainer release flow

1. Prepare and merge a release PR that updates package versions and adds a
   reviewed `## [X.Y.Z]` changelog section.
2. Verify canonical `main` CI and security workflows at the merge commit.
3. Create and push an `X.Y.Z` tag that points to canonical `main`.
4. The release workflow verifies the tag, package versions, changelog section,
   and ancestry before receiving privileged permissions.
5. The workflow builds, signs, attests, and publishes the CLI archives and
   container image, then creates the GitHub pre-release for `0.x` versions.
6. Verify the published release assets, GHCR digest, Cosign signatures, and
   GitHub attestations before announcing the release.

The workflow refuses to overwrite an existing GitHub release or versioned
container tag. A partial publication failure must be inspected and repaired
deliberately rather than silently replacing previously published artifacts.

## Trust boundary

Pull requests run only an unprivileged release smoke build. OIDC,
`attestations: write`, `packages: write`, and `contents: write` are granted only
to jobs reached from a canonical tag push. All third-party actions in the
release workflow are pinned to immutable commits.

Keyless signing binds artifacts to the GitHub Actions workflow identity and
records the signing event in Sigstore's transparency infrastructure. GitHub
artifact attestations are a separate provenance channel and should be checked
independently where policy permits.
