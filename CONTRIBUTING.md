# Contributing to Q-Cap

Thanks for helping improve Q-Cap! This guide explains how to set up your environment, propose changes, and submit pull requests.

> By contributing, you agree your work will be licensed under this repo’s **Apache-2.0** license.

---

## Table of contents
- [Code of Conduct](#code-of-conduct)
- [Security first](#security-first)
- [What’s in this repo](#whats-in-this-repo)
- [Prerequisites](#prerequisites)
- [Quick start (build & run)](#quick-start-build--run)
- [Style & quality checks](#style--quality-checks)
- [Commit conventions](#commit-conventions)
- [Pull request checklist](#pull-request-checklist)
- [Issue triage & labels](#issue-triage--labels)
- [Internationalization & accessibility](#internationalization--accessibility)
- [Design & crypto changes](#design--crypto-changes)
- [Release process (high-level)](#release-process-highlevel)
- [Community & support](#community--support)

---

## Code of Conduct
Be kind and inclusive. We follow a **zero-tolerance** policy for harassment or discrimination.  
See **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** for details and reporting channels.

---

## Security first
- **Do not file security bugs in public issues.**  
  Report suspected vulnerabilities via **GitHub private security advisory** or to the maintainer.
- Never commit secrets. Use env vars or secret stores.
- If your change touches crypto, capabilities, or key management, see [Design & crypto changes](#design--crypto-changes) and **link a threat-model note**.

Full policy: **[SECURITY.md](SECURITY.md)**.

---

## What’s in this repo

```
core/
  qcap-core/   # Rust library (crypto, Merkle, capabilities – WIP)
  qcap-cli/    # Rust CLI (demo: hash)
services/
  qcap-registry/  # Go service (REST/gRPC skeleton, health endpoint)
sdks/
  ts/          # TypeScript SDK (WASM) stub
api/
  proto/       # Protobuf definitions (WIP)
.github/workflows/  # CI pipelines
docs/              # Docs stubs
```

---

## Prerequisites

- **Git** & **GitHub CLI** (`gh auth login`)
- **Rust** (stable) — install with `rustup`
- **Go** 1.21+
- **Node.js** (for the TS SDK)
- Optional linters: `clippy`, `staticcheck`, `eslint`

**Windows quick install (PowerShell)**
```powershell
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --silent --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart"
winget install GoLang.Go
```

**macOS quick install (Homebrew)**
```bash
brew install rustup-init go gh node
rustup-init -y
gh auth login
```

> After installing Rust: restart your shell or add `~/.cargo/bin` (Windows: `%USERPROFILE%\.cargo\bin`) to PATH.

---

## Quick start (build & run)

Clone, build, and try the CLI demo:

```bash
git clone https://github.com/<YOUR_OWNER>/q-cap
cd q-cap
cargo build --workspace

# Demo: compute a BLAKE3 “root” over input bytes
cargo run -p qcap-cli -- hash "hello world"
```

Run the registry (dev):

```bash
cd services/qcap-registry
go run .
# GET http://localhost:8080/health  -> {"status":"ok"}
```

Build the TS SDK stub:

```bash
cd sdks/ts
npm install --silent || true
npm run build
```

---

## Style & quality checks

**Rust**
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

**Go**
```bash
cd services/qcap-registry
go fmt ./...
go vet ./...
# optional: staticcheck ./...
go test ./...
```

**TypeScript**
```bash
cd sdks/ts
# optional: npm run lint
npm run build
```

General rules:
- Avoid `unsafe` Rust unless strictly necessary; justify with comments & tests.
- Keep functions small and documented; prefer pure functions where possible.
- Add tests for new logic; property tests encouraged for crypto/IO.

---

## Commit conventions

Use **Conventional Commits** to keep history and changelogs clean.

Examples:
```
feat(cli): add grant command with expiry caveat
fix(core): correct Merkle leaf ordering for empty files
docs(readme): add architecture mermaid diagram
chore(ci): enable codeql for rust/go/js
```

Branch naming: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, etc.

---

## Pull request checklist

Before opening a PR:

- [ ] Tests added/updated and passing locally
- [ ] Docs updated (`README.md`, `docs/*`), examples updated if needed
- [ ] `cargo fmt` + `clippy` clean
- [ ] `go vet` clean (if touching Go)
- [ ] `npm run build` clean (if touching TS)
- [ ] No secrets or credentials added
- [ ] Security considerations noted (if relevant)
- [ ] Linked issue(s) and added appropriate labels

PR template (recommended in description):
- Motivation & context
- What changed
- How to test (commands)
- Risks/rollbacks
- Screenshots/logs (if applicable)

---

## Issue triage & labels

Common labels:
- **type**: `bug`, `enhancement`, `documentation`, `security`
- **area**: `core`, `cli`, `registry`, `sdk`
- **good-first-issue`, `help-wanted`**

Please include:
- Repro steps (exact commands)
- Expected vs actual behavior
- Versions (`rustc -V`, `go version`, OS)

---

## Internationalization & accessibility

- Issues and PRs welcome in **English or French**.
- Prefer clear, plain language for CLI messages and docs.
- When feasible, add French strings alongside English for user-facing messages.

---

## Design & crypto changes

If your change affects **capability semantics**, **crypto primitives**, or **on-disk format**:

1. Open/attach an **ADR** (Architecture Decision Record) draft in `docs/` or an issue.
2. Add/refresh **test vectors** and property tests.
3. Document migration/compat implications (e.g., manifest schema bump).
4. Note threat-model impacts and mitigations.

---

## Release process (high-level)

- CI runs build, tests, CodeQL, SBOM, and image scans.
- Releases are cut from `main` via tags; artifacts and container images are signed (cosign).
- SDKs use semantic versioning; server/CLI use pre-1.0 `0.x.y` until the format stabilizes.

---

## Community & support

- Questions: open a **discussion** or an issue labeled `question`.
- Security: **do not** file public issues — see **[SECURITY.md](SECURITY.md)**.
- Conduct: **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** applies.

---

*Thank you for contributing to Q-Cap!*
