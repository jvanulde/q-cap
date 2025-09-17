#!/usr/bin/env bash
set -euo pipefail

#############################################
# CONFIG — EDIT THESE VALUES
#############################################
OWNER="jvanulde"   # e.g., nrcan-ccmeo or your GitHub username
REPO="q-cap"
VISIBILITY="private"               # "private" or "public"
CREATE_REMOTE=true                 # true=create on GitHub & push, false=local only
DEFAULT_BRANCH="main"
#############################################

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
echo "Checking prerequisites..."
need git
need gh
need bash
# Rust & Go are needed to build locally; you can still scaffold without them:
if ! command -v cargo >/dev/null 2>&1; then echo "Note: cargo not found (Rust). You can install via 'brew install rustup-init && rustup-init' or skip build for now."; fi
if ! command -v go >/dev/null 2>&1; then echo "Note: go not found (Go). Install via 'brew install go'."; fi

if "$CREATE_REMOTE"; then
  echo "Creating GitHub repo $OWNER/$REPO (ok if it already exists)..."
  if [[ "$VISIBILITY" == "public" ]]; then
    gh repo create "$OWNER/$REPO" --public --description "Q-Cap: capability-based encrypted content packaging & registry" --disable-wiki --disable-issues || true
  else
    gh repo create "$OWNER/$REPO" --private --description "Q-Cap: capability-based encrypted content packaging & registry" --disable-wiki --disable-issues || true
  fi
  git clone "https://github.com/$OWNER/$REPO.git"
  cd "$REPO"
else
  mkdir -p "$REPO"
  cd "$REPO"
  git init -b "$DEFAULT_BRANCH"
fi

# Directories
mkdir -p core/qcap-core/src core/qcap-cli/src services/qcap-registry sdks/ts/src api/proto .github/workflows docs

# README
cat > README.md <<'EOF'
# Q-Cap

Monorepo skeleton for Q-Cap (capability-based encrypted content packaging).
EOF

# .gitignore
cat > .gitignore <<'EOF'
/target
/bin/
/build/
node_modules/
dist/
.DS_Store
.env
EOF

# .editorconfig
cat > .editorconfig <<'EOF'
root = true
[*]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 2
insert_final_newline = true
trim_trailing_whitespace = true
EOF

# Root Cargo workspace
cat > Cargo.toml <<'EOF'
[workspace]
members = [
  "core/qcap-core",
  "core/qcap-cli"
]
resolver = "2"
EOF

# qcap-core (Rust lib)
cat > core/qcap-core/Cargo.toml <<'EOF'
[package]
name = "qcap-core"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
blake3 = "1"
chacha20poly1305 = { version = "0.10", features = ["xchacha20"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
zip = { version = "0.6", default-features = false, features = ["deflate"] }
EOF

cat > core/qcap-core/src/lib.rs <<'EOF'
#![forbid(unsafe_code)]
use blake3::Hasher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QcapError { #[error("generic: {0}")] Generic(String) }

pub fn merkle_root_demo(bytes: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(bytes);
    format!("blake3:{}", h.finalize().to_hex())
}
EOF

# qcap-cli (Rust bin)
cat > core/qcap-cli/Cargo.toml <<'EOF'
[package]
name = "qcap-cli"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[dependencies]
clap = { version = "4", features = ["derive"] }
qcap-core = { path = "../qcap-core" }
EOF

cat > core/qcap-cli/src/main.rs <<'EOF'
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "qcap", version, about = "Q-Cap CLI (alpha)")]
struct Cli { #[command(subcommand)] command: Commands }

#[derive(Subcommand)]
enum Commands {
    /// Demo: hash input bytes
    Hash { input: String },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hash { input } => {
            let root = qcap_core::merkle_root_demo(input.as_bytes());
            println!("{}", root);
        }
    }
}
EOF

# Go registry (minimal)
cat > services/qcap-registry/go.mod <<EOF
module github.com/${OWNER}/qcap-registry

go 1.21

require github.com/go-chi/chi/v5 v5.0.10
EOF

cat > services/qcap-registry/main.go <<'EOF'
package main

import (
  "encoding/json"
  "net/http"
  chi "github.com/go-chi/chi/v5"
)

func main() {
  r := chi.NewRouter()
  r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status":"ok"})
  })
  http.ListenAndServe(":8080", r)
}
EOF

# TS SDK (stub)
cat > sdks/ts/package.json <<'EOF'
{
  "name": "@qcap/sdk",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "scripts": { "build": "tsc -p ." },
  "license": "Apache-2.0"
}
EOF

cat > sdks/ts/tsconfig.json <<'EOF'
{ "compilerOptions": { "target": "ES2020", "module": "ES2020", "declaration": true, "outDir": "dist", "strict": true }, "include": ["src"] }
EOF

cat > sdks/ts/src/index.ts <<'EOF'
export function verifyDemo(bytes: Uint8Array): string { return `len:${bytes.length}` }
EOF

# Proto stub
cat > api/proto/qcap.proto <<'EOF'
syntax = "proto3";
package qcap.v1;

message HealthReply { string status = 1; }
// (Note: add google/protobuf/empty.proto import and service later)
EOF

# CI (GitHub Actions)
cat > .github/workflows/ci.yml <<'EOF'
name: ci
on: [push, pull_request]
jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --workspace --verbose
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.21"
      - run: |
          cd services/qcap-registry
          go build ./...
EOF

# Docs
cat > docs/overview.md <<'EOF'
# Q-Cap Overview (stub)
MVP scaffolding created. See ADRs for decisions.
EOF

# Commit & (optional) push
git add .
git commit -m "chore: bootstrap monorepo skeleton (Rust core/CLI, Go registry, TS SDK, CI)" >/dev/null || true

if "$CREATE_REMOTE"; then
  git push -u origin "$DEFAULT_BRANCH" || true
fi

echo
echo "✅ Bootstrap complete."
echo "Try building locally (optional):"
echo "  cargo build --workspace"
echo "Run demo:"
echo "  cargo run -p qcap-cli -- hash hello"
