# Q-Cap Registry (MVP)

A minimal registry that stores `.qcap` artifacts on disk, persists an `index.json`, serves signed issuer revocation lists, and can require bearer-token auth for publishing.

## Endpoints

- `GET /health` - JSON status, including whether publish auth is enabled
- `GET /index.json` - JSON array of capsules
- `GET /index` - HTML index listing
- `POST /artifacts` - publish a `.qcap`
- `GET /artifacts/<name>` - download a `.qcap`
- `POST /revocations/<issuer>/revocations.json` - publish a signed revocation list
- `GET /revocations/<issuer>/revocations.json` - download a signed revocation list

## Configuration

- `QCAP_REGISTRY_STORE` - artifact directory
- `QCAP_REGISTRY_SEED` - backward-compatible alias for `QCAP_REGISTRY_STORE`
- `QCAP_REGISTRY_INDEX` - index file path, defaults to `<store>/index.json`
- `QCAP_REGISTRY_TOKEN` - when set, `POST /artifacts` requires `Authorization: Bearer <token>`

## Quick Start

```sh
# Seed with demo capsules
scripts/seed-registry.sh

# Run registry with publish auth
QCAP_REGISTRY_TOKEN=demo-token go run services/qcap-registry/main.go

# Publish with the CLI
cargo run -p qcap-cli -- publish target/qcap-demo/demo.qcap \
  --registry http://127.0.0.1:8080 \
  --token demo-token

# Publish and fetch issuer revocations
cargo run -p qcap-cli -- publish-revocations target/qcap-demo/revocations.json \
  --registry http://127.0.0.1:8080 \
  --token demo-token
cargo run -p qcap-cli -- fetch-revocations <issuer-public-key> \
  --out target/qcap-demo/fetched-revocations.json \
  --registry http://127.0.0.1:8080

# Smoke test endpoints
scripts/smoke-registry.sh
```
