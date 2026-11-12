#!/usr/bin/env zsh

# Seed the QCAP registry with two demo capsules (alpha and beta).
# Requires: cargo, Rust toolchain; qcap-cli builds and runs locally.
# Usage: scripts/seed-registry.sh

set -euo pipefail

ROOT_DIR=${0:A:h:h}
SEED_DIR="$ROOT_DIR/services/qcap-registry/seed"

mkdir -p "$SEED_DIR"

echo "[seed] Using seed dir: $SEED_DIR"

# Create demo payload A
TMP_A=$(mktemp -d /tmp/qcap-seed-a.XXXXXX)
echo "alpha" > "$TMP_A/file1.txt"
printf "01020304" | xxd -r -p > "$TMP_A/file2.bin"
cat > "$TMP_A/data.json" <<'JSON'
{ "title": "Alpha capsule", "tags": ["demo","json"], "count": 2 }
JSON

# Create demo payload B (with tiny GeoJSON)
TMP_B=$(mktemp -d /tmp/qcap-seed-b.XXXXXX)
echo "beta" > "$TMP_B/file1.txt"
cat > "$TMP_B/geo.json" <<'JSON'
{
  "type": "FeatureCollection",
  "features": [
    { "type": "Feature", "properties": { "name": "Point A" },
      "geometry": { "type": "Point", "coordinates": [-75.6972, 45.4215] } }
  ]
}
JSON

# Demo signing key (DO NOT USE IN PRODUCTION)
SEED_KEY="/tmp/ed25519.seed.hex"
if [ ! -f "$SEED_KEY" ]; then
  echo "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" > "$SEED_KEY"
fi

echo "[seed] Building qcap-cli (if needed)…"
(cd "$ROOT_DIR" && cargo build -p qcap-cli)

echo "[seed] Packing demo capsules…"
(cd "$ROOT_DIR" && cargo run -p qcap-cli -- pack "$TMP_A" --out "$SEED_DIR/alpha.qcap" --key "$SEED_KEY")
(cd "$ROOT_DIR" && cargo run -p qcap-cli -- pack "$TMP_B" --out "$SEED_DIR/beta.qcap" --key "$SEED_KEY")

echo "[seed] Done. Seeded capsules:"
ls -lh "$SEED_DIR"/*.qcap || true

echo "[seed] You can now run the registry:"
echo "       go -C services/qcap-registry run ."
