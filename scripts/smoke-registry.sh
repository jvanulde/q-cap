#!/usr/bin/env zsh

# Simple smoke test for the QCAP registry.
# Requires: curl, jq (optional for pretty output).
# Usage: scripts/smoke-registry.sh [base_url]
# Default base_url: http://localhost:8080

set -euo pipefail

BASE_URL=${1:-http://localhost:8080}

echo "[smoke] Target: $BASE_URL"

echo "[smoke] Checking /health…"
curl -sS "$BASE_URL/health" | (jq . 2>/dev/null || cat)

echo "[smoke] Fetching /index.json…"
INDEX_JSON=$(curl -sS "$BASE_URL/index.json")
echo "$INDEX_JSON" | (jq . 2>/dev/null || cat)

COUNT=$(echo "$INDEX_JSON" | jq 'length' 2>/dev/null || echo "unknown")
echo "[smoke] Found $COUNT artifacts"

if [ "$COUNT" = "unknown" ]; then
  echo "[smoke] jq not available or index format unexpected; skipping artifact fetch"
  exit 0
fi

FIRST=$(echo "$INDEX_JSON" | jq -r '.[0].name' 2>/dev/null)
if [ -z "$FIRST" ] || [ "$FIRST" = "null" ]; then
  echo "[smoke] No artifacts listed; done"
  exit 0
fi

echo "[smoke] Downloading first artifact: $FIRST"
curl -fSL "$BASE_URL/artifacts/$FIRST" -o "/tmp/$FIRST"
ls -lh "/tmp/$FIRST"
echo "[smoke] OK"
