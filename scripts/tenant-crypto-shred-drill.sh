#!/usr/bin/env bash
set -euo pipefail

# M10.5 Tenant Crypto-Shredding Verification Drill
# Verifies DEK destruction, session eviction, and unrecoverable ciphertext via integration test
# and (optionally) a live target endpoint when OPERQUAY_BASE_URL + OPERQUAY_COOKIE_JAR are set.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/2] Running deterministic tenant crypto-shredding integration test..."
(
  cd "${REPO_ROOT}"
  cargo test -p operquay-server tenant_crypto_shred_destroys_dek_and_renders_recordings_undecryptable -- --nocapture
)

if [ -n "${OPERQUAY_BASE_URL:-}" ] && [ -n "${OPERQUAY_COOKIE_JAR:-}" ]; then
  TENANT_ID="${OPERQUAY_DRILL_TENANT_ID:-drill-shred-tenant}"
  echo "[2/2] Invoking live crypto-shred API for tenant '${TENANT_ID}' at ${OPERQUAY_BASE_URL}..."
  resp="$(curl -fsS -X POST \
    -b "${OPERQUAY_COOKIE_JAR}" \
    -H "Content-Type: application/json" \
    -d '{"confirm":true}' \
    "${OPERQUAY_BASE_URL%/}/api/v1/tenants/${TENANT_ID}/crypto-shred")"
  echo "      Live response: ${resp}"
  echo "${resp}" | grep -q '"shredded":true'
else
  echo "[2/2] Skipping live API invocation (set OPERQUAY_BASE_URL & OPERQUAY_COOKIE_JAR to run live tenant shred)."
fi

echo "PASS: Tenant crypto-shredding verification drill completed."
