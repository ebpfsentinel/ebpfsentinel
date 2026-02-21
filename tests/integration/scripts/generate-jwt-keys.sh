#!/usr/bin/env bash
# generate-jwt-keys.sh — Generate RSA keypair and pre-sign JWT tokens
#
# Usage: generate-jwt-keys.sh [--out-dir /tmp/ebpfsentinel-test-jwt]
#
# Produces:
#   jwt-private.pem, jwt-public.pem    — RSA 2048 keypair
#   token-admin.jwt                    — Admin role, all namespaces
#   token-viewer.jwt                   — Viewer role (read-only)
#   token-operator.jwt                 — Operator role, namespace:prod only
#   token-expired.jwt                  — Expired token (exp in past)
set -euo pipefail

OUT_DIR="${1:-/tmp/ebpfsentinel-test-jwt}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        *) OUT_DIR="$1"; shift ;;
    esac
done

mkdir -p "$OUT_DIR"

echo "Generating JWT keypair and tokens in ${OUT_DIR}..."

# ── RSA keypair ────────────────────────────────────────────────────
openssl genrsa -out "${OUT_DIR}/jwt-private.pem" 2048 2>/dev/null
openssl rsa -in "${OUT_DIR}/jwt-private.pem" -pubout -out "${OUT_DIR}/jwt-public.pem" 2>/dev/null

# ── Helper: create signed JWT ──────────────────────────────────────
# Uses openssl + base64 to create RS256 JWTs without external dependencies.
sign_jwt() {
    local payload="$1"
    local key_file="${OUT_DIR}/jwt-private.pem"

    local header='{"alg":"RS256","typ":"JWT"}'
    local h_b64
    h_b64="$(echo -n "$header" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')"
    local p_b64
    p_b64="$(echo -n "$payload" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')"

    local signing_input="${h_b64}.${p_b64}"
    local signature
    signature="$(echo -n "$signing_input" | \
        openssl dgst -sha256 -sign "$key_file" | \
        openssl base64 -e -A | tr '+/' '-_' | tr -d '=')"

    echo "${signing_input}.${signature}"
}

NOW="$(date +%s)"
EXP_FUTURE=$((NOW + 86400 * 365))  # 1 year from now
EXP_PAST=$((NOW - 3600))            # 1 hour ago

# ── Admin token ────────────────────────────────────────────────────
ADMIN_PAYLOAD="{\"sub\":\"admin-user\",\"role\":\"admin\",\"namespaces\":[\"*\"],\"iss\":\"ebpfsentinel-test\",\"aud\":\"ebpfsentinel\",\"iat\":${NOW},\"exp\":${EXP_FUTURE}}"
sign_jwt "$ADMIN_PAYLOAD" > "${OUT_DIR}/token-admin.jwt"

# ── Viewer token ───────────────────────────────────────────────────
VIEWER_PAYLOAD="{\"sub\":\"viewer-user\",\"role\":\"viewer\",\"namespaces\":[\"*\"],\"iss\":\"ebpfsentinel-test\",\"aud\":\"ebpfsentinel\",\"iat\":${NOW},\"exp\":${EXP_FUTURE}}"
sign_jwt "$VIEWER_PAYLOAD" > "${OUT_DIR}/token-viewer.jwt"

# ── Operator token (namespace:prod only) ───────────────────────────
OPERATOR_PAYLOAD="{\"sub\":\"operator-user\",\"role\":\"operator\",\"namespaces\":[\"prod\"],\"iss\":\"ebpfsentinel-test\",\"aud\":\"ebpfsentinel\",\"iat\":${NOW},\"exp\":${EXP_FUTURE}}"
sign_jwt "$OPERATOR_PAYLOAD" > "${OUT_DIR}/token-operator.jwt"

# ── Expired token ──────────────────────────────────────────────────
EXPIRED_PAYLOAD="{\"sub\":\"expired-user\",\"role\":\"admin\",\"namespaces\":[\"*\"],\"iss\":\"ebpfsentinel-test\",\"aud\":\"ebpfsentinel\",\"iat\":${EXP_PAST},\"exp\":${EXP_PAST}}"
sign_jwt "$EXPIRED_PAYLOAD" > "${OUT_DIR}/token-expired.jwt"

echo "JWT keys and tokens generated:"
echo "  Private key: ${OUT_DIR}/jwt-private.pem"
echo "  Public key:  ${OUT_DIR}/jwt-public.pem"
echo "  Admin token: ${OUT_DIR}/token-admin.jwt"
echo "  Viewer token: ${OUT_DIR}/token-viewer.jwt"
echo "  Operator token: ${OUT_DIR}/token-operator.jwt"
echo "  Expired token: ${OUT_DIR}/token-expired.jwt"
