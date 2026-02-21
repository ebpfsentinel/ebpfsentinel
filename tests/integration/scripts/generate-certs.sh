#!/usr/bin/env bash
# generate-certs.sh — Generate self-signed CA + server certificate with SAN
#
# Usage: generate-certs.sh [--out-dir /tmp/ebpfsentinel-test-certs]
#
# Produces:
#   ca.pem, ca-key.pem           — Self-signed CA
#   server.pem, server-key.pem   — Server cert signed by CA (SAN: localhost, 127.0.0.1)
set -euo pipefail

OUT_DIR="${1:-/tmp/ebpfsentinel-test-certs}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        *) OUT_DIR="$1"; shift ;;
    esac
done

mkdir -p "$OUT_DIR"

echo "Generating test certificates in ${OUT_DIR}..."

# ── CA ─────────────────────────────────────────────────────────────
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${OUT_DIR}/ca-key.pem" \
    -out "${OUT_DIR}/ca.pem" \
    -days 365 \
    -subj "/CN=eBPFsentinel Test CA/O=eBPFsentinel/C=US" \
    2>/dev/null

# ── Server CSR + cert ──────────────────────────────────────────────
cat > "${OUT_DIR}/server-ext.cnf" <<'EOF'
[req]
req_extensions = v3_req
distinguished_name = req_dn
prompt = no

[req_dn]
CN = localhost
O = eBPFsentinel
C = US

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -newkey rsa:2048 -nodes \
    -keyout "${OUT_DIR}/server-key.pem" \
    -out "${OUT_DIR}/server.csr" \
    -config "${OUT_DIR}/server-ext.cnf" \
    2>/dev/null

openssl x509 -req \
    -in "${OUT_DIR}/server.csr" \
    -CA "${OUT_DIR}/ca.pem" \
    -CAkey "${OUT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUT_DIR}/server.pem" \
    -days 365 \
    -extfile "${OUT_DIR}/server-ext.cnf" \
    -extensions v3_req \
    2>/dev/null

# Cleanup intermediate files
rm -f "${OUT_DIR}/server.csr" "${OUT_DIR}/server-ext.cnf" "${OUT_DIR}/ca.srl"

echo "Certificates generated:"
echo "  CA:         ${OUT_DIR}/ca.pem"
echo "  CA key:     ${OUT_DIR}/ca-key.pem"
echo "  Server:     ${OUT_DIR}/server.pem"
echo "  Server key: ${OUT_DIR}/server-key.pem"
