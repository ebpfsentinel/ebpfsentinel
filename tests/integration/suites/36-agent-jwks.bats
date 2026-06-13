#!/usr/bin/env bats
# 36-agent-jwks.bats — agent verifies EdDSA JWTs against a fake JWKS server.
#
# Boots a tiny Python `http.server` that serves a JWKS containing the
# matching Ed25519 public key, signs a JWT with `python -m jwt`, and
# asserts the agent's auth middleware accepts it.

load '../lib/helpers'

setup_file() {
    if ! command -v python3 &>/dev/null; then
        { echo "python3 not installed" >&2; return 1; }
    fi
    if ! python3 -c "import jwt" &>/dev/null; then
        { echo "PyJWT not installed (pip install pyjwt cryptography)" >&2; return 1; }
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-jwks-test-$$"
    mkdir -p "$DATA_DIR"

    export JWKS_PORT="${JWKS_PORT:-8765}"
    export JWKS_DIR="${DATA_DIR}/jwks"
    mkdir -p "$JWKS_DIR/.well-known"

    # Generate a fresh Ed25519 keypair + matching JWKS.
    python3 "${BATS_TEST_DIRNAME}/../scripts/build_eddsa_jwks.py" \
        "$JWKS_DIR/.well-known/jwks.json" \
        "$JWKS_DIR/private.pem" \
        "kid-test"

    # Serve the JWKS on localhost. Launch python directly (no cd subshell)
    # so $! is the real server PID — a subshell wrapper makes $! the
    # subshell, and killing it leaves the python orphaned. Close bats' FD 3
    # (3>&-) so a stray server can never hold the TAP stream open and hang
    # teardown.
    python3 -m http.server "$JWKS_PORT" --directory "$JWKS_DIR" \
        >"$JWKS_DIR/server.log" 2>&1 3>&- &
    export JWKS_PID=$!
    sleep 1

    export PREPARED_CONFIG="/tmp/ebpfsentinel-jwks-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"
    cat <<EOF >> "$PREPARED_CONFIG"
auth:
  enabled: true
  jwt:
    algorithm: EdDSA
    jwks_url: http://127.0.0.1:${JWKS_PORT}/.well-known/jwks.json
    jwks_cache_ttl_seconds: 3600
    issuer: dashboard-test
    audience: ebpfsentinel-agent
EOF
    chmod 640 "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    if [ -n "${JWKS_PID:-}" ]; then
        kill "$JWKS_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

mint_token() {
    local kid="$1" sub="$2"
    python3 "${BATS_TEST_DIRNAME}/../scripts/mint_eddsa_jwt.py" \
        "$JWKS_DIR/private.pem" "$kid" "$sub" "dashboard-test" "ebpfsentinel-agent"
}

@test "EdDSA token signed by JWKS-listed key is accepted" {
    local token
    token="$(mint_token "kid-test" "soc-analyst")"
    local status
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        -H "Authorization: Bearer ${token}" \
        "${BASE_URL}/api/v1/agent/identity")"
    [ "$status" = "200" ]
}

@test "Token signed with unknown kid is rejected" {
    local token
    token="$(mint_token "kid-rotated-out" "x")"
    local status
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        -H "Authorization: Bearer ${token}" \
        "${BASE_URL}/api/v1/agent/identity")"
    [ "$status" = "401" ]
}

@test "Token without bearer prefix is rejected" {
    local status
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        -H "Authorization: not-a-token" \
        "${BASE_URL}/api/v1/agent/identity")"
    [ "$status" = "401" ]
}
