#!/usr/bin/env bats
# 05-grpc-streaming.bats — gRPC service tests (health, reflection, streaming)
# Requires: grpcurl

load '../lib/helpers'

setup_file() {
    # Skip entire suite if grpcurl is not available
    if ! command -v grpcurl &>/dev/null; then
        skip "grpcurl not installed"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-config-$$.yaml"
    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"

    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "gRPC health check returns SERVING" {
    command -v grpcurl &>/dev/null || skip "grpcurl not installed"

    local output
    output="$(grpcurl -plaintext -import-path "${FIXTURE_DIR}" -proto health.proto \
        "$GRPC_ADDR" grpc.health.v1.Health/Check 2>&1)" || true
    assert_contains "$output" "SERVING"
}

@test "gRPC reflection lists AlertStreamService" {
    command -v grpcurl &>/dev/null || skip "grpcurl not installed"

    local output
    output="$(grpcurl -plaintext "$GRPC_ADDR" list 2>&1)" || true
    assert_contains "$output" "AlertStream"
}

@test "StreamAlerts connects without error" {
    command -v grpcurl &>/dev/null || skip "grpcurl not installed"

    # Connect to the stream with a short timeout — we just verify the connection works
    local output
    output="$(timeout 3 grpcurl -plaintext -d '{}' "$GRPC_ADDR" \
        ebpfsentinel.AlertStreamService/StreamAlerts 2>&1)" || true
    # Connection should succeed (may timeout or return empty — both are fine)
    # A connection error would contain "failed to connect" or "connection refused"
    [[ "$output" != *"connection refused"* ]]
}

@test "StreamAlerts with severity filter connects" {
    command -v grpcurl &>/dev/null || skip "grpcurl not installed"

    local output
    output="$(timeout 3 grpcurl -plaintext \
        -d '{"min_severity":"high"}' "$GRPC_ADDR" \
        ebpfsentinel.AlertStreamService/StreamAlerts 2>&1)" || true
    [[ "$output" != *"connection refused"* ]]
}
