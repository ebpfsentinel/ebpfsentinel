#!/usr/bin/env bats
# 01-agent-lifecycle.bats — Agent startup, shutdown, and signal handling

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"

    # Prepare config from template
    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-config-$$.yaml"
    export PREPARED_INVALID_CONFIG="/tmp/ebpfsentinel-test-invalid-$$.yaml"

    sed "s|__DATA_DIR__|${DATA_DIR}|g" \
        "${FIXTURE_DIR}/config-minimal.yaml" > "$PREPARED_CONFIG"
    cp "${FIXTURE_DIR}/config-invalid.yaml" "$PREPARED_INVALID_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG" "$PREPARED_INVALID_CONFIG"
}

teardown() {
    stop_agent 2>/dev/null || true
}

# ── Tests ──────────────────────────────────────────────────────────

@test "agent starts with valid minimal config and healthz returns 200" {
    start_agent "$PREPARED_CONFIG"

    local status_code
    status_code="$(api_status /healthz)"
    assert_http_status "200" "$status_code"
}

@test "agent fails cleanly with invalid config (non-zero exit)" {
    run start_agent_expect_fail "$PREPARED_INVALID_CONFIG"
    [ "$status" -ne 0 ]
}

@test "agent fails with nonexistent config file" {
    run start_agent_expect_fail "/tmp/nonexistent-config-$$.yaml"
    [ "$status" -ne 0 ]
}

@test "healthz returns {\"status\":\"ok\"}" {
    start_agent "$PREPARED_CONFIG"

    local body
    body="$(api_get /healthz)"
    assert_json_field "$body" '.status' 'ok'
}

@test "readyz returns 200 or 503 with ebpf_loaded field" {
    start_agent "$PREPARED_CONFIG"

    local body
    body="$(api_get /readyz)"
    _load_http_status
    # readyz should return 200 or 503 depending on eBPF load status
    [[ "$HTTP_STATUS" == "200" ]] || [[ "$HTTP_STATUS" == "503" ]]
    assert_json_field_exists "$body" '.ebpf_loaded'
}

@test "graceful shutdown via SIGTERM completes in <5s" {
    start_agent "$PREPARED_CONFIG"
    local pid
    pid="$(cat "$AGENT_PID_FILE")"

    local start_time
    start_time="$(date +%s)"
    kill -TERM "$pid"

    # Wait for process to exit
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
        sleep 0.2
        waited=$((waited + 1))
    done

    local end_time
    end_time="$(date +%s)"
    local elapsed=$((end_time - start_time))

    # Process should be gone
    ! kill -0 "$pid" 2>/dev/null

    # Should complete within 5 seconds
    [ "$elapsed" -lt 6 ]

    # Clean up PID file since we killed it manually
    rm -f "$AGENT_PID_FILE"
    unset AGENT_PID
}

@test "SIGHUP triggers config reload (same PID, still healthy)" {
    start_agent "$PREPARED_CONFIG"
    local pid_before
    pid_before="$(cat "$AGENT_PID_FILE")"

    # Send SIGHUP for config reload
    kill -HUP "$pid_before"
    sleep 2

    # PID should be the same (no restart)
    local pid_after
    pid_after="$(cat "$AGENT_PID_FILE")"
    [ "$pid_before" = "$pid_after" ]

    # Agent should still be healthy
    local status_code
    status_code="$(api_status /healthz)"
    assert_http_status "200" "$status_code"
}
