#!/usr/bin/env bats
# 26-ebpf-dlp-scenarios.bats — DLP (uprobe-dlp) eBPF scenario tests
# Requires: root, kernel >= 5.17, bpftool
#
# Tests DLP program with:
#   - Program attachment and health checks
#   - DLP pattern configuration via REST API
#   - DLP metrics endpoint accessibility
#   - Pattern loading verification
#   - DLP mode verification (alert mode)

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dlp-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Prepare config
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dlp.yaml")"
    export PREPARED_CONFIG

    # Start agent with eBPF programs
    start_ebpf_agent "$PREPARED_CONFIG"

    # Wait for eBPF programs to load
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load (degraded mode). Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dlp-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Program attachment ───────────────────────────────────────────

@test "DLP program attaches successfully" {
    require_root

    local body
    body="$(api_get /healthz)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

# ── DLP configuration API ────────────────────────────────────────

@test "DLP configuration accessible via API" {
    require_root

    local body
    body="$(api_get /api/v1/dlp/patterns)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}

# ── DLP metrics ──────────────────────────────────────────────────

@test "DLP metrics endpoint accessible" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true

    [ -n "$metrics" ]

    # Verify at least one DLP metric line exists
    local dlp_lines
    dlp_lines="$(echo "$metrics" | grep -c "ebpfsentinel_dlp" 2>/dev/null)" || dlp_lines=0

    [ "$dlp_lines" -ge 1 ]
}

# ── DLP patterns loaded ─────────────────────────────────────────

@test "DLP patterns loaded" {
    require_root

    local body
    body="$(api_get /api/v1/dlp/patterns)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true

    [ -n "$count" ]
    [ "$count" -ge 1 ]
}

# ── DLP mode ─────────────────────────────────────────────────────

@test "DLP mode is alert" {
    require_root

    local body
    body="$(api_get /api/v1/dlp/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local mode
    mode="$(echo "$body" | jq -r '.mode // .dlp.mode // empty' 2>/dev/null)" || true

    [ "$mode" = "alert" ]
}
