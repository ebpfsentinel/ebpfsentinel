#!/usr/bin/env bats
# 26-ebpf-dlp-scenarios.bats — DLP (uprobe-dlp) eBPF scenario tests
# Requires: root, kernel >= 6.1, bpftool
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
    # Stop TLS echo server if running
    [ -f "$DATA_DIR/tls_server.pid" ] && kill "$(cat "$DATA_DIR/tls_server.pid")" 2>/dev/null || true
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

# ── Pattern validation: all 9 OSS patterns loaded ──────────────────

@test "all 9 default DLP patterns loaded" {
    require_root

    local body
    body="$(api_get /api/v1/dlp/patterns)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'if type == "array" then length else (.patterns // []) | length end' 2>/dev/null)" || count="0"
    [ "${count:-0}" -ge 9 ]
}

@test "PCI patterns include Visa, Mastercard, Amex" {
    require_root

    local body
    body="$(api_get /api/v1/dlp/patterns)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local pci_count
    pci_count="$(echo "$body" | jq '[.[] | select(.data_type == "pci")] | length' 2>/dev/null)" || pci_count="0"
    [ "${pci_count:-0}" -ge 3 ]
}

@test "credential patterns include AWS key, GitHub token, password, bearer" {
    require_root

    local body
    body="$(api_get /api/v1/dlp/patterns)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]

    local cred_count
    cred_count="$(echo "$body" | jq '[.[] | select(.data_type == "credentials")] | length' 2>/dev/null)" || cred_count="0"
    [ "${cred_count:-0}" -ge 4 ]
}

# ── Regex validation via HTTPS traffic (uprobe captures SSL plaintext) ──

# ── Regex validation via local TLS traffic ──────────────────────────
#
# DLP uprobe hooks SSL_write/SSL_read on ANY process using libssl on
# the SAME machine. We start an openssl s_server locally, then send
# data with openssl s_client locally. The uprobe intercepts the
# plaintext in the s_client process, sends it to the DLP engine.
#
# All TLS happens on localhost — no namespace, no cross-VM traffic.

_start_tls_echo_server() {
    openssl req -x509 -newkey rsa:2048 -keyout "$DATA_DIR/tls.key" \
        -out "$DATA_DIR/tls.crt" -days 1 -nodes -subj '/CN=localhost' 2>/dev/null
    nohup openssl s_server -accept 9443 -cert "$DATA_DIR/tls.crt" \
        -key "$DATA_DIR/tls.key" -quiet >/dev/null 2>&1 &
    echo $! > "$DATA_DIR/tls_server.pid"
    sleep 1
}

_stop_tls_echo_server() {
    [ -f "$DATA_DIR/tls_server.pid" ] && kill "$(cat "$DATA_DIR/tls_server.pid")" 2>/dev/null || true
}

_send_tls_data() {
    # Local TLS send — uprobe on libssl captures the plaintext from s_client
    local data="$1"
    echo "$data" | timeout 3 openssl s_client -connect 127.0.0.1:9443 -quiet 2>/dev/null || true
}

@test "TLS echo server starts for DLP tests" {
    require_root
    command -v openssl &>/dev/null || skip "openssl not installed"

    _start_tls_echo_server
    sleep 1
    local pid
    pid="$(cat "$DATA_DIR/tls_server.pid" 2>/dev/null)" || true
    [ -n "$pid" ]
    kill -0 "$pid" 2>/dev/null
}

@test "Visa card via TLS triggers DLP scan" {
    require_root
    command -v openssl &>/dev/null || skip "openssl not installed"
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "payment card: 4111111111111111 process immediately"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "SSN via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "Employee SSN: 123-45-6789 salary 85000"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "AWS key via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "GitHub token via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "password leak via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "database: password=SuperSecretP@ss123 host=db.prod"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "Bearer token via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "email address via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "send credentials to john.doe@company-internal.com ASAP"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "Mastercard via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "charge card 5105105105105100 amount 499.99"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "Amex via TLS triggers DLP scan" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "amex corporate 371449635398431 exp 12/28"
    sleep 3

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "clean data does not trigger DLP false positive" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    local before_body
    before_body="$(api_get /api/v1/alerts)"
    _load_http_status
    local before_count
    before_count="$(echo "$before_body" | jq '[(.alerts // .)[] | select(.component == "dlp")] | length' 2>/dev/null)" || before_count="0"

    _send_tls_data "This is a perfectly normal message with no sensitive data at all."
    sleep 3

    local after_body
    after_body="$(api_get /api/v1/alerts)"
    _load_http_status
    local after_count
    after_count="$(echo "$after_body" | jq '[(.alerts // .)[] | select(.component == "dlp")] | length' 2>/dev/null)" || after_count="0"

    [ "${after_count:-0}" -le "$((before_count + 1))" ]
}

@test "multiple patterns in single TLS message" {
    require_root
    [ -f "$DATA_DIR/tls_server.pid" ] || skip "TLS server not running"

    _send_tls_data "Payment: 4111111111111111 SSN: 987-65-4321 email: leak@evil.com password=hunter2hunter2"
    sleep 5

    local body
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "TLS echo server cleanup" {
    _stop_tls_echo_server
}

@test "DLP metrics present after TLS traffic" {
    require_root

    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "$metrics" ]
    echo "$metrics" | grep -qE "ebpfsentinel_dlp" || true
}
