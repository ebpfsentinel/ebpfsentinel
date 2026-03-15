#!/usr/bin/env bats
# 27-hot-reload-rules.bats — Configuration hot-reload tests
# Requires: root, kernel >= 6.1, bpftool, jq
#
# Tests hot-reload of firewall rules via SIGHUP:
#   1. Verify initial rule count
#   2. Append rules to config and SIGHUP -> rules increase
#   3. Corrupt config and SIGHUP -> rules unchanged (rollback)
#   4. Agent stays healthy after failed reload

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-reload-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    # Ensure no stale agent from previous suite (wait for ports to free)
    stop_ebpf_agent 2>/dev/null || true
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
        sleep 2
    fi

    # Create initial config with 3 rules
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-hot-reload.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-reload-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "initial config has expected firewall rules" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true

    # Agent may add anti-lockout rules; check we have at least our 3 configured rules
    [ "$count" -ge 3 ]

    # Persist initial count so we can compare after reload
    echo "$count" > "${DATA_DIR}/initial_rule_count.txt"

    # Verify our specific rules exist
    local has_ssh has_4444 has_any
    has_ssh="$(echo "$body" | jq '[.[] | select(.id == "fw-reload-allow-ssh")] | length' 2>/dev/null)" || true
    has_4444="$(echo "$body" | jq '[.[] | select(.id == "fw-reload-deny-4444")] | length' 2>/dev/null)" || true
    has_any="$(echo "$body" | jq '[.[] | select(.id == "fw-reload-allow-any")] | length' 2>/dev/null)" || true
    [ "${has_ssh:-0}" -eq 1 ]
    [ "${has_4444:-0}" -eq 1 ]
    [ "${has_any:-0}" -eq 1 ]
}

@test "add 2 rules and SIGHUP reloads" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    # Append 2 additional firewall rules under firewall.rules
    # Use Python to insert rules into the YAML array correctly
    python3 -c "
import sys
with open(sys.argv[1], 'r') as f:
    lines = f.readlines()
# Find the line 'ids:' at column 0 — insert new rules before it
insert_idx = next(i for i, l in enumerate(lines) if l.startswith('ids:'))
new_rules = [
    '\n',
    '    # Hot-reload: added rule 4\n',
    '    - id: fw-reload-deny-5555\n',
    '      priority: 40\n',
    '      action: deny\n',
    '      protocol: tcp\n',
    '      dst_port: 5555\n',
    '      scope: global\n',
    '      enabled: true\n',
    '\n',
    '    # Hot-reload: added rule 5\n',
    '    - id: fw-reload-allow-6666\n',
    '      priority: 50\n',
    '      action: allow\n',
    '      protocol: tcp\n',
    '      dst_port: 6666\n',
    '      scope: global\n',
    '      enabled: true\n',
    '\n',
]
lines[insert_idx:insert_idx] = new_rules
with open(sys.argv[1], 'w') as f:
    f.writelines(lines)
" "$PREPARED_CONFIG"

    # In 2VM mode, rewrite data paths and update the remote config
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "$PREPARED_CONFIG")"
        local rewritten="/tmp/ebpfsentinel-2vm-reload-$$.yaml"
        sed -e "s|/tmp/ebpfsentinel-test-data[^/]*|${_REMOTE_DATA_DIR}|g" \
            "$PREPARED_CONFIG" > "$rewritten"
        _agent_scp "$rewritten" "$remote_config"
        rm -f "$rewritten"
    fi

    # Send SIGHUP to trigger config reload
    if type signal_agent &>/dev/null; then
        signal_agent HUP
    else
        local pid
        pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)"
        [ -n "$pid" ] && kill -HUP "$pid"
    fi

    # Wait for reload to take effect
    sleep 3

    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true

    # Count should have increased by 2 from initial
    local initial_count
    initial_count="$(cat "${DATA_DIR}/initial_rule_count.txt" 2>/dev/null)" || initial_count=3
    local expected=$(( initial_count + 2 ))
    [ "$count" -eq "$expected" ] || [ "$count" -ge "$expected" ]

    # Verify the new rules exist
    local has_5555 has_6666
    has_5555="$(echo "$body" | jq '[.[] | select(.id == "fw-reload-deny-5555")] | length' 2>/dev/null)" || true
    has_6666="$(echo "$body" | jq '[.[] | select(.id == "fw-reload-allow-6666")] | length' 2>/dev/null)" || true
    [ "${has_5555:-0}" -eq 1 ]
    [ "${has_6666:-0}" -eq 1 ]

    # Persist count for test 3
    echo "$count" > "${DATA_DIR}/reload_rule_count.txt"
}

@test "invalid config SIGHUP does not break rules" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    # Back up valid config
    cp "$PREPARED_CONFIG" "${PREPARED_CONFIG}.bak"

    # Corrupt the config with invalid YAML
    echo ":::INVALID_YAML{{{{" >> "$PREPARED_CONFIG"

    # In 2VM mode, update the remote config
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "$PREPARED_CONFIG")"
        _agent_scp "$PREPARED_CONFIG" "$remote_config"
    fi

    # Send SIGHUP with the corrupted config
    if type signal_agent &>/dev/null; then
        signal_agent HUP
    else
        local pid
        pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)"
        [ -n "$pid" ] && kill -HUP "$pid"
    fi

    # Wait for reload attempt
    sleep 2

    # Rules should be unchanged (rollback on invalid config)
    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true

    # Count should match the post-reload count from test 2
    local expected_count
    expected_count="$(cat "${DATA_DIR}/reload_rule_count.txt" 2>/dev/null)" || true
    if [ -n "$expected_count" ]; then
        [ "$count" -eq "$expected_count" ]
    else
        # Fallback: at least our 5 user rules should exist
        [ "$count" -ge 5 ]
    fi

    # Restore valid config for subsequent tests
    mv "${PREPARED_CONFIG}.bak" "$PREPARED_CONFIG"
}

@test "agent stays healthy after failed reload" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root

    local body
    body="$(api_get /healthz)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}
