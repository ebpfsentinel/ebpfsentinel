#!/usr/bin/env bats
# 27-hot-reload-rules.bats — Configuration hot-reload tests
# Requires: root, kernel >= 5.17, bpftool, jq
#
# Tests hot-reload of firewall rules via SIGHUP:
#   1. Verify initial rule count
#   2. Append rules to config and SIGHUP -> rules increase
#   3. Corrupt config and SIGHUP -> rules unchanged (rollback)
#   4. Agent stays healthy after failed reload

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool bpftool
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-reload-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

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

@test "initial config has 3 firewall rules" {
    require_root

    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true

    [ "$count" -eq 3 ]
}

@test "add 2 rules and SIGHUP reloads" {
    require_root

    # Append 2 additional firewall rules to the prepared config
    cat >> "$PREPARED_CONFIG" <<'RULES'

    # Hot-reload: added rule 4
    - id: fw-reload-deny-5555
      priority: 40
      action: deny
      protocol: tcp
      dst_port: 5555
      scope: global
      enabled: true

    # Hot-reload: added rule 5
    - id: fw-reload-allow-6666
      priority: 50
      action: allow
      protocol: tcp
      dst_port: 6666
      scope: global
      enabled: true
RULES

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

    [ "$count" -eq 5 ]
}

@test "invalid config SIGHUP does not break rules" {
    require_root

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

    # Rules should still be 5 (rollback on invalid config)
    local body
    body="$(api_get /api/v1/firewall/rules)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]

    local count
    count="$(echo "$body" | jq 'length' 2>/dev/null)" || true

    [ "$count" -eq 5 ]

    # Restore valid config for subsequent tests
    mv "${PREPARED_CONFIG}.bak" "$PREPARED_CONFIG"
}

@test "agent stays healthy after failed reload" {
    require_root

    local body
    body="$(api_get /healthz)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
}
