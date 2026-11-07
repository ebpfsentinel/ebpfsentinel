#!/usr/bin/env bats
# 105-config-reload-triggers.bats - each way a configuration change reaches
# the agent, taken on its own.
#
# The suite asserts:
#
#   * `sed -i`, which writes a new file and renames it over the old one,
#     is seen by the file watcher: the change is applied with no signal.
#   * A rewrite in place that keeps the inode is seen the same way.
#   * SIGHUP sent to the pid the lane started reloads the configuration,
#     counted as a reload attempt, and the agent survives it.
#
# Requires: root, kernel >= 6.12, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 105 edits the configuration beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-reload-triggers-$$"
    mkdir -p "$DATA_DIR"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns

    # The configuration sits alone in a directory of its own, the way a
    # mounted ConfigMap or /etc/ebpfsentinel does.
    mkdir -p "${DATA_DIR}/etc"
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-hot-reload.yaml" \
        "${DATA_DIR}/etc/agent.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    # The watcher opens after the datapath reports itself loaded; a change
    # made before it opens is one nothing was there to see.
    local attempt=0
    until grep -q '"config file watcher started"' "${AGENT_LOG_FILE}"; do
        attempt=$((attempt + 1))
        [ "${attempt}" -lt 30 ] || {
            stop_ebpf_agent 2>/dev/null || true
            { echo "the configuration file watcher never started" >&2; return 1; }
        }
        sleep 0.5
    done
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-reload-triggers-$$}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# The destination port the API reports for rule $1.
_rule_port() {
    api_get /api/v1/firewall/rules | jq -r --arg id "$1" \
        '[.[] | select(.id == $id)] | first | .dst_port | if type == "object" then (.start // .port // tostring) else . end | tostring'
}

# Wait up to $3 seconds for rule $1 to report port $2.
_wait_port() {
    local i
    for i in $(seq 1 "$3"); do
        [ "$(_rule_port "$1")" = "$2" ] && return 0
        sleep 1
    done
    return 1
}

_log_count() {
    grep -c "$1" "$AGENT_LOG_FILE" 2>/dev/null || true
}

_reload_attempts() {
    curl -s --max-time "$HTTP_TIMEOUT" "${BASE_URL}/metrics" 2>/dev/null \
        | awk '/^ebpfsentinel_rules_reloads_total/ { s += $NF } END { print s + 0 }'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the rule starts on its configured port" {
    [ "$(_rule_port fw-reload-deny-4444)" = "4444" ]
}

@test "sed -i on the configuration is applied by the watcher alone" {
    local before
    before="$(_log_count 'config file change detected')"
    local inode_before inode_after
    inode_before="$(stat -c %i "$PREPARED_CONFIG")"
    sed -i 's/dst_port: 4444$/dst_port: 4545/' "$PREPARED_CONFIG"
    inode_after="$(stat -c %i "$PREPARED_CONFIG")"
    [ "$inode_before" != "$inode_after" ] || { echo "sed -i kept the inode; the case is not the rename" >&2; return 1; }

    _wait_port fw-reload-deny-4444 4545 10 || {
        echo "rewrite by rename not applied: port $(_rule_port fw-reload-deny-4444)" >&2
        grep -i 'reload\|watcher' "$AGENT_LOG_FILE" | tail -10 >&2
        return 1
    }
    [ "$(_log_count 'config file change detected')" -gt "$before" ]
}

@test "a rewrite in place keeping the inode is applied by the watcher alone" {
    local inode_before
    inode_before="$(stat -c %i "$PREPARED_CONFIG")"
    local text
    text="$(sed 's/dst_port: 4545$/dst_port: 4646/' "$PREPARED_CONFIG")"
    printf '%s\n' "$text" > "$PREPARED_CONFIG"
    [ "$(stat -c %i "$PREPARED_CONFIG")" = "$inode_before" ]

    _wait_port fw-reload-deny-4444 4646 10 || {
        echo "rewrite in place not applied: port $(_rule_port fw-reload-deny-4444)" >&2
        grep -i 'reload\|watcher' "$AGENT_LOG_FILE" | tail -10 >&2
        return 1
    }
}

@test "SIGHUP to the pid the lane started reloads and the agent survives it" {
    local pid
    pid="$(cat "$AGENT_PID_FILE")"
    [ -n "$pid" ] && kill -0 "$pid" || { echo "agent pid ${pid:-none} is not alive" >&2; return 1; }
    # The pid the lane holds is the process serving the API.
    grep -q -- "--config" "/proc/${pid}/cmdline" || {
        echo "pid ${pid} is not the agent: $(tr '\0' ' ' < "/proc/${pid}/cmdline")" >&2
        return 1
    }

    # Let any watcher event from the previous test drain first.
    sleep 2
    local logged attempts
    logged="$(_log_count 'SIGHUP received')"
    attempts="$(_reload_attempts)"

    kill -HUP "$pid"
    local i ok=""
    for i in $(seq 1 10); do
        if [ "$(_log_count 'SIGHUP received')" -gt "$logged" ] \
            && [ "$(_reload_attempts)" -gt "$attempts" ]; then
            ok=1; break
        fi
        sleep 1
    done
    [ -n "$ok" ] || {
        echo "SIGHUP not taken as a reload (attempts ${attempts} -> $(_reload_attempts))" >&2
        tail -10 "$AGENT_LOG_FILE" >&2
        return 1
    }
    kill -0 "$pid" || { echo "the agent died on SIGHUP" >&2; return 1; }
    api_get /healthz >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    [ "$(_rule_port fw-reload-deny-4444)" = "4646" ]
}
