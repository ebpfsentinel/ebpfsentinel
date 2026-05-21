#!/usr/bin/env bats
# 57-multiwan-failover.bats — Multi-WAN gateway selection + failover surface.
#
# Scope:
#   The full end-to-end transit-failover path (egress shifts on link-down
#   between two real WAN gateways with traffic in flight) needs a 3-VM
#   topology with two upstream NICs on the agent VM. The fields the agent
#   surfaces today (REST /api/v1/routing/gateways + Prometheus metrics)
#   are independent of that topology, so this suite asserts the
#   observable contract from a single-VM run:
#
#     * Two configured gateways round-trip through the gateways REST list
#       sorted by priority, primary first.
#     * Routing status reflects the configured gateway count.
#     * Routing metrics are exposed: gateways_total gauge + failovers_total
#       counter + per-gateway status family.
#     * A SIGHUP-driven priority swap re-orders the list deterministically,
#       proving the failover-ordering contract that the kernel-side policy
#       lookup relies on.
#
# Coverage gaps (tracked, deferred):
#
#   * In-process active health probing loop (AC #1: ≤3 s detection).
#     The probe scheduler that calls record_probe_failure/record_probe_success
#     based on interval_secs is not wired into the agent runtime. Health
#     status currently stays at "unknown" without explicit state writes.
#   * Real link-down → egress reroute (AC #2/#3). Requires the 3-VM
#     transit topology — covered by a future tagging in coverage-matrix.yaml.
#   * WAN_ALL_DOWN alert (AC #2 simultaneous failure). Tied to the missing
#     probe loop above.
#
# Both gaps land on the same internal task (multi-WAN probe loop + alert)
# and are explicitly skipped here rather than silently passed.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 5 17
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-multiwan-$$"
    mkdir -p "${DATA_DIR}"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-multiwan.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-multiwan-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_gateways_array() {
    local body
    body="$(api_get /api/v1/routing/gateways 2>/dev/null)" || body=""
    [ -n "${body}" ] || return 1
    echo "${body}" \
        | jq 'if type == "array" then . else (.gateways // []) end' 2>/dev/null
}

_agent_pid_local() {
    cat "${AGENT_PID_FILE}" 2>/dev/null
}

_signal_hup() {
    local pid
    pid="$(_agent_pid_local)"
    [ -n "${pid}" ] || return 1
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo "kill -HUP ${pid}" >/dev/null 2>&1
    else
        kill -HUP "${pid}" 2>/dev/null
    fi
}

_swap_gateway_priorities() {
    # Flip primary (priority 10) ↔ secondary (priority 20) so the
    # priority-ordered selector picks the other gateway first.
    python3 - "${PREPARED_CONFIG}" <<'PY'
import sys, re
path = sys.argv[1]
with open(path, 'r') as f:
    text = f.read()
# Swap via sentinel passes to keep idempotency safe.
text = re.sub(r'priority: 10\b', 'priority: __SWAP_A__', text, count=1)
text = re.sub(r'priority: 20\b', 'priority: 10', text, count=1)
text = text.replace('__SWAP_A__', '20')
with open(path, 'w') as f:
    f.write(text)
PY
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "${PREPARED_CONFIG}")"
        local rewritten="/tmp/ebpfsentinel-2vm-multiwan-$$.yaml"
        sed -e "s|/tmp/ebpfsentinel-test-data[^/]*|${_REMOTE_DATA_DIR}|g" \
            "${PREPARED_CONFIG}" >"${rewritten}"
        _agent_scp "${rewritten}" "${remote_config}" 2>/dev/null || true
        rm -f "${rewritten}"
    fi
}

# ── Routing surface ────────────────────────────────────────────────

@test "routing status surfaces both configured gateways" {
    local body
    body="$(api_get /api/v1/routing/status)"
    _load_http_status

    [ "${HTTP_STATUS}" = "200" ]
    local enabled count
    enabled="$(echo "${body}" | jq -r '.enabled' 2>/dev/null)" || true
    count="$(echo "${body}" | jq -r '.gateway_count' 2>/dev/null)" || true
    [ "${enabled}" = "true" ]
    [ "${count}" = "2" ]
}

@test "gateways list returns primary first ordered by priority" {
    local gws
    gws="$(_gateways_array)" || {
        echo "could not fetch gateways list" >&2
        return 1
    }

    local count
    count="$(echo "${gws}" | jq 'length' 2>/dev/null)" || count=0
    [ "${count}" = "2" ]

    local first_name first_priority
    first_name="$(echo "${gws}" | jq -r '.[0].name' 2>/dev/null)" || true
    first_priority="$(echo "${gws}" | jq -r '.[0].priority' 2>/dev/null)" || true
    [ "${first_name}" = "gw-primary" ]
    [ "${first_priority}" = "10" ]

    local second_name second_priority
    second_name="$(echo "${gws}" | jq -r '.[1].name' 2>/dev/null)" || true
    second_priority="$(echo "${gws}" | jq -r '.[1].priority' 2>/dev/null)" || true
    [ "${second_name}" = "gw-secondary" ]
    [ "${second_priority}" = "20" ]
}

@test "every gateway exposes a status field" {
    local gws
    gws="$(_gateways_array)" || return 1

    local null_count
    null_count="$(echo "${gws}" | jq '[.[] | select(.status == null or .status == "")] | length' 2>/dev/null)" || null_count=0
    [ "${null_count}" = "0" ] || {
        echo "gateways missing status field:" >&2
        echo "${gws}" >&2
        return 1
    }
}

# ── Routing metrics ────────────────────────────────────────────────

@test "routing_gateways_total gauge reports configured gateway count" {
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "${metrics}" ]

    local value
    value="$(echo "${metrics}" \
        | awk '/^ebpfsentinel_routing_gateways(_total)?\b/ {print $NF; exit}')"
    [ -n "${value}" ] || {
        echo "ebpfsentinel_routing_gateways gauge missing from /metrics" >&2
        return 1
    }
    [ "${value}" = "2" ]
}

@test "routing_failovers_total counter is exposed" {
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "${metrics}" ]
    echo "${metrics}" \
        | grep -qE '^ebpfsentinel_routing_failovers(_total)?\b' || {
            echo "ebpfsentinel_routing_failovers counter missing from /metrics" >&2
            return 1
        }
}

# ── Hot-reload-driven priority flip ────────────────────────────────

@test "SIGHUP-driven priority swap re-orders gateways" {
    local pid_before
    pid_before="$(_agent_pid_local)"
    [ -n "${pid_before}" ] || {
        echo "agent pid file empty" >&2
        return 1
    }

    _swap_gateway_priorities
    _signal_hup
    sleep 3

    local pid_after
    pid_after="$(_agent_pid_local)"
    [ "${pid_after}" = "${pid_before}" ] || {
        echo "agent PID changed across SIGHUP (${pid_before} → ${pid_after}) — crash suspected" >&2
        return 1
    }

    local gws
    gws="$(_gateways_array)" || return 1

    local first_name first_priority
    first_name="$(echo "${gws}" | jq -r '.[0].name' 2>/dev/null)" || true
    first_priority="$(echo "${gws}" | jq -r '.[0].priority' 2>/dev/null)" || true
    [ "${first_name}" = "gw-secondary" ] || {
        echo "expected gw-secondary first after priority swap, got ${first_name}" >&2
        echo "${gws}" >&2
        return 1
    }
    [ "${first_priority}" = "10" ]
}

# ── Documented deferral: active probe loop + WAN_ALL_DOWN alert ────

@test "active probe-driven failover path is tracked as a coverage gap" {
    skip "in-process gateway health probe loop + WAN_ALL_DOWN alert not wired yet; AC #1/#2 deferred"
}
