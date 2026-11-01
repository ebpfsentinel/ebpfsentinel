#!/usr/bin/env bats
# 78-host-rules-shadow-and-enforce.bats - a host rule counts in shadow,
# acts once promoted, and an intention the host cannot serve says why.
#
# The suite asserts:
#
#   * A shipped rule fires end to end: a program started from /tmp is
#     counted by the shipped rule on temporary directories, in shadow.
#   * A written rule in shadow counts the start it would have acted on,
#     raises no alert and lets the process run to its end.
#   * The same rule promoted to `mode: enforce` raises its alert and kills
#     the process it names.
#   * Every intention the host does not serve is reported not applicable
#     with its reason, and a rule naming one carries that state.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 78 starts its processes on the agent's host (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-host-rules-$$"
    mkdir -p "${DATA_DIR}"
    # A copy rather than a link: a process is known by its file. A shell
    # rather than `sleep`, because a kill lands at the target's next system
    # call and a `sleep` blocked in one long nanosleep makes none.
    cp "$(readlink -f "$(command -v bash)")" "${DATA_DIR}/hr-loop"
    chmod 0755 "${DATA_DIR}/hr-loop"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-host-rules.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_rule hr-loop || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "host rules never listed" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-host-rules-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_host_rules() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/host-rules"
}

_rule() {
    _host_rules | jq -c --arg r "$1" '.rules[] | select(.id == $r)'
}

# _wait_rule <rule> - poll until the rule is listed. The host rules are
# loaded after the datapath reports itself up, so readiness alone does not
# mean the list is there yet.
_wait_rule() {
    local attempt=0
    while [ "${attempt}" -lt 30 ]; do
        [ -n "$(_rule "$1" 2>/dev/null)" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _shadow_events <rule> - the events the rule counted in shadow, 0 if none.
_shadow_events() {
    _rule "$1" | jq -r '.shadow.events // 0'
}

# _wait_shadow <rule> <at_least> - poll until the rule counted that many.
_wait_shadow() {
    local attempt=0
    while [ "${attempt}" -lt 20 ]; do
        [ "$(_shadow_events "$1")" -ge "$2" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _loop <seconds> - run the suite's shell copy for that long, waking every
# tenth of a second.
_loop() {
    "${DATA_DIR}/hr-loop" -c 'for _ in $(seq 1 '"$(( $1 * 10 ))"'); do sleep 0.1; done'
}

_loop_requires_applicable() {
    local state
    state="$(_rule hr-loop | jq -r '.state')"
    if [ "${state}" != "applicable" ]; then
        env_skip "process.starts is not served on this host (${state})"
    fi
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the written rule loads in shadow beside the shipped rules" {
    local body
    body="$(_host_rules)"
    [ "$(jq -r '.rules[] | select(.id == "hr-loop") | .mode' <<<"${body}")" = "shadow" ]
    [ "$(jq '[.rules[] | select(.id | startswith("shipped-"))] | length' <<<"${body}")" -ge 1 ]
    [ "$(jq '[.rules[] | select(.id | startswith("shipped-")) | select(.mode != "shadow")] | length' <<<"${body}")" -eq 0 ]
}

@test "a shipped rule fires end to end on a start from a temporary directory" {
    _loop_requires_applicable
    local before
    before="$(_shadow_events shipped-exec-from-temporary-directory)"
    run _loop 1
    [ "$status" -eq 0 ]
    _wait_shadow shipped-exec-from-temporary-directory $((before + 1))
}

@test "a rule in shadow counts the start and neither alerts nor kills" {
    _loop_requires_applicable
    local before
    before="$(_shadow_events hr-loop)"
    run timeout 10 bash -c "$(declare -f _loop); DATA_DIR=${DATA_DIR} _loop 2"
    echo "exit ${status}" >&2
    [ "$status" -eq 0 ]
    _wait_shadow hr-loop $((before + 1))
    [ "$(_rule hr-loop | jq '.shadow.workloads | length')" -ge 1 ]
    run wait_for_alert '.[] | select(.rule_id == "hr-loop")' 3 1
    [ "$status" -ne 0 ]
}

@test "the same rule promoted to enforce alerts and kills the process" {
    _loop_requires_applicable
    stop_ebpf_agent
    sed -i 's/^      mode: shadow$/      mode: enforce/' "${PREPARED_CONFIG}"
    grep -q '^      mode: enforce$' "${PREPARED_CONFIG}"
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30
    _wait_rule hr-loop
    [ "$(_rule hr-loop | jq -r '.mode')" = "enforce" ]

    run timeout 15 bash -c "$(declare -f _loop); DATA_DIR=${DATA_DIR} _loop 10"
    echo "exit ${status}" >&2
    # Killed by a signal: neither a clean exit nor the timeout's 124.
    [ "$status" -ne 0 ]
    [ "$status" -ne 124 ]
    wait_for_alert '.[] | select(.rule_id == "hr-loop")' 15 1
    [ "$(_host_rules | jq -r '.matched')" -ge 1 ]
}

@test "an intention the host does not serve is not applicable with its reason" {
    local intents
    intents="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/host-rules/intents")"
    [ "$(jq '.intents | length' <<<"${intents}")" -ge 1 ]
    [ "$(jq '[.intents[] | select(.state == "applicable")] | length' <<<"${intents}")" -eq "$(jq -r '.applicable' <<<"${intents}")" ]
    # Whatever this host refuses, it says why; none is refused in silence.
    [ "$(jq '[.intents[] | select(.state == "not_applicable") | select((.reason // "") == "")] | length' <<<"${intents}")" -eq 0 ]

    # A rule naming one carries the same state and the same reason: the
    # shipped reverse-shell rule names a connect, which this build does not
    # feed to the rules.
    local rules named
    rules="$(_host_rules)"
    named="$(jq -r '[.rules[].intents[] | select(.state == "not_applicable") | .name] | first // empty' <<<"${rules}")"
    echo "refused intention named by a rule: ${named}" >&2
    [ -n "${named}" ]
    local reason
    reason="$(jq -r --arg n "${named}" '.intents[] | select(.name == $n) | .reason' <<<"${intents}")"
    [ -n "${reason}" ]
    jq -e --arg n "${named}" --arg r "${reason}" \
        '[.rules[].intents[] | select(.name == $n)] | all(.state == "not_applicable" and .reason == $r)' <<<"${rules}"
    [ "$(jq -r '.rules[] | select(.id == "shipped-reverse-shell") | .state' <<<"${rules}")" = "partially_applicable" ]
}
