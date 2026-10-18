#!/usr/bin/env bats
# 67-ebpf-every-program-loads.bats - every kernel program this build ships
# is accepted by the verifier and ends up loaded.
#
# Why a suite of its own. A program the verifier refuses does not stop the
# agent: it keeps running, answers its probes, publishes its metrics, and
# whatever that one program alone was doing simply does not happen. The
# refusal is therefore only ever visible where the program is asked for, and
# every other eBPF fixture turns most features off - the firewall fixture
# loads one program out of thirteen - so a program broken in the object was
# loading nowhere and no suite was saying so. tc-ids spent that way: its
# classifier frame plus one outlined subprogram overran the 512-byte combined
# stack the verifier allows a call chain, so it loaded on no kernel at all,
# and the only suite that noticed was an enterprise one that happens to
# enable everything.
#
# The verifier is also the only judge available. These objects resolve kfuncs
# through the agent's own loader, so `bpftool prog loadall` refuses them
# before it gets as far as the instructions ("failed to find BTF for extern
# 'bpf_skb_get_fou_encap'"), and there is no static bound either: the limit is
# on the frames of a bpf-to-bpf call chain, and the call graph is not derivable
# from the object without hand-parsing relocations. So the gate is a real
# kernel being asked, with the config that asks for all of it.
#
# Requires: root, kernel >= 6.9.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 9

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-allprog-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-all-programs.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"

    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# The programs this fixture asks for, by the name the gauge publishes. Fifteen
# names for eighteen objects: xdp-firewall-reject, xdp-ratelimit-syncookie and
# xdp-pass are not loaded on their own - the first two are tail-call targets of
# the program that installs them, and the last is test scaffolding for a veth
# peer. The last two names are the attribution objects, which this fixture does
# not configure and therefore gets on their defaults, which is the posture a
# node ships with.
EXPECTED_PROGRAMS=(
    xdp-firewall
    xdp-ratelimit
    xdp-loadbalancer
    xdp-vip-announcer
    tc-ids
    tc-threatintel
    tc-dns
    tc-conntrack
    tc-nat-ingress
    tc-nat-egress
    tc-scrub
    tc-qos
    uprobe-dlp
    cgroup-attribution
    tracepoint-process
)

_metrics_body() {
    curl -sf --max-time "${HTTP_TIMEOUT:-10}" \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null || true
}

# What the agent says about the loads, printed for a failing test. The verifier's
# own words are in the log and nowhere else, and the rest is noise at this
# fixture's log level.
_load_log() {
    grep -iE "verifier|load failed|attach|program" "$AGENT_LOG_FILE" 2>/dev/null \
        | tail -25 | cut -c1-400
}

# Programs are published as they are loaded, and the chain is attached over
# several seconds, so the readings wait for the set to settle rather than
# sampling it the moment the firewall came up. The counters below ride the
# datapath state loop, whose first tick fires as the loop starts.
_wait_for_program_set() {
    local waited=0 body="" program missing
    while [ "$waited" -lt 60 ]; do
        body="$(_metrics_body)"
        missing=0
        for program in "${EXPECTED_PROGRAMS[@]}"; do
            echo "$body" \
                | grep -q "^ebpfsentinel_ebpf_program_status{program=\"${program}\"}" \
                || missing=1
        done
        if [ "$missing" -eq 0 ] \
            && echo "$body" | grep -q '^ebpfsentinel_ebpf_verifier_rejections'; then
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done
    echo "$body"
}

@test "the verifier refused none of the loads this configuration asked for" {
    require_root

    # The agent counts a refusal only where the verifier actually spoke: a load
    # that failed with an empty log failed for a reason of its own and is not
    # the verifier saying no. So a non-zero figure here is a program this build
    # cannot run, and the agent log carries the verifier's own words for it.
    local refusals
    refusals="$(_wait_for_program_set \
        | grep '^ebpfsentinel_ebpf_verifier_rejections' | head -1 | awk '{print $2}')"
    [ -n "$refusals" ]
    if [ "${refusals%.*}" -ne 0 ]; then
        echo "# verifier refused ${refusals} load(s):" >&3
        _load_log >&3
        false
    fi
}

@test "every program the configuration asks for is in the kernel" {
    require_root

    # One gauge series per program the agent tried, 1 when it loaded. A zero is
    # a program that is not in the kernel while the agent carries on, and a
    # missing series is a feature the agent never got to - both of which this
    # fixture has turned on.
    local body
    body="$(_wait_for_program_set)"
    echo "$body" | grep -q '^ebpfsentinel_ebpf_program_status{'

    local missing=() down=() program line
    for program in "${EXPECTED_PROGRAMS[@]}"; do
        line="$(echo "$body" \
            | grep "^ebpfsentinel_ebpf_program_status{program=\"${program}\"}" || true)"
        if [ -z "$line" ]; then
            missing+=("$program")
        elif [ "$(echo "$line" | awk '{print $2}')" != "1" ]; then
            down+=("$program")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ] || [ "${#down[@]}" -gt 0 ]; then
        [ "${#missing[@]}" -eq 0 ] || echo "# never attempted: ${missing[*]}" >&3
        [ "${#down[@]}" -eq 0 ] || echo "# not loaded: ${down[*]}" >&3
        _load_log >&3
        false
    fi
}

@test "the process table names a program that execed after the hooks attached" {
    require_root
    require_tool jq

    # The exec tracepoint is the only way into the table, so a process that
    # started before the agent is deliberately absent. One started now must be
    # there, with the path the kernel execed rather than the sixteen bytes of
    # comm, which is what tells a resolved identity from a guessed one.
    _wait_for_program_set >/dev/null

    sleep 30 &
    local target=$!
    # The event crosses a ring buffer and a channel before the table holds it.
    local waited=0 body="" entry=""
    while [ "$waited" -lt 10 ]; do
        body="$(api_get /api/v1/processes)"
        _load_http_status
        [ "$HTTP_STATUS" = "200" ]
        entry="$(echo "$body" | jq -c --argjson pid "$target" \
            '.processes[] | select(.pid == $pid)')"
        [ -z "$entry" ] || break
        sleep 1
        waited=$((waited + 1))
    done
    kill "$target" 2>/dev/null || true

    if [ -z "$entry" ]; then
        echo "# pid ${target} never reached the process table" >&3
        echo "$body" | jq -c '.tracing, .stats' >&3
        false
    fi

    [ "$(echo "$entry" | jq -r '.identity.kind')" = "path" ]
    assert_contains "$(echo "$entry" | jq -r '.identity.path')" "sleep"
}

@test "the exit tracepoint removes the entry rather than ageing it out" {
    require_root
    require_tool jq

    _wait_for_program_set >/dev/null

    sleep 5 &
    local target=$!
    local waited=0 present=""
    while [ "$waited" -lt 10 ]; do
        present="$(api_get /api/v1/processes \
            | jq -r --argjson pid "$target" '[.processes[] | select(.pid == $pid)] | length')"
        [ "$present" = "0" ] || break
        sleep 1
        waited=$((waited + 1))
    done
    [ "$present" = "1" ]

    wait "$target" 2>/dev/null || true

    waited=0
    while [ "$waited" -lt 10 ]; do
        present="$(api_get /api/v1/processes \
            | jq -r --argjson pid "$target" '[.processes[] | select(.pid == $pid)] | length')"
        [ "$present" = "0" ] && break
        sleep 1
        waited=$((waited + 1))
    done
    if [ "$present" != "0" ]; then
        echo "# pid ${target} exited and the table still holds it" >&3
        false
    fi

    # A purge is an exit the table had an entry for. An exit it did not is
    # counted apart, because a process that execed before the hooks attached
    # has nothing to remove and that is not the same failure.
    local purged
    purged="$(api_get /api/v1/processes | jq -r '.stats.purged')"
    [ "${purged:-0}" -ge 1 ]
}

@test "the kernel agrees the datapath is attached" {
    require_root
    require_tool bpftool

    # The gauge says the program loaded, which is not the same as the kernel
    # running it: an object can load and attach nowhere. The agent counts that
    # case too, and the interface itself is the second opinion.
    local blocked
    blocked="$(get_metrics_value ebpfsentinel_ebpf_attach_blocked)" || true
    if [ -n "$blocked" ] && [ "${blocked%.*}" -ne 0 ]; then
        echo "# ${blocked} program(s) loaded and attached nowhere" >&3
        false
    fi

    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}
