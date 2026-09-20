#!/usr/bin/env bats
# 66-ids-kernel-ct-kill.bats - what the agent decided against what the kernel applied.
#
# A packet matching a block-mode IDS rule takes one branch of tc-ids. That
# branch does two things and counts both: it asks the kernel to mark the
# netfilter conntrack entry behind the flow as DYING, and it shoots the
# packet. `dropped` is therefore the attempt count as well as the drop
# count, and `ct_kill_confirmed` is the kernel's own word on how many of
# those attempts found an entry to mark.
#
# The two are not the same number and are not meant to be: a flow with no
# conntrack entry is dropped and confirms nothing, which is ordinary rather
# than a fault. What must hold is that the confirmation never runs ahead of
# the attempt, and that the series exists at all - a build that never looked
# and a build that looked and found nothing used to be the same zero.
#
# Which of the two a packet gets is decided by where the tc hook sits in the
# kernel's own order, and this suite drives both sides of it on purpose. A
# packet arriving from the namespace hits tc ingress before netfilter's
# PREROUTING, so nothing has created a conntrack entry yet and the tear-down
# finds nothing to mark. A packet the host sends toward the namespace has
# already been through OUTPUT and POSTROUTING, where netfilter creates and
# confirms the entry, by the time tc egress runs - so the same branch of the
# same program finds an entry and the kernel confirms the tear-down. One
# direction proves the counter moves, the other proves it is not simply a
# copy of the drop count.
#
# Requires: root, kernel >= 6.9, ncat.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 9
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ids-kill-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-ids-kill.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"

    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load. Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ids-kill-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

_scrape() {
    curl -sf --max-time "$HTTP_TIMEOUT" \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null
}

# ids_metric <action> - one slot of the tc-ids metrics map, mirrored onto
# packets_total by the kernel-metrics poll loop. 0 when the series has not
# been created yet.
ids_metric() {
    local action="${1:?usage: ids_metric <action>}"

    local value
    value="$(_scrape | grep '^ebpfsentinel_packets_total{' |
        grep 'interface="IDS_METRICS"' |
        grep "action=\"${action}\"" | awk '{print $2}' | head -1)"

    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "0"
    else
        echo "${value%%.*}"
    fi
}

# _wait_for_ids_series <action> [seconds] - wait for the kernel-metrics poll
# loop to mirror one slot of the tc-ids map onto packets_total. The loop runs
# on its own tick, so a scrape taken the moment the programs finished loading
# is earlier than the first poll rather than evidence of a missing series.
_wait_for_ids_series() {
    local action="${1:?usage: _wait_for_ids_series <action> [seconds]}"
    local deadline="${2:-25}"

    local waited=0
    while [ "$waited" -lt "$deadline" ]; do
        if _scrape | grep -q "interface=\"IDS_METRICS\",action=\"${action}\""; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# _drive_blocked_flows <count> - open connections the IDS rule blocks.
_drive_blocked_flows() {
    local count="${1:-10}"
    local i
    for i in $(seq 1 "$count"); do
        send_tcp_from_ns "$EBPF_HOST_IP" 4444 "ids-kill-${i}" 1
        sleep 0.2
    done
    # The poll loop mirrors the map onto packets_total on its own tick.
    sleep 12
}

# _drive_tracked_flows <count> - open the same blocked connections in the
# direction netfilter has already tracked. The host is the one sending, so
# the entry is created in OUTPUT and confirmed in POSTROUTING before tc
# egress ever sees the packet, which is the only way the tear-down has
# something to mark.
_drive_tracked_flows() {
    local count="${1:-10}"
    local i
    for i in $(seq 1 "$count"); do
        send_tcp_to_ns 4444 "ids-kill-tracked-${i}" 1
        sleep 0.2
    done
    # The poll loop mirrors the map onto packets_total on its own tick.
    sleep 12
}

# ── The series exists whether or not it ever moved ─────────────────

@test "the kernel confirmation is a series of its own beside the drop" {
    # Nothing has been sent yet, so every slot of the map is still at zero.
    # That is the whole point of the assertion: the series has to be there
    # before it has ever moved.
    _wait_for_ids_series dropped || {
        echo "IDS_METRICS dropped slot is not mirrored onto packets_total" >&2
        return 1
    }

    local body
    body="$(_scrape)"

    # The point of the whole counter: it is published at zero rather than
    # materialising the first time it moves, because a missing series and a
    # measured zero read the same way on a screen and mean opposite things.
    echo "$body" | grep -q 'interface="IDS_METRICS",action="ct_kill_confirmed"' || {
        echo "IDS_METRICS ct_kill_confirmed slot is not mirrored onto packets_total" >&2
        return 1
    }

    # What the agent decided is a different family with a different name, so
    # the two can never be read as one number.
    echo "$body" | grep -q '^ebpfsentinel_ids_ct_dying_total' || {
        echo "the userspace verdict counter ids_ct_dying is missing" >&2
        return 1
    }
}

# ── The drop branch is actually taken ──────────────────────────────

@test "a blocked flow is dropped and the attempt is counted" {
    local before
    before="$(ids_metric dropped)"

    _drive_blocked_flows 10

    local after
    after="$(ids_metric dropped)"
    echo "IDS_METRICS dropped: ${before} -> ${after}"

    [ "$after" -gt "$before" ] || {
        echo "no packet was dropped by the block-mode IDS rule" >&2
        return 1
    }
}

# ── The confirmation never runs ahead of the attempt ───────────────

@test "what the kernel confirmed is a subset of what the agent asked for" {
    local dropped confirmed
    dropped="$(ids_metric dropped)"
    confirmed="$(ids_metric ct_kill_confirmed)"

    echo "decided=${dropped} confirmed=${confirmed}"

    # The attempt and the confirmation sit in the same branch of the same
    # program, one attempt per shot packet. A confirmation without an attempt
    # behind it means the two have drifted apart.
    [ "$confirmed" -le "$dropped" ] || {
        echo "the kernel confirmed ${confirmed} tear-downs against ${dropped} attempts" >&2
        return 1
    }
}

@test "the confirmation only moves where the attempt moved" {
    local dropped_before confirmed_before
    dropped_before="$(ids_metric dropped)"
    confirmed_before="$(ids_metric ct_kill_confirmed)"

    _drive_blocked_flows 10

    local dropped_after confirmed_after
    dropped_after="$(ids_metric dropped)"
    confirmed_after="$(ids_metric ct_kill_confirmed)"

    local attempted gained
    attempted=$((dropped_after - dropped_before))
    gained=$((confirmed_after - confirmed_before))
    echo "window: attempted=${attempted} confirmed=${gained}"

    [ "$attempted" -gt 0 ]
    [ "$gained" -ge 0 ]
    [ "$gained" -le "$attempted" ] || {
        echo "${gained} tear-downs confirmed over a window of ${attempted} attempts" >&2
        return 1
    }

    # Whether the kernel had an entry to mark depends on whether netfilter
    # was tracking the flow at all, which this lane does not control. Say
    # which of the two happened rather than asserting one of them.
    if [ "$gained" -gt 0 ]; then
        echo "the kernel found and marked ${gained} of ${attempted} flows"
    else
        echo "no flow had a conntrack entry to mark; every attempt confirmed nothing"
    fi
}

# ── The kernel actually carries the tear-down out ──────────────────

@test "a flow netfilter already tracks is torn down and the kernel says so" {
    local dropped_before confirmed_before
    dropped_before="$(ids_metric dropped)"
    confirmed_before="$(ids_metric ct_kill_confirmed)"

    _drive_tracked_flows 10

    local dropped_after confirmed_after
    dropped_after="$(ids_metric dropped)"
    confirmed_after="$(ids_metric ct_kill_confirmed)"

    local attempted gained
    attempted=$((dropped_after - dropped_before))
    gained=$((confirmed_after - confirmed_before))
    echo "tracked window: attempted=${attempted} confirmed=${gained}"

    [ "$attempted" -gt 0 ] || {
        echo "no packet was dropped on the egress side of the veth" >&2
        return 1
    }

    # This is the assertion the whole counter exists for: the agent decided
    # and the kernel confirmed it carried the decision out. A zero here with
    # a non-zero attempt means the branch counts the attempt and never the
    # confirmation, which reads on a screen as a verifier that found nothing
    # rather than as a counter nobody wired.
    [ "$gained" -gt 0 ] || {
        echo "${attempted} tear-downs attempted on tracked flows and none confirmed" >&2
        return 1
    }

    [ "$gained" -le "$attempted" ] || {
        echo "${gained} tear-downs confirmed over a window of ${attempted} attempts" >&2
        return 1
    }
}
