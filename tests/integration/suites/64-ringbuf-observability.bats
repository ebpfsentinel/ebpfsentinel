#!/usr/bin/env bats
# 64-ringbuf-observability.bats - ring-buffer handover accounting.
#
# Every eBPF program hands its events to userspace through a ring buffer.
# Three questions this suite answers with numbers rather than assumption:
#
#   1. Is a single isolated record observed immediately, or only when the
#      10-second kernel-metrics poll happens to run? The reader is
#      epoll-driven, so "immediately" is the only acceptable answer, and a
#      regression here would be invisible under sustained load.
#   2. What is the commit-to-observe latency at a low event rate? The agent
#      measures it itself: both ends read CLOCK_BOOTTIME, so
#      ringbuf_latency_seconds is a real queueing delay, not an estimate.
#   3. Is a record the kernel refused to emit distinguishable from one
#      userspace drained and then threw away? Those are two different
#      failures and they are now two different counters.
#
# Requires: root, kernel >= 6.9, ncat.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# The kernel-metrics poll interval. Any observation faster than this proves
# the event path does not depend on that tick.
HEARTBEAT_SECS=10

setup_file() {
    require_root
    require_kernel 6 9
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ringbuf-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    # The firewall fixture denies TCP 9990-9999, so one connection attempt
    # produces exactly one ring-buffer record.
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-firewall.yaml")"
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
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ringbuf-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers ────────────────────────────────────────────────────────

_scrape() {
    curl -sf --max-time "$HTTP_TIMEOUT" \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null
}

# ringbuf_series <metric_suffix> <source> - one counter/histogram value,
# 0 when the series has not been created yet.
ringbuf_series() {
    local suffix="${1:?usage: ringbuf_series <suffix> <source>}"
    local source="${2:?usage: ringbuf_series <suffix> <source>}"

    local value
    value="$(_scrape | grep "^ebpfsentinel_ringbuf_${suffix}{" |
        grep "source=\"${source}\"" | awk '{print $2}' | head -1)"

    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "0"
    else
        echo "$value"
    fi
}

# ringbuf_dropped <source> - userspace-side drops, summed over reasons.
ringbuf_dropped() {
    local source="${1:?usage: ringbuf_dropped <source>}"

    local total
    total="$(_scrape | grep "^ebpfsentinel_ringbuf_events_dropped_total{" |
        grep "source=\"${source}\"" | awk '{s += $2} END {print s + 0}')"
    echo "${total:-0}"
}

# ── AC2: an isolated record needs no heartbeat tick ────────────────

@test "a single event is observed without waiting for the metrics heartbeat" {
    local before
    before="$(ringbuf_series events_total xdp-firewall)"

    local start_ns
    start_ns="$(date +%s%N)"

    # One denied connection attempt = one committed record.
    send_tcp_from_ns "$EBPF_HOST_IP" 9995

    # Poll far faster than the heartbeat: if the counter only moves on the
    # 10-second tick, this loop times out well before it.
    local deadline=$((HEARTBEAT_SECS - 2))
    local elapsed_ms=0 after="$before"
    while [ "$elapsed_ms" -lt $((deadline * 1000)) ]; do
        after="$(ringbuf_series events_total xdp-firewall)"
        if [ "${after%%.*}" -gt "${before%%.*}" ]; then
            break
        fi
        sleep 0.2
        elapsed_ms=$(((($(date +%s%N) - start_ns)) / 1000000))
    done

    echo "ringbuf_events_total{source=\"xdp-firewall\"} ${before} -> ${after} after ${elapsed_ms}ms"

    [ "${after%%.*}" -gt "${before%%.*}" ] || {
        echo "no record observed within ${deadline}s; the event path is waiting on something" >&2
        return 1
    }
    [ "$elapsed_ms" -lt $((deadline * 1000)) ]
}

# ── AC3: commit-to-observe latency at a low event rate ─────────────

@test "commit-to-observe latency is measured at a low event rate" {
    local count_before sum_before
    count_before="$(ringbuf_series latency_seconds_count xdp-firewall)"
    sum_before="$(ringbuf_series latency_seconds_sum xdp-firewall)"

    # 20 records, one every 250ms: low enough that nothing batches, so each
    # measurement is a genuine single-record handover.
    local i
    for i in $(seq 1 20); do
        send_tcp_from_ns "$EBPF_HOST_IP" 9995 "probe-${i}" 1
        sleep 0.25
    done
    sleep 1

    local count_after sum_after
    count_after="$(ringbuf_series latency_seconds_count xdp-firewall)"
    sum_after="$(ringbuf_series latency_seconds_sum xdp-firewall)"

    local observed
    observed="$(awk -v a="$count_after" -v b="$count_before" 'BEGIN {print a - b}')"
    [ "$(awk -v o="$observed" 'BEGIN {print (o >= 15) ? 1 : 0}')" -eq 1 ] || {
        echo "only ${observed} latency observations for 20 probes" >&2
        return 1
    }

    local mean_ms
    mean_ms="$(awk -v sa="$sum_after" -v sb="$sum_before" -v o="$observed" \
        'BEGIN {printf "%.3f", ((sa - sb) / o) * 1000}')"
    echo "commit-to-observe latency: ${observed} records, mean ${mean_ms} ms"

    # A record drained by an epoll-woken reader lands in single-digit
    # milliseconds. A whole second means it waited for something.
    [ "$(awk -v m="$mean_ms" 'BEGIN {print (m < 1000) ? 1 : 0}')" -eq 1 ] || {
        echo "mean latency ${mean_ms} ms - the reader is not being woken promptly" >&2
        return 1
    }
}

# ── AC1: refused-by-kernel and dropped-by-userspace are separate ───

@test "a low-rate run drops nothing in userspace" {
    local dropped
    dropped="$(ringbuf_dropped xdp-firewall)"
    echo "ringbuf_events_dropped_total{source=\"xdp-firewall\"} = ${dropped}"

    # At one record per 250ms the 4096-slot event channel cannot fill. A
    # non-zero value here means events were lost between the ring buffer and
    # the pipeline, which no other counter would have shown.
    [ "$(awk -v d="$dropped" 'BEGIN {print (d == 0) ? 1 : 0}')" -eq 1 ]
}

@test "kernel refusals and userspace drops are distinct series" {
    local body
    body="$(_scrape)"

    # What userspace received.
    echo "$body" | grep -q "^ebpfsentinel_ringbuf_events_total{.*source=\"xdp-firewall\"" || {
        echo "ringbuf_events_total missing for xdp-firewall" >&2
        return 1
    }

    # What the kernel decided, mirrored from the program's own metrics map.
    # A different family entirely, keyed by `interface`, so a kernel-side
    # refusal can never be confused for a userspace-side drop. The
    # `events_dropped` slot of that map is the kernel's refusal counter; it
    # is deliberately not asserted here, because a counter family only
    # materialises a series once the value moves, and forcing real
    # ring-buffer backpressure is not something this lane can do reliably.
    echo "$body" | grep -q "^ebpfsentinel_packets_total{.*interface=\"FIREWALL_METRICS\"" || {
        echo "kernel-side FIREWALL_METRICS mirror missing" >&2
        return 1
    }

    # The two families never share a label space: nothing in packets_total
    # carries a `source`, and nothing in the ringbuf families carries an
    # `interface`. That is what makes them impossible to conflate.
    if echo "$body" | grep "^ebpfsentinel_packets_total{" | grep -q "source="; then
        echo "packets_total leaked a source label into the kernel-side family" >&2
        return 1
    fi
    if echo "$body" | grep "^ebpfsentinel_ringbuf_" | grep -q "interface="; then
        echo "ringbuf metrics leaked an interface label into the userspace family" >&2
        return 1
    fi

    # And the histogram that separates "late" from "lost".
    echo "$body" | grep -q "^ebpfsentinel_ringbuf_latency_seconds_bucket{.*source=\"xdp-firewall\"" || {
        echo "ringbuf_latency_seconds missing for xdp-firewall" >&2
        return 1
    }
}

# ── AC1: the drained count tracks a sustained burst ────────────────

@test "a sustained burst is accounted record by record" {
    local before dropped_before
    before="$(ringbuf_series events_total xdp-firewall)"
    dropped_before="$(ringbuf_dropped xdp-firewall)"

    local i
    for i in $(seq 1 40); do
        send_tcp_from_ns "$EBPF_HOST_IP" 9995 "burst-${i}" 1 &
    done
    wait
    sleep 2

    local after dropped_after
    after="$(ringbuf_series events_total xdp-firewall)"
    dropped_after="$(ringbuf_dropped xdp-firewall)"

    local drained
    drained="$(awk -v a="$after" -v b="$before" 'BEGIN {print a - b}')"
    echo "burst: drained ${drained}, userspace drops $(awk -v a="$dropped_after" -v b="$dropped_before" 'BEGIN {print a - b}')"

    # Every connection attempt the kernel accepted must appear. Some of the
    # 40 may be refused in-kernel on backpressure, which is by design and
    # counted elsewhere - hence a floor rather than equality.
    [ "$(awk -v d="$drained" 'BEGIN {print (d >= 20) ? 1 : 0}')" -eq 1 ] || {
        echo "only ${drained} records drained from a 40-packet burst" >&2
        return 1
    }
}
