#!/usr/bin/env bash
# slowhttp_helpers.bash — Drive slowhttptest from BATS suites.
#
# slowhttptest is provisioned on the attacker VM (Story 34.3) via the
# distro package and exposes three attack modes:
#   -H  Slowloris    — slow GET headers (default)
#   -B  RUDY         — slow POST body
#   -X  Slowread     — slow TCP receive window
#
# Helpers stay declarative: tests call run_slowhttp <mode> [duration]
# and the helper picks sane defaults for connection count, rate, and
# header/data sizes that reliably trip an L7 slow-request timeout in
# under 30 s.
#
# Public entrypoints:
#   require_slowhttptest     — skip the calling test if not installed
#   run_slowhttp <mode> [duration] [conns] [rate] [path]
#                            — foreground attack, returns slowhttptest's
#                              exit code (captured in SLOWHTTP_LOG)
#   run_slowhttp_background  — same args, returns immediately, exports
#                              SLOWHTTP_PID for later wait/kill
#   stop_slowhttp            — best-effort kill of the background run
#   attacker_ip              — agent-visible source IP for blacklist asserts
#
# Tests MUST assert on agent-side side-effects (metric / alert / IPS),
# NOT on slowhttptest's exit code: the tool returns non-zero whenever
# its connection pool is denied service, which is the success state.

SLOWHTTP_BIN="${SLOWHTTP_BIN:-/usr/bin/slowhttptest}"
SLOWHTTP_DEFAULT_DURATION="${SLOWHTTP_DEFAULT_DURATION:-30}"
SLOWHTTP_DEFAULT_CONNS="${SLOWHTTP_DEFAULT_CONNS:-500}"
SLOWHTTP_DEFAULT_RATE="${SLOWHTTP_DEFAULT_RATE:-200}"
SLOWHTTP_DEFAULT_INTERVAL="${SLOWHTTP_DEFAULT_INTERVAL:-10}"

# ── Guards ────────────────────────────────────────────────────────────

# require_slowhttptest
# Skip the calling test if slowhttptest is not installed locally.
require_slowhttptest() {
    if ! command -v slowhttptest >/dev/null 2>&1 && [ ! -x "$SLOWHTTP_BIN" ]; then
        skip "slowhttptest not installed (run story 34.3 provisioner)"
    fi
}

# _slowhttp_validate_target <ip>
# Refuse non-RFC1918 targets — guards against accidental public-net flooding.
_slowhttp_validate_target() {
    local ip="${1:?usage: _slowhttp_validate_target <ip>}"
    case "$ip" in
        10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*| \
        172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*| \
        172.28.*|172.29.*|172.30.*|172.31.*|192.168.*|127.*)
            return 0
            ;;
        *)
            skip "slowhttptest target ${ip} is not RFC1918 — refusing to flood"
            ;;
    esac
}

# _slowhttp_mode_flag <mode>
# Maps a logical mode name to the slowhttptest CLI flag.
#   slowloris → -H   (slow headers)
#   rudy      → -B   (slow body / POST)
#   slowread  → -X   (slow read)
_slowhttp_mode_flag() {
    case "$1" in
        slowloris|H|headers|GET)  echo "-H" ;;
        rudy|B|body|POST)         echo "-B" ;;
        slowread|X|read|R)        echo "-X" ;;
        *)
            echo "_slowhttp_mode_flag: unknown mode '$1'" >&2
            return 2
            ;;
    esac
}

# ── Public entrypoints ────────────────────────────────────────────────

# run_slowhttp <mode> [duration] [conns] [rate] [path]
# Foreground attack. Captures output to SLOWHTTP_LOG. Returns 0 even on
# slowhttptest non-zero exit; callers MUST inspect agent-side metrics.
run_slowhttp() {
    local mode="${1:?usage: run_slowhttp <mode> [duration] [conns] [rate] [path]}"
    local duration="${2:-$SLOWHTTP_DEFAULT_DURATION}"
    local conns="${3:-$SLOWHTTP_DEFAULT_CONNS}"
    local rate="${4:-$SLOWHTTP_DEFAULT_RATE}"
    local path="${5:-/}"

    require_slowhttptest

    local target_ip="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"
    local target_port="${AGENT_HTTP_PORT:-8080}"
    _slowhttp_validate_target "$target_ip"

    local mode_flag
    mode_flag="$(_slowhttp_mode_flag "$mode")" || return 2

    local target_url="http://${target_ip}:${target_port}${path}"

    SLOWHTTP_LOG="${SLOWHTTP_LOG:-/tmp/slowhttp-${mode}-$$.log}"
    : > "$SLOWHTTP_LOG"

    local hard_timeout=$((duration + 10))
    timeout --signal=TERM --kill-after=5 "${hard_timeout}s" \
        "$SLOWHTTP_BIN" \
            "$mode_flag" \
            -c "$conns" \
            -r "$rate" \
            -i "$SLOWHTTP_DEFAULT_INTERVAL" \
            -l "$duration" \
            -t GET \
            -u "$target_url" \
            -p 3 \
            >>"$SLOWHTTP_LOG" 2>&1 || true

    return 0
}

# run_slowhttp_background <mode> [duration] [conns] [rate] [path]
# Same as run_slowhttp but non-blocking. Exports SLOWHTTP_PID / SLOWHTTP_LOG.
run_slowhttp_background() {
    local mode="${1:?usage: run_slowhttp_background <mode> [duration] [conns] [rate] [path]}"
    local duration="${2:-$SLOWHTTP_DEFAULT_DURATION}"
    local conns="${3:-$SLOWHTTP_DEFAULT_CONNS}"
    local rate="${4:-$SLOWHTTP_DEFAULT_RATE}"
    local path="${5:-/}"

    require_slowhttptest

    local target_ip="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"
    local target_port="${AGENT_HTTP_PORT:-8080}"
    _slowhttp_validate_target "$target_ip"

    local mode_flag
    mode_flag="$(_slowhttp_mode_flag "$mode")" || return 2

    local target_url="http://${target_ip}:${target_port}${path}"

    SLOWHTTP_LOG="${SLOWHTTP_LOG:-/tmp/slowhttp-${mode}-bg-$$.log}"
    : > "$SLOWHTTP_LOG"

    local hard_timeout=$((duration + 10))
    (
        exec timeout --signal=TERM --kill-after=5 "${hard_timeout}s" \
            "$SLOWHTTP_BIN" \
                "$mode_flag" \
                -c "$conns" \
                -r "$rate" \
                -i "$SLOWHTTP_DEFAULT_INTERVAL" \
                -l "$duration" \
                -t GET \
                -u "$target_url" \
                -p 3 \
                </dev/null >>"$SLOWHTTP_LOG" 2>&1
    ) &
    SLOWHTTP_PID=$!
    export SLOWHTTP_PID SLOWHTTP_LOG
}

# stop_slowhttp
# Terminate a backgrounded slowhttptest run.
stop_slowhttp() {
    if [ -n "${SLOWHTTP_PID:-}" ]; then
        kill -TERM "$SLOWHTTP_PID" 2>/dev/null || true
        wait "$SLOWHTTP_PID" 2>/dev/null || true
        unset SLOWHTTP_PID
    fi
}

# slowhttp_legit_request <duration> [path]
# Open a single connection that streams a request just slow enough to
# stay *inside* the agent's slow-request timeout — used as a false-
# positive guard. Writes one CRLF every floor(duration/2) seconds.
#
# We use curl --limit-rate against a fast-responding path; the body is
# delivered in two CRLF chunks so total wall-clock < timeout-policy.
slowhttp_legit_request() {
    local duration="${1:-5}"
    local path="${2:-/}"

    local target_ip="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"
    local target_port="${AGENT_HTTP_PORT:-8080}"
    _slowhttp_validate_target "$target_ip"

    local url="http://${target_ip}:${target_port}${path}"
    # Two-chunk delay; both halves arrive before the slow-request timer fires.
    (
        printf 'GET %s HTTP/1.1\r\nHost: %s\r\n' "$path" "$target_ip"
        sleep "$((duration / 2))"
        printf 'User-Agent: legit-slow/1.0\r\n\r\n'
    ) | timeout "$((duration + 5))s" nc "$target_ip" "$target_port" >/dev/null 2>&1 || true
}
