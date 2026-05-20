#!/usr/bin/env bash
# mhddos_helpers.bash — Drive MHDDoS from BATS suites.
#
# MHDDoS is provisioned at /opt/MHDDoS on the attacker VM (Story 34.3),
# with a dedicated venv at /opt/MHDDoS/.venv and a `.tor-disabled` flag
# that the helper honours to force deterministic origin IPs (no exit
# rotation, no Internet fan-out). Use from BATS via:
#
#   run_mhddos GET   30 10            # method, duration_secs, threads
#   run_mhddos POST  30 10 "/login"   # optional path override
#
# Output is captured into MHDDOS_LOG (per-invocation tmpfile) and the
# exit code of /opt/MHDDoS/start.py is returned. Tests check metric /
# alert side-effects on the agent, not the helper's exit code, because
# MHDDoS itself exits non-zero whenever the target connection rate
# drops (which is expected when the agent rate-limits or blocks).
#
# Skip-on-network-error guard: if the local route to the target is the
# default gateway (rather than the private 192.168.56.0/24 link), the
# helper aborts via `skip` — accidentally aiming MHDDoS at the public
# Internet during a CI accident must NOT silently succeed.

MHDDOS_DIR="${MHDDOS_DIR:-/opt/MHDDoS}"
MHDDOS_VENV="${MHDDOS_VENV:-${MHDDOS_DIR}/.venv}"
MHDDOS_PY="${MHDDOS_PY:-${MHDDOS_VENV}/bin/python3}"
MHDDOS_START="${MHDDOS_START:-${MHDDOS_DIR}/start.py}"
MHDDOS_TOR_FLAG="${MHDDOS_TOR_FLAG:-${MHDDOS_DIR}/.tor-disabled}"
MHDDOS_DEFAULT_RPC="${MHDDOS_DEFAULT_RPC:-100}"
MHDDOS_DEFAULT_THREADS="${MHDDOS_DEFAULT_THREADS:-10}"
MHDDOS_DEFAULT_DURATION="${MHDDOS_DEFAULT_DURATION:-30}"

# ── Guards ────────────────────────────────────────────────────────────

# require_mhddos
# Skip the calling test if MHDDoS is not installed on this host.
require_mhddos() {
    if [ ! -x "${MHDDOS_PY}" ] || [ ! -f "${MHDDOS_START}" ]; then
        skip "MHDDoS not provisioned at ${MHDDOS_DIR} (run story 34.3 provisioner)"
    fi
    if [ ! -f "${MHDDOS_TOR_FLAG}" ]; then
        skip "MHDDoS Tor disable flag missing (${MHDDOS_TOR_FLAG})"
    fi
}

# _mhddos_validate_target <ip>
# Refuse to drive MHDDoS at anything outside the private test network.
# Prevents an environment-variable mishap from launching a flood at a
# real Internet address.
_mhddos_validate_target() {
    local ip="${1:?usage: _mhddos_validate_target <ip>}"
    case "$ip" in
        10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*| \
        172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*| \
        172.28.*|172.29.*|172.30.*|172.31.*|192.168.*|127.*)
            return 0
            ;;
        *)
            skip "MHDDoS target ${ip} is not RFC1918 — refusing to flood public address"
            ;;
    esac
}

# _mhddos_method_args <method> <target_url> <duration> <threads> [path]
# Build the start.py argument vector for a given attack method.
#
# MHDDoS expects positional args in the order: <method> <target> <args...>.
# The exact tail differs per method; we route through this dispatcher so
# the per-test call sites stay declarative.
_mhddos_method_args() {
    local method="$1"
    local target="$2"
    local duration="$3"
    local threads="$4"
    local extra="${5:-}"

    case "$method" in
        # L7 HTTP/HTTPS floods — all share <method> <url> useproxy rpc threads duration
        GET|POST|STRESS|BYPASS|OVH|TLS|CFB)
            # useproxy=0 disables the proxy pool; rpc = requests per connection
            printf '%s\n%s\n0\n%d\n%d\n%d\n' \
                "$method" "${target}${extra}" "$MHDDOS_DEFAULT_RPC" \
                "$threads" "$duration"
            ;;
        # SLOW = slowloris-style; same arg shape as the L7 floods.
        SLOW)
            printf '%s\n%s\n0\n%d\n%d\n%d\n' \
                "$method" "${target}${extra}" "$MHDDOS_DEFAULT_RPC" \
                "$threads" "$duration"
            ;;
        *)
            echo "_mhddos_method_args: unknown method '${method}'" >&2
            return 2
            ;;
    esac
}

# ── Public entrypoint ─────────────────────────────────────────────────

# run_mhddos <method> [duration_secs] [threads] [path]
# Drive MHDDoS against the agent's HTTP port. Captures stdout+stderr to
# MHDDOS_LOG and ALWAYS returns 0 — callers MUST assert on the agent's
# observable side-effects (metrics / alerts / blacklist), never on
# MHDDoS's own exit code.
run_mhddos() {
    local method="${1:?usage: run_mhddos <method> [duration] [threads] [path]}"
    local duration="${2:-$MHDDOS_DEFAULT_DURATION}"
    local threads="${3:-$MHDDOS_DEFAULT_THREADS}"
    local path="${4:-/}"

    require_mhddos

    local target_ip="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"
    local target_port="${AGENT_HTTP_PORT:-8080}"
    _mhddos_validate_target "$target_ip"

    local scheme="http"
    case "$method" in
        TLS|CFB|BYPASS) scheme="https"; target_port="${AGENT_TLS_PORT:-8443}" ;;
    esac
    local target_url="${scheme}://${target_ip}:${target_port}"

    MHDDOS_LOG="${MHDDOS_LOG:-/tmp/mhddos-${method}-$$.log}"
    : > "$MHDDOS_LOG"

    # MHDDoS reads positional args from CLI; feed the dispatcher output as args.
    local -a argv
    mapfile -t argv < <(_mhddos_method_args "$method" "$target_url" "$duration" "$threads" "$path")

    # Run with a hard timeout = duration + 10s grace. start.py loops until
    # SIGTERM, so this guarantees the helper returns deterministically.
    local hard_timeout=$((duration + 10))

    (
        cd "$MHDDOS_DIR" || exit 1
        # shellcheck disable=SC2068
        timeout --signal=TERM --kill-after=5 "${hard_timeout}s" \
            "$MHDDOS_PY" "$MHDDOS_START" ${argv[@]} \
            </dev/null >>"$MHDDOS_LOG" 2>&1
    ) || true

    # MHDDOS_LOG kept on disk for the calling test's debug bundle.
    return 0
}

# run_mhddos_background <method> [duration] [threads] [path]
# Same as run_mhddos but does NOT block. Writes the child PID to
# MHDDOS_PID for later kill. Caller is responsible for wait/kill.
run_mhddos_background() {
    local method="${1:?usage: run_mhddos_background <method> [duration] [threads] [path]}"
    local duration="${2:-$MHDDOS_DEFAULT_DURATION}"
    local threads="${3:-$MHDDOS_DEFAULT_THREADS}"
    local path="${4:-/}"

    require_mhddos

    local target_ip="${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}"
    local target_port="${AGENT_HTTP_PORT:-8080}"
    _mhddos_validate_target "$target_ip"

    local scheme="http"
    case "$method" in
        TLS|CFB|BYPASS) scheme="https"; target_port="${AGENT_TLS_PORT:-8443}" ;;
    esac
    local target_url="${scheme}://${target_ip}:${target_port}"

    MHDDOS_LOG="${MHDDOS_LOG:-/tmp/mhddos-${method}-bg-$$.log}"
    : > "$MHDDOS_LOG"

    local -a argv
    mapfile -t argv < <(_mhddos_method_args "$method" "$target_url" "$duration" "$threads" "$path")

    local hard_timeout=$((duration + 10))
    (
        cd "$MHDDOS_DIR" || exit 1
        # shellcheck disable=SC2068
        exec timeout --signal=TERM --kill-after=5 "${hard_timeout}s" \
            "$MHDDOS_PY" "$MHDDOS_START" ${argv[@]} \
            </dev/null >>"$MHDDOS_LOG" 2>&1
    ) &
    MHDDOS_PID=$!
    export MHDDOS_PID MHDDOS_LOG
}

# stop_mhddos
# Terminate a background MHDDoS run started with run_mhddos_background.
stop_mhddos() {
    if [ -n "${MHDDOS_PID:-}" ]; then
        kill -TERM "$MHDDOS_PID" 2>/dev/null || true
        wait "$MHDDOS_PID" 2>/dev/null || true
        unset MHDDOS_PID
    fi
}

# attacker_ip
# Echoes the IP the agent will see as the attack source. In 2-VM mode
# this is the attacker VM's address; otherwise localhost (host-local
# tests do not exercise IPS auto-blacklist because the whitelist
# covers loopback).
attacker_ip() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        echo "${ATTACKER_VM_IP:-192.168.56.20}"
    else
        echo "127.0.0.1"
    fi
}
