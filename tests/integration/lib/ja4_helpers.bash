#!/usr/bin/env bash
# ja4_helpers.bash — Drive diverse TLS clients against an agent-side
# TLS target so the agent's JA4 fingerprint cache is populated with
# distinct ClientHello signatures.
#
# Public entrypoints:
#   require_ja4_min                — require curl + openssl (skip otherwise)
#   ja4_have_client <name>         — return 0 if the named client is available
#   start_tls_target [port]        — start openssl s_server on agent VM
#   stop_tls_target                — kill it
#   ja4_connect <client> <sni>     — single TLS connect from attacker VM
#   ja4_summary_count              — GET /api/v1/fingerprints/summary → cached_count
#   ja4_alert_hashes [filter]      — distinct ja4_fingerprint values across alerts
#
# Clients (subset, gated by availability):
#   curl, openssl, urllib3, aiohttp, go, mhddos

JA4_TLS_PORT="${JA4_TLS_PORT:-8443}"
JA4_TARGET_HOST="${JA4_TARGET_HOST:-${AGENT_HOST:-${AGENT_VM_IP:-127.0.0.1}}}"

# Remote paths used when running against the agent VM. Local /tmp under
# 1-VM mode (no SSH wrapper executes anyway since we never call the
# remote variants without EBPF_2VM_MODE=true).
JA4_REMOTE_DIR="${JA4_REMOTE_DIR:-/tmp/ebpfsentinel-ja4}"
JA4_TLS_PID_FILE="${JA4_TLS_PID_FILE:-${JA4_REMOTE_DIR}/s_server.pid}"
JA4_TLS_LOG_FILE="${JA4_TLS_LOG_FILE:-${JA4_REMOTE_DIR}/s_server.log}"
JA4_TLS_CERT_FILE="${JA4_TLS_CERT_FILE:-${JA4_REMOTE_DIR}/cert.pem}"
JA4_TLS_KEY_FILE="${JA4_TLS_KEY_FILE:-${JA4_REMOTE_DIR}/key.pem}"

# ── Guards ────────────────────────────────────────────────────────────

require_ja4_min() {
    if ! command -v curl >/dev/null 2>&1; then
        skip "curl not available on attacker VM"
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        skip "openssl not available on attacker VM"
    fi
}

# ja4_have_client <name>
# Returns 0 if the named client can be exercised on the attacker VM.
ja4_have_client() {
    local client="${1:?usage: ja4_have_client <name>}"
    case "$client" in
        curl)
            command -v curl >/dev/null 2>&1
            ;;
        openssl)
            command -v openssl >/dev/null 2>&1
            ;;
        urllib3)
            command -v python3 >/dev/null 2>&1 \
                && python3 -c "import urllib3" >/dev/null 2>&1
            ;;
        aiohttp)
            command -v python3 >/dev/null 2>&1 \
                && python3 -c "import aiohttp, asyncio" >/dev/null 2>&1
            ;;
        go)
            command -v go >/dev/null 2>&1
            ;;
        mhddos)
            # Detect either the system-installed `mhddos` wrapper or the
            # MHDDoS sources cloned by story 34.3.
            command -v mhddos >/dev/null 2>&1 \
                || [ -f "${MHDDOS_HOME:-/opt/mhddos}/start.py" ]
            ;;
        *)
            return 1
            ;;
    esac
}

# ── TLS target lifecycle (agent VM) ───────────────────────────────────

# _ja4_remote_exec <command>
# Run a command on the agent VM in 2VM mode, locally otherwise.
_ja4_remote_exec() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo "$@"
    else
        "$@"
    fi
}

# _ja4_remote_exec_user <command>
# Run a command on the agent VM as the vagrant user (non-sudo).
_ja4_remote_exec_user() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh "$@"
    else
        "$@"
    fi
}

# start_tls_target [port]
# Spawn an openssl s_server on the agent VM at the chosen port. The
# server is started detached and its PID written to JA4_TLS_PID_FILE.
# Returns 0 on success.
start_tls_target() {
    local port="${1:-$JA4_TLS_PORT}"

    _ja4_remote_exec mkdir -p "$JA4_REMOTE_DIR" >/dev/null 2>&1 || true

    # Generate a throwaway self-signed cert idempotently.
    _ja4_remote_exec_user bash -c "\
        set -e; \
        if [ ! -s '${JA4_TLS_CERT_FILE}' ] || [ ! -s '${JA4_TLS_KEY_FILE}' ]; then \
            openssl req -x509 -newkey rsa:2048 \
                -keyout '${JA4_TLS_KEY_FILE}' \
                -out '${JA4_TLS_CERT_FILE}' \
                -sha256 -days 1 -nodes \
                -subj '/CN=ja4-target.test' >/dev/null 2>&1; \
        fi" || return 1

    # Spawn s_server detached. Always reachable on 0.0.0.0.
    _ja4_remote_exec bash -c "\
        : > '${JA4_TLS_LOG_FILE}'; \
        setsid openssl s_server \
            -accept ${port} \
            -cert '${JA4_TLS_CERT_FILE}' \
            -key '${JA4_TLS_KEY_FILE}' \
            -www -quiet -naccept 200 \
            >'${JA4_TLS_LOG_FILE}' 2>&1 & \
        echo \$! > '${JA4_TLS_PID_FILE}'" || return 1

    # Probe readiness up to 5 s.
    local i
    for i in 1 2 3 4 5; do
        if openssl s_client -connect "${JA4_TARGET_HOST}:${port}" \
            -servername health-check.test </dev/null >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# stop_tls_target — best-effort kill of the s_server started above.
stop_tls_target() {
    _ja4_remote_exec bash -c "\
        if [ -s '${JA4_TLS_PID_FILE}' ]; then \
            pid=\"\$(cat '${JA4_TLS_PID_FILE}')\"; \
            kill -TERM \"\${pid}\" 2>/dev/null || true; \
            sleep 1; \
            kill -KILL \"\${pid}\" 2>/dev/null || true; \
        fi; \
        pkill -f 'openssl s_server.*-accept ${JA4_TLS_PORT}' 2>/dev/null || true; \
        rm -f '${JA4_TLS_PID_FILE}'" >/dev/null 2>&1 || true
}

# ── Per-client connect routines ───────────────────────────────────────
#
# Each routine emits exactly one TLS ClientHello to the target. We
# never assert on the client's exit code — the agent observes packets
# regardless of whether the handshake completes cleanly.

_ja4_connect_curl() {
    local sni="$1"
    curl -sk --max-time 5 \
        --resolve "${sni}:${JA4_TLS_PORT}:${JA4_TARGET_HOST}" \
        "https://${sni}:${JA4_TLS_PORT}/" >/dev/null 2>&1 || true
}

_ja4_connect_openssl() {
    local sni="$1"
    : | openssl s_client \
        -connect "${JA4_TARGET_HOST}:${JA4_TLS_PORT}" \
        -servername "$sni" \
        -tls1_2 -no_tls1_3 -quiet >/dev/null 2>&1 || true
}

_ja4_connect_urllib3() {
    local sni="$1"
    python3 - "$sni" "$JA4_TARGET_HOST" "$JA4_TLS_PORT" <<'PY' >/dev/null 2>&1 || true
import socket, ssl, sys
sni, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
addr = (host, port)
with socket.create_connection(addr, timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname=sni) as s:
        try:
            s.do_handshake()
        except Exception:
            pass
PY
}

_ja4_connect_aiohttp() {
    local sni="$1"
    python3 - "$sni" "$JA4_TARGET_HOST" "$JA4_TLS_PORT" <<'PY' >/dev/null 2>&1 || true
import asyncio, ssl, sys
import aiohttp
sni, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

async def go():
    connector = aiohttp.TCPConnector(ssl=ctx, force_close=True)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            url = f"https://{sni}:{port}/"
            try:
                async with session.get(url, server_hostname=sni,
                                       timeout=aiohttp.ClientTimeout(total=5)) as r:
                    await r.read()
            except Exception:
                pass
    except Exception:
        pass

asyncio.run(go())
PY
}

_ja4_connect_go() {
    local sni="$1"
    local tmpdir
    tmpdir="$(mktemp -d -t ja4-go.XXXXXX)" || return 0
    cat >"${tmpdir}/main.go" <<'GO'
package main

import (
    "crypto/tls"
    "fmt"
    "net"
    "os"
    "time"
)

func main() {
    if len(os.Args) < 4 {
        os.Exit(0)
    }
    sni, host, port := os.Args[1], os.Args[2], os.Args[3]
    cfg := &tls.Config{
        ServerName:         sni,
        InsecureSkipVerify: true,
    }
    d := &net.Dialer{Timeout: 5 * time.Second}
    conn, err := tls.DialWithDialer(d, "tcp", fmt.Sprintf("%s:%s", host, port), cfg)
    if err != nil {
        return
    }
    defer conn.Close()
    _ = conn.Handshake()
}
GO
    ( cd "$tmpdir" && go run main.go "$sni" "$JA4_TARGET_HOST" "$JA4_TLS_PORT" \
        >/dev/null 2>&1 ) || true
    rm -rf "$tmpdir"
}

_ja4_connect_mhddos() {
    local sni="$1"
    local home="${MHDDOS_HOME:-/opt/mhddos}"
    # MHDDoS' TLS method drives a custom ClientHello via Python+tls-client.
    # We invoke a one-shot probe: 1 worker, 1 second, against the target.
    if [ -f "${home}/start.py" ]; then
        ( cd "$home" && python3 start.py TLS \
            "https://${sni}:${JA4_TLS_PORT}/" 1 1 1 1 \
            >/dev/null 2>&1 ) || true
    else
        # Fallback: emit a ClientHello via Python's ssl module with a
        # forced cipher list distinct from the urllib3 default.
        python3 - "$sni" "$JA4_TARGET_HOST" "$JA4_TLS_PORT" <<'PY' >/dev/null 2>&1 || true
import socket, ssl, sys
sni, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
addr = (host, port)
try:
    with socket.create_connection(addr, timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            try:
                s.do_handshake()
            except Exception:
                pass
except Exception:
    pass
PY
    fi
}

# ja4_connect <client> <sni>
ja4_connect() {
    local client="${1:?usage: ja4_connect <client> <sni>}"
    local sni="${2:?usage: ja4_connect <client> <sni>}"
    case "$client" in
        curl)     _ja4_connect_curl "$sni" ;;
        openssl)  _ja4_connect_openssl "$sni" ;;
        urllib3)  _ja4_connect_urllib3 "$sni" ;;
        aiohttp)  _ja4_connect_aiohttp "$sni" ;;
        go)       _ja4_connect_go "$sni" ;;
        mhddos)   _ja4_connect_mhddos "$sni" ;;
        *)
            echo "ja4_connect: unknown client '${client}'" >&2
            return 2
            ;;
    esac
}

# ── Observation helpers ───────────────────────────────────────────────

# ja4_summary_count — return the agent's cached fingerprint count.
ja4_summary_count() {
    local body
    body="$(api_get /api/v1/fingerprints/summary 2>/dev/null)" || return 1
    _load_http_status
    [ "${HTTP_STATUS:-0}" = "200" ] || return 1
    echo "$body" | jq -r '.cached_count // 0'
}

# ja4_alert_hashes [extra-jq-filter]
# Print one JA4 hash per line for alerts that have ja4_fingerprint set.
# Optional second-stage jq filter narrows by e.g. rule id.
ja4_alert_hashes() {
    local filter="${1:-.}"
    local body
    body="$(api_get /api/v1/alerts?limit=1000 2>/dev/null)" || return 1
    _load_http_status
    [ "${HTTP_STATUS:-0}" = "200" ] || return 1
    echo "$body" \
        | jq -r ".alerts[] | ${filter} | select(.ja4_fingerprint != null) | .ja4_fingerprint" \
        | sort -u
}

# ja4_distinct_hash_count
# Convenience: how many distinct JA4 hashes are surfaced on stored alerts.
ja4_distinct_hash_count() {
    ja4_alert_hashes "." | grep -c .
}
