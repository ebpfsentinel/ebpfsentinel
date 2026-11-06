#!/usr/bin/env bats
# 89-tls-handshakes-and-crypto-posture.bats - what the TLS handshakes seen on
# the node negotiated, and the posture of each edge they ran on.
#
# A client in the test namespace reaches servers on the host: openssl
# s_server on 8443 and 8444, and a Python HTTP server on 8880. The suite
# asserts:
#
#   * A TLS 1.3 handshake forced onto x25519 is recorded with its version,
#     its group and a classical key exchange, and its certificate as not
#     observable, since TLS 1.3 encrypts it.
#   * A TLS 1.3 handshake over X25519MLKEM768 is recorded as a post-quantum
#     hybrid and the edge counts it as post-quantum.
#   * A TLS 1.2 handshake is recorded as TLS 1.2, and where the certificate
#     was in the captured flight its validity window is the one the server
#     presented.
#   * A handshake below TLS 1.2 counts as legacy TLS on its edge.
#   * A clear-text HTTP request counts as clear text on its edge, with the
#     protocol named, and never as TLS.
#
# Requires: root, kernel >= 6.12, jq, openssl, python3, curl.

load '../lib/helpers'
load '../lib/ebpf_helpers'

TLS_PORT=8443
LEGACY_PORT=8444
HTTP_PORT=8880

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool openssl
    require_tool python3
    require_tool curl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-posture-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj "/CN=posture.test" \
        -keyout "${DATA_DIR}/key.pem" -out "${DATA_DIR}/cert.pem" >/dev/null 2>&1

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-crypto-posture.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }

    setsid openssl s_server -accept "$TLS_PORT" -www \
        -cert "${DATA_DIR}/cert.pem" -key "${DATA_DIR}/key.pem" \
        >"${DATA_DIR}/s_server.log" 2>&1 </dev/null &
    echo $! > "${DATA_DIR}/s_server.pid"

    # The legacy server ignores the host's openssl configuration, whose
    # minimum protocol would refuse the handshake before the agent sees it.
    OPENSSL_CONF=/dev/null setsid openssl s_server -accept "$LEGACY_PORT" -www \
        -cipher 'DEFAULT:@SECLEVEL=0' \
        -cert "${DATA_DIR}/cert.pem" -key "${DATA_DIR}/key.pem" \
        >"${DATA_DIR}/s_server-legacy.log" 2>&1 </dev/null &
    echo $! > "${DATA_DIR}/s_server-legacy.pid"

    setsid python3 -m http.server "$HTTP_PORT" --bind "$EBPF_HOST_IP" \
        --directory "$DATA_DIR" >"${DATA_DIR}/http.log" 2>&1 </dev/null &
    echo $! > "${DATA_DIR}/http.pid"

    sleep 1
}

teardown_file() {
    local f
    for f in s_server s_server-legacy http; do
        [ -f "${DATA_DIR}/${f}.pid" ] && kill "$(cat "${DATA_DIR}/${f}.pid")" 2>/dev/null
    done
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# _client <port> [s_client args...] - one handshake from the test namespace.
_client() {
    local port="$1"
    shift
    echo | timeout 10 ip netns exec "$EBPF_TEST_NS" \
        openssl s_client -connect "${EBPF_HOST_IP}:${port}" -servername posture.test "$@" \
        >"${DATA_DIR}/s_client.log" 2>&1
}

# _wait_handshake <jq select expression> - the newest recorded handshake the
# expression selects, waited for up to ten seconds.
_wait_handshake() {
    local filter="$1" i body found
    for i in $(seq 1 20); do
        body="$(api_get '/api/v1/tls/handshakes?limit=256')"
        found="$(echo "$body" | jq -c "[.handshakes[] | select(${filter})] | first // empty")"
        if [ -n "$found" ]; then
            echo "$found"
            return 0
        fi
        sleep 0.5
    done
    echo "# no handshake matched ${filter}: ${body}" >&3
    return 1
}

# _wait_edge <port> <jq condition on the edge> - the posture edge to this
# host on the port once the condition holds, waited for up to ten seconds.
_wait_edge() {
    local port="$1" cond="$2" i body found
    for i in $(seq 1 20); do
        body="$(api_get /api/v1/tls/posture)"
        found="$(echo "$body" | jq -c --argjson p "$port" --arg s "$EBPF_HOST_IP" \
            "[.edges[] | select(.server_port == \$p and .server.address == \$s)
              | select(${cond})] | first // empty")"
        if [ -n "$found" ]; then
            echo "$found"
            return 0
        fi
        sleep 0.5
    done
    echo "# no edge on ${port} met ${cond}: ${body}" >&3
    return 1
}

@test "the handshake log is recording" {
    local body
    body="$(api_get /api/v1/tls/handshakes)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    [ "$(echo "$body" | jq -r '.recording')" = "true" ]
    [ "$(echo "$body" | jq -r '.capacity')" -gt 0 ]
}

@test "a TLS 1.3 handshake over x25519 is recorded as classical, its certificate out of sight" {
    _client "$TLS_PORT" -tls1_3 -groups X25519 || {
        cat "${DATA_DIR}/s_client.log" >&3
        false
    }
    local hs
    hs="$(_wait_handshake '.server_port == 8443 and .version_name == "TLS 1.3" and .group_name == "x25519"')"
    [ "$(echo "$hs" | jq -r '.client')" = "$EBPF_NS_IP" ]
    [ "$(echo "$hs" | jq -r '.server')" = "$EBPF_HOST_IP" ]
    [ "$(echo "$hs" | jq -r '.key_exchange')" = "classical" ]
    [ "$(echo "$hs" | jq -r '.posture')" = "classical" ]
    [ "$(echo "$hs" | jq -r '.certificate.state')" = "not_observable" ]
    [ "$(echo "$hs" | jq -r '.cipher_name')" != "null" ]

    _wait_edge "$TLS_PORT" '.classical >= 1' >/dev/null
}

@test "a TLS 1.3 handshake over X25519MLKEM768 is recorded and counted as post-quantum" {
    openssl list -kem-algorithms 2>/dev/null | grep -qi mlkem768 \
        || env_skip "this host's openssl has no ML-KEM"
    _client "$TLS_PORT" -tls1_3 -groups X25519MLKEM768 || {
        cat "${DATA_DIR}/s_client.log" >&3
        false
    }
    local hs
    hs="$(_wait_handshake '.server_port == 8443 and .group_name == "X25519MLKEM768"')"
    [ "$(echo "$hs" | jq -r '.key_exchange')" = "post_quantum_hybrid" ]
    [ "$(echo "$hs" | jq -r '.posture')" = "post_quantum" ]

    local edge
    edge="$(_wait_edge "$TLS_PORT" '.post_quantum >= 1 and .classical >= 1')"
    [ "$(echo "$edge" | jq -r '.clear_text')" = "0" ]
    [ "$(echo "$edge" | jq -r '.legacy_tls')" = "0" ]
}

@test "a TLS 1.2 handshake carries the certificate window the server presented, where it was captured" {
    _client "$TLS_PORT" -tls1_2 || {
        cat "${DATA_DIR}/s_client.log" >&3
        false
    }
    local hs state
    hs="$(_wait_handshake '.server_port == 8443 and .version_name == "TLS 1.2"')"
    state="$(echo "$hs" | jq -r '.certificate.state')"
    case "$state" in
        read)
            local want_after want_before
            want_after="$(date -d "$(openssl x509 -enddate -noout -in "${DATA_DIR}/cert.pem" | cut -d= -f2)" +%s)"
            want_before="$(date -d "$(openssl x509 -startdate -noout -in "${DATA_DIR}/cert.pem" | cut -d= -f2)" +%s)"
            [ "$(echo "$hs" | jq -r '.certificate.not_after')" = "$want_after" ] || {
                echo "# not_after ${hs} against ${want_after}" >&3
                false
            }
            [ "$(echo "$hs" | jq -r '.certificate.not_before')" = "$want_before" ]
            ;;
        not_captured) ;;
        *)
            echo "# a TLS 1.2 certificate reported as ${state}" >&3
            false
            ;;
    esac
}

@test "a handshake below TLS 1.2 counts as legacy TLS on its edge" {
    OPENSSL_CONF=/dev/null _client "$LEGACY_PORT" -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' \
        || soft_skip "the host's openssl negotiates nothing below TLS 1.2"
    local hs
    hs="$(_wait_handshake '.server_port == 8444 and .version_name == "TLS 1.1"')"
    [ "$(echo "$hs" | jq -r '.posture')" = "legacy_tls" ]
    _wait_edge "$LEGACY_PORT" '.legacy_tls >= 1' >/dev/null
}

@test "a clear-text HTTP request counts as clear text, named, and never as TLS" {
    ip netns exec "$EBPF_TEST_NS" curl -s -o /dev/null --max-time 5 \
        "http://${EBPF_HOST_IP}:${HTTP_PORT}/"
    local edge
    edge="$(_wait_edge "$HTTP_PORT" '.clear_text >= 1')"
    [ "$(echo "$edge" | jq -r '.clear_text_protocols.http')" -ge 1 ]
    [ "$(echo "$edge" | jq -r '.post_quantum + .classical + .legacy_tls')" = "0" ]
    [ "$(echo "$edge" | jq -r '.client.address')" = "$EBPF_NS_IP" ]

    local totals
    totals="$(api_get /api/v1/tls/posture | jq -c '.totals')"
    [ "$(echo "$totals" | jq -r '.clear_text')" -ge 1 ]
    [ "$(echo "$totals" | jq -r '.connections')" -ge "$(echo "$totals" | jq -r '.post_quantum + .classical + .legacy_tls + .clear_text')" ]
}
