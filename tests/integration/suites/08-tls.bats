#!/usr/bin/env bats
# 08-tls.bats — TLS termination tests (HTTPS and gRPC over TLS)

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    export CERT_DIR="${CERT_DIR:-/tmp/ebpfsentinel-test-certs}"
    mkdir -p "$DATA_DIR"

    # Generate certs if not present
    if [ ! -f "${CERT_DIR}/server.pem" ]; then
        bash "${SCRIPT_DIR}/generate-certs.sh" --out-dir "$CERT_DIR"
    fi

    # In 2VM mode, copy certs to agent VM so it can use them
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo mkdir -p "$CERT_DIR" 2>/dev/null || true
        _agent_ssh_sudo chown vagrant:vagrant "$CERT_DIR" 2>/dev/null || true
        for f in server.pem server-key.pem ca.pem; do
            [ -f "${CERT_DIR}/$f" ] && _agent_scp "${CERT_DIR}/$f" "${CERT_DIR}/$f"
        done
    fi

    # Prepare TLS config from template
    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-tls-$$.yaml"
    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__CERT_PATH__|${CERT_DIR}/server.pem|g" \
        -e "s|__KEY_PATH__|${CERT_DIR}/server-key.pem|g" \
        "${FIXTURE_DIR}/config-tls.yaml" > "$PREPARED_CONFIG"

    # Override ports for TLS suite
    export AGENT_HTTP_PORT="${AGENT_TLS_PORT}"
    export BASE_URL="https://${AGENT_HOST}:${AGENT_TLS_PORT}"
    export TLS_URL="https://${AGENT_HOST}:${AGENT_TLS_PORT}"

    # Kill stale agent from previous suites
    stop_agent 2>/dev/null || true

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        # Must stop stale agent, start new one, but skip the HTTP health check
        # because this agent listens on TLS only.
        stop_agent 2>/dev/null || true
        _agent_ssh_sudo mkdir -p "${_REMOTE_CONFIG_DIR}" "${_REMOTE_DATA_DIR}" 2>/dev/null || true
        _agent_ssh_sudo chown vagrant:vagrant "${_REMOTE_CONFIG_DIR}" "${_REMOTE_DATA_DIR}" 2>/dev/null || true
        local rewritten="/tmp/ebpfsentinel-2vm-tls-$$.yaml"
        sed -e "s|/tmp/ebpfsentinel-test-data[^/]*|${_REMOTE_DATA_DIR}|g" \
            "$PREPARED_CONFIG" > "$rewritten"
        local remote_config="${_REMOTE_CONFIG_DIR}/$(basename "$PREPARED_CONFIG")"
        _agent_scp "$rewritten" "$remote_config"
        rm -f "$rewritten"
        _agent_ssh_sudo bash -c \
            "'nohup /usr/local/bin/ebpfsentinel-agent --config ${remote_config} >${_REMOTE_LOG_FILE} 2>&1 & echo \$! > ${_REMOTE_PID_FILE}'"
        sleep 0.5
        local remote_pid
        remote_pid="$(_agent_ssh cat "${_REMOTE_PID_FILE}" 2>/dev/null)" || true
        AGENT_PID="$remote_pid"
        echo "$AGENT_PID" > "$AGENT_PID_FILE"
        # Wait for TLS health check
        wait_for_agent_tls "${TLS_URL}/healthz" "${CERT_DIR}/ca.pem" || {
            echo "TLS agent failed health check on ${AGENT_HOST}. Remote log:" >&2
            _agent_ssh cat "${_REMOTE_LOG_FILE}" 2>&1 | tail -20 >&2
            return 1
        }
    else
        _kill_port_holders "${AGENT_TLS_PORT}" "${AGENT_GRPC_PORT}"

        # Wait for ports to be fully freed
        local port_wait=0
        while { ss -tlnp 2>/dev/null | grep -qE ":(${AGENT_TLS_PORT}|${AGENT_GRPC_PORT}) "; } && [ "$port_wait" -lt 10 ]; do
            sleep 0.3
            port_wait=$((port_wait + 1))
        done

        "$AGENT_BIN" --config "$PREPARED_CONFIG" \
            >"$AGENT_LOG_FILE" 2>&1 &
        AGENT_PID=$!
        echo "$AGENT_PID" > "$AGENT_PID_FILE"

        # Brief pause then verify the process is still alive
        sleep 0.3
        if ! kill -0 "$AGENT_PID" 2>/dev/null; then
            echo "TLS agent process exited immediately. Log tail:" >&2
            tail -20 "$AGENT_LOG_FILE" >&2
            return 1
        fi

        # Wait for agent to be healthy over TLS
        wait_for_agent_tls "${TLS_URL}/healthz" "${CERT_DIR}/ca.pem" || {
            echo "TLS agent failed to start. Log tail:" >&2
            tail -20 "$AGENT_LOG_FILE" >&2
            return 1
        }
    fi
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# ── Tests ──────────────────────────────────────────────────────────

@test "HTTPS healthz with CA cert returns 200" {
    local status_code
    status_code="$(curl -s -o /dev/null --max-time "$HTTP_TIMEOUT" -w '%{http_code}' \
        --cacert "${CERT_DIR}/ca.pem" "${TLS_URL}/healthz")"
    assert_http_status "200" "$status_code"
}

@test "HTTPS rejects without CA cert (self-signed)" {
    # curl should fail because the server cert is self-signed
    local exit_code=0
    curl -sf --max-time "$HTTP_TIMEOUT" "${TLS_URL}/healthz" 2>/dev/null || exit_code=$?
    [ "$exit_code" -ne 0 ]
}

@test "HTTPS API works with CA cert" {
    local body
    body="$(curl -s --max-time "$HTTP_TIMEOUT" \
        --cacert "${CERT_DIR}/ca.pem" "${TLS_URL}/api/v1/agent/status")"
    local version
    version="$(echo "$body" | jq -r '.version' 2>/dev/null)" || true
    [ -n "$version" ] && [ "$version" != "null" ]
}

@test "gRPC over TLS with CA cert returns SERVING" {
    command -v grpcurl &>/dev/null || skip "grpcurl not installed"

    local output
    output="$(grpcurl -cacert "${CERT_DIR}/ca.pem" \
        -import-path "${FIXTURE_DIR}" -proto health.proto \
        "${AGENT_HOST}:${AGENT_GRPC_PORT}" grpc.health.v1.Health/Check 2>&1)" || true
    assert_contains "$output" "SERVING"
}

@test "gRPC without CA cert fails connection" {
    command -v grpcurl &>/dev/null || skip "grpcurl not installed"

    local exit_code=0
    grpcurl "${AGENT_HOST}:${AGENT_GRPC_PORT}" \
        grpc.health.v1.Health/Check 2>/dev/null || exit_code=$?
    [ "$exit_code" -ne 0 ]
}
