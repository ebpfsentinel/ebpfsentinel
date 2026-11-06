#!/usr/bin/env bats
# 91-network-executables.bats - only the executables in the list open an
# internet socket on this host, decided in the kernel at socket_create and
# socket_connect.
#
# The suite asserts:
#
#   * In observe, an executable outside the list still gets its socket, and
#     one alert names its pid and the device and inode of its binary, read
#     off the task by the kernel, as what would have been refused.
#   * An executable in the list raises nothing.
#   * In enforce, the same call is refused with a permission error, the
#     alert says refused, and the listed executable and the agent's own API
#     keep working.
#   * With the agent stopped, the refusal is gone: the call goes through.
#
# Requires: root, kernel >= 6.12, the BPF LSM active at boot, jq, python3,
# curl.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool curl

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-execnet-$$"
    mkdir -p "$DATA_DIR"
    create_test_netns

    export PYTHON_BIN CURL_BIN
    PYTHON_BIN="$(readlink -f "$(command -v python3)")"
    CURL_BIN="$(readlink -f "$(command -v curl)")"
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    stop_ebpf_agent 2>/dev/null || true
}

_require_bpf_lsm() {
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
        || env_skip "the BPF LSM is not among this host's security modules"
}

# _start <observe|enforce>
_start() {
    local mode="$1" fixture="${DATA_DIR}/config-${1}.yaml"
    sed -e "s|__EXEC_MODE__|${mode}|" -e "s|__CURL__|${CURL_BIN}|" \
        "${FIXTURE_DIR}/config-ebpf-network-executables.yaml" > "$fixture"
    PREPARED_CONFIG="$(prepare_ebpf_config "$fixture")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
    grep -q "network executables ${mode}" "$AGENT_LOG_FILE" || {
        echo "# the list did not start in ${mode}" >&3
        tail -30 "$AGENT_LOG_FILE" >&3
        false
    }
}

# _python_socket - open and connect an internet socket from the unlisted
# binary; prints "ok <pid>" or "refused <errno> <pid>".
_python_socket() {
    "$PYTHON_BIN" - "$EBPF_NS_IP" <<'PY'
import errno, os, socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((sys.argv[1], 9))
    print("ok", os.getpid())
except OSError as e:
    print("refused", errno.errorcode.get(e.errno, e.errno), os.getpid())
PY
}

_binary_identity() {
    "$PYTHON_BIN" -c 'import os,sys; s=os.stat(sys.argv[1]); print(f"executable dev {s.st_dev} inode {s.st_ino}")' "$PYTHON_BIN"
}

@test "in observe an unlisted executable keeps its socket and is reported by pid and inode" {
    _require_bpf_lsm
    _start observe

    local out pid identity
    out="$(_python_socket)"
    [ "${out%% *}" = "ok" ] || {
        echo "# observe refused the call: ${out}" >&3
        false
    }
    pid="${out##* }"
    identity="$(_binary_identity)"

    run wait_for_alert ".[] | select(.rule_id == \"network-executables\" and (.message | contains(\"pid ${pid} \"))) | .message" 15 1
    [ "$status" -eq 0 ] || {
        echo "# no alert for pid ${pid}" >&3
        api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.rule_id == "network-executables")]' >&3
        false
    }
    assert_contains "$output" "would refuse"
    assert_contains "$output" "$identity"

    # curl is listed: its calls to the agent raise nothing.
    local curl_alerts
    curl_alerts="$(api_get /api/v1/alerts | jq \
        '[.alerts // . | .[] | select(.rule_id == "network-executables")] | length')"
    api_get /healthz >/dev/null
    sleep 2
    [ "$(api_get /api/v1/alerts | jq '[.alerts // . | .[] | select(.rule_id == "network-executables")] | length')" = "$curl_alerts" ]
}

@test "in enforce an unlisted executable is refused, and the listed one and the agent keep working" {
    _require_bpf_lsm
    _start enforce

    local out pid
    out="$(_python_socket)"
    [ "${out%% *}" = "refused" ] || {
        echo "# enforce let the call through: ${out}" >&3
        false
    }
    case "$out" in
        "refused EPERM "* | "refused EACCES "*) ;;
        *)
            echo "# refused with an unexpected error: ${out}" >&3
            false
            ;;
    esac
    pid="${out##* }"

    run wait_for_alert ".[] | select(.rule_id == \"network-executables\" and (.message | contains(\"pid ${pid} \"))) | .message" 15 1
    [ "$status" -eq 0 ]
    assert_contains "$output" "network executables refused"
    assert_contains "$output" "$(_binary_identity)"

    api_get /healthz >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
}

@test "with the agent stopped the refusal is gone" {
    _require_bpf_lsm
    _start enforce
    [ "$(_python_socket | cut -d' ' -f1)" = "refused" ]
    stop_ebpf_agent
    sleep 1
    local out
    out="$(_python_socket)"
    [ "${out%% *}" = "ok" ] || {
        echo "# the call is still refused with the agent gone: ${out}" >&3
        false
    }
}
