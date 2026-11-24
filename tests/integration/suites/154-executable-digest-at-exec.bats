#!/usr/bin/env bats
# 154-executable-digest-at-exec.bats - the SHA-256 of what a process runs,
# taken by the kernel when it executes and dropped when the file is
# rewritten.
#
# The suite asserts:
#
#   * The kernel-features report says the kernel digests executables, on a
#     host with the BPF LSM and IMA among its security modules.
#   * An executed copy of python3 is digested at exec, counted as computed,
#     and the process table carries the same SHA-256 sha256sum reads off the
#     file.
#   * A second exec of the unchanged file reuses the digest rather than
#     reading the file again.
#   * A write-open of the file drops the digest, and the next exec carries
#     the digest of the new bytes, never the old one.
#
# Requires: root, kernel >= 6.18, the BPF LSM and IMA active at boot, jq,
# python3, sha256sum.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 18
    require_tool jq
    require_tool python3
    require_tool sha256sum

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 154 runs its processes beside the agent (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-exec-digest-$$"
    mkdir -p "$DATA_DIR"
    create_test_netns

    # A copy of python3 run with the system's library, so the suite owns
    # the file it rewrites.
    export SYS_PYTHON PYTHONHOME_DIR PYCOPY
    SYS_PYTHON="$(readlink -f "$(command -v python3)")"
    PYTHONHOME_DIR="$("$SYS_PYTHON" -c 'import sys; print(sys.base_prefix)')"
    PYCOPY="${DATA_DIR}/digest-python"
    cp "$SYS_PYTHON" "$PYCOPY"
    chmod 0755 "$PYCOPY"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-executable-digest.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_require_bpf_lsm_and_ima() {
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
        || lane_skip bpf-lsm "the BPF LSM is not among this host's security modules"
    grep -qw ima /sys/kernel/security/lsm 2>/dev/null \
        || env_skip "IMA is not among this host's security modules"
}

# _counter <action> - the kernel's count for one slot of the object.
_counter() {
    scrape_metrics \
        | awk -v want="ebpfsentinel_packets_total{interface=\"EXEC_DIGEST_METRICS\",action=\"$1\"}" \
            'index($0, want) == 1 { v = $NF } END { print v + 0 }'
}

# _wait_counter_above <action> <value> - the count passed <value> within
# fifteen seconds, the agent reading the kernel's counters on its interval.
_wait_counter_above() {
    local i
    for i in $(seq 1 30); do
        [ "$(_counter "$1")" -gt "$2" ] && return 0
        sleep 0.5
    done
    echo "# ${1} stayed at $(_counter "$1")" >&3
    return 1
}

# _run_copy - start the copy for long enough to be read; prints its pid.
_run_copy() {
    PYTHONHOME="$PYTHONHOME_DIR" "$PYCOPY" -c 'import time; time.sleep(20)' >/dev/null 2>&1 &
    echo $!
}

# _table_hash <pid> - the digest the process table holds for <pid>.
_table_hash() {
    local i hash=""
    for i in $(seq 1 20); do
        hash="$(api_get "/api/v1/processes/$1" 2>/dev/null | jq -r '.identity.exe_hash // empty')"
        [ -n "$hash" ] && break
        sleep 0.5
    done
    echo "$hash"
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the kernel-features report says the kernel digests executables" {
    _require_bpf_lsm_and_ima
    local entry
    entry="$(api_get /api/v1/ebpf/kernel-features | jq -c '.capabilities[] | select(.id == "executable_digest")')"
    [ -n "$entry" ]
    [ "$(echo "$entry" | jq -r '.active')" = "true" ] || {
        echo "# ${entry}" >&3
        false
    }
}

@test "an executed copy is digested by the kernel and the table carries the same SHA-256" {
    _require_bpf_lsm_and_ima
    local before pid want got
    before="$(_counter computed)"
    pid="$(_run_copy)"
    _wait_counter_above computed "$before"
    want="sha256:$(sha256sum "$PYCOPY" | cut -d' ' -f1)"
    got="$(_table_hash "$pid")"
    kill "$pid" 2>/dev/null || true
    [ "$got" = "$want" ] || {
        echo "# pid ${pid}: table says '${got}', the file is ${want}" >&3
        false
    }
}

@test "a second exec of the unchanged file reuses the kernel's digest" {
    _require_bpf_lsm_and_ima
    local before pid
    before="$(_counter reused)"
    pid="$(_run_copy)"
    _wait_counter_above reused "$before"
    kill "$pid" 2>/dev/null || true
}

@test "a rewrite drops the digest and the next exec carries the new bytes" {
    _require_bpf_lsm_and_ima
    local dropped computed pid want got
    dropped="$(_counter invalidated)"
    computed="$(_counter computed)"
    printf 'ebpfsentinel-test-mark' >> "$PYCOPY"
    _wait_counter_above invalidated "$dropped"

    pid="$(_run_copy)"
    _wait_counter_above computed "$computed"
    want="sha256:$(sha256sum "$PYCOPY" | cut -d' ' -f1)"
    got="$(_table_hash "$pid")"
    kill "$pid" 2>/dev/null || true
    [ "$got" = "$want" ] || {
        echo "# pid ${pid}: table says '${got}', the rewritten file is ${want}" >&3
        false
    }
}
