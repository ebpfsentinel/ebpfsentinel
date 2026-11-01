#!/usr/bin/env bats
# 83-a-write-is-refused.bats - the kernel refuses a writer's write-opens
# under a watched directory once it has made as many as the threshold allows
# inside the window, before a byte of the refused one is written.
#
# The suite asserts:
#
#   * A process creating files one after the other under the watched
#     directory gets EACCES at the tenth, and only nine files carry a byte:
#     a refused creation leaves its name behind, empty, because the inode
#     exists before the open is decided.
#   * Once refused, truncating a file it had written is refused too.
#   * Another process is counted on its own and is not refused.
#   * Writes outside the watched directory are never counted.
#   * One alert names the writer and the directory, and the counters say
#     what was refused.
#   * With the agent stopped, the same run writes every file: the refusal
#     fails open.
#
# Needs the BPF LSM active at boot (`bpf` in /sys/kernel/security/lsm).

load '../lib/helpers'
load '../lib/ebpf_helpers'

THRESHOLD=10
ATTEMPTS=20

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_root

    if ! tr ',' '\n' </sys/kernel/security/lsm 2>/dev/null | grep -qx bpf; then
        env_skip "the BPF LSM is not active on this host (lsm=bpf at boot)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 83 writes its files on the agent's host (local lane only)"
    fi

    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-write-refusal-$$"
    mkdir -p "${DATA_DIR}/watched" "${DATA_DIR}/outside"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-write-refusal.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_enforcing || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the write refusal never reported itself in force" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-write-refusal-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_wait_enforcing() {
    local attempt=0 body
    while [ "${attempt}" -lt 30 ]; do
        body="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null)" || body=""
        [ "$(jq -r '.write_refusal.attached' <<<"${body}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.write_refusal.enforcing' <<<"${body}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.write_refusal.directories' <<<"${body}" 2>/dev/null)" = "1" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _write <dir> <count> - one process creating <count> files under <dir>,
# then truncating the first; prints one line per call, `ok` or the errno.
_write() {
    python3 - "$1" "$2" <<'PY'
import errno, os, sys
root, count = sys.argv[1], int(sys.argv[2])
for n in range(count):
    try:
        with open(os.path.join(root, f"doc{n}.txt"), "w") as f:
            f.write("payload\n")
        print("ok")
    except OSError as e:
        print(errno.errorcode[e.errno])
try:
    os.truncate(os.path.join(root, "doc0.txt"), 0)
    print("truncate ok")
except OSError as e:
    print("truncate " + errno.errorcode[e.errno])
PY
}

# ── Tests ───────────────────────────────────────────────────────────

@test "a writer past the threshold is refused at the tenth write-open and nine files carry a byte" {
    local dir="${DATA_DIR}/watched/run"
    mkdir -p "${dir}"
    run _write "${dir}" "${ATTEMPTS}"
    [ "$status" -eq 0 ]
    [ "$(grep -cx ok <<<"${output}")" -eq $((THRESHOLD - 1)) ]
    [ "$(grep -cx EACCES <<<"${output}")" -eq $((ATTEMPTS - THRESHOLD + 1)) ]
    # The tenth line is the first refusal: nothing before it was refused.
    [ "$(sed -n "${THRESHOLD}p" <<<"${output}")" = "EACCES" ]
    [ "$(find "${dir}" -type f -size +0 | wc -l)" -eq $((THRESHOLD - 1)) ]
    [ "$(find "${dir}" -type f -empty | wc -l)" -eq $((ATTEMPTS - THRESHOLD + 1)) ]
}

@test "once refused, truncating a file it wrote is refused too" {
    local dir="${DATA_DIR}/watched/trunc"
    mkdir -p "${dir}"
    run _write "${dir}" "${ATTEMPTS}"
    [ "$(tail -n 1 <<<"${output}")" = "truncate EACCES" ]
    [ "$(cat "${dir}/doc0.txt")" = "payload" ]
}

@test "a process under its threshold writes every file it opens" {
    local dir="${DATA_DIR}/watched/small"
    mkdir -p "${dir}"
    run _write "${dir}" $((THRESHOLD - 2))
    [ "$(grep -cx ok <<<"${output}")" -eq $((THRESHOLD - 2)) ]
    [ "$(tail -n 1 <<<"${output}")" = "truncate ok" ]
}

@test "writes outside the watched directory are never counted" {
    run _write "${DATA_DIR}/outside" "${ATTEMPTS}"
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
    [ "$(tail -n 1 <<<"${output}")" = "truncate ok" ]
}

@test "one alert names the writer and the directory, and the counters say what was refused" {
    local alert
    alert="$(wait_for_alert "[.[] | select(.rule_id == \"write-refusal\" and (.message | contains(\"${DATA_DIR}/watched\")))] | first" 30 1)"
    [ -n "${alert}" ]
    jq -e '.message | startswith("write refusal refused pid ")' <<<"${alert}"
    jq -e '.message | contains("opening for writing `doc9.txt`")' <<<"${alert}"
    local refused
    refused="$(wait_for_metric ebpfsentinel_packets_total 1 30 '{interface="WRITE_REFUSAL_METRICS",action="refused"}')"
    [ "${refused%.*}" -ge $((ATTEMPTS - THRESHOLD + 1)) ]
}

@test "with the agent stopped the same run writes every file: the refusal fails open" {
    stop_ebpf_agent
    local dir="${DATA_DIR}/watched/after"
    mkdir -p "${dir}"
    run _write "${dir}" "${ATTEMPTS}"
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
    [ "$(tail -n 1 <<<"${output}")" = "truncate ok" ]
}
