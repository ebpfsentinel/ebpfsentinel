#!/usr/bin/env bats
# 84-a-write-is-refused-without-the-bpf-lsm.bats - the write refusal on its
# fanotify route: a permission group on the inodes of the watched paths,
# for the hosts whose kernel has no BPF LSM active.
#
# The suite asserts:
#
#   * The kernel-features report names the route and counts its inode
#     marks: one per directory under a watched directory, one per watched
#     file.
#   * A process creating files under the watched directory is refused at
#     the tenth write-open, and only nine files carry a byte.
#   * Reading the same files again and again is never counted.
#   * Under a system directory, and on a system file, the first write-open
#     by an unexpected executable is refused, the expected writer writes,
#     and a file beside the held one is free.
#   * The alerts and the route's own counters say what was refused.
#   * With the agent stopped, every write goes through: closing the group
#     allows what it held.
#
# Runs on any host: the route is named in the configuration rather than
# chosen for want of the BPF LSM.

load '../lib/helpers'
load '../lib/ebpf_helpers'

THRESHOLD=10
ATTEMPTS=20

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 84 writes its files on the agent's host (local lane only)"
    fi

    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-fanotify-refusal-$$"
    # Every directory the tests write in exists before the agent walks the
    # set: a directory created later is marked at the next refresh.
    mkdir -p "${DATA_DIR}/watched/run" "${DATA_DIR}/watched/read" \
        "${DATA_DIR}/outside" "${DATA_DIR}/system" "${DATA_DIR}/bin"
    install -m 0755 "$(command -v tee)" "${DATA_DIR}/bin/expected-writer"
    echo original >"${DATA_DIR}/held.conf"
    for n in 0 1 2 3 4; do echo "kept" >"${DATA_DIR}/watched/read/doc${n}.txt"; done

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-fanotify-write-refusal.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_enforcing || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the fanotify route never reported itself in force" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-fanotify-refusal-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_wait_enforcing() {
    local attempt=0 body
    while [ "${attempt}" -lt 30 ]; do
        body="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null)" || body=""
        [ "$(jq -r '.write_refusal.route' <<<"${body}" 2>/dev/null)" = "fanotify" ] &&
            [ "$(jq -r '.write_refusal.attached' <<<"${body}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.write_refusal.enforcing' <<<"${body}" 2>/dev/null)" = "true" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _write <dir> <count> - one process creating <count> files under <dir>;
# prints one line per open, `ok` or the errno.
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
PY
}

# _read <dir> <rounds> - one process reading every file under <dir>
# <rounds> times; prints how many reads failed.
_read() {
    python3 - "$1" "$2" <<'PY'
import os, sys
root, rounds = sys.argv[1], int(sys.argv[2])
failed = 0
for _ in range(rounds):
    for name in os.listdir(root):
        try:
            with open(os.path.join(root, name)) as f:
                f.read()
        except OSError:
            failed += 1
print(failed)
PY
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the report names the fanotify route and counts its inode marks" {
    local body
    body="$(api_get /api/v1/ebpf/kernel-features)"
    [ "$(jq -r '.write_refusal.directories' <<<"${body}")" = "3" ]
    [ "$(jq -r '.write_refusal.system_paths' <<<"${body}")" = "2" ]
    [ "$(jq -r '.write_refusal.expected_writers' <<<"${body}")" = "1" ]
    # watched, watched/run, watched/read, system, held.conf
    [ "$(jq -r '.write_refusal.marks' <<<"${body}")" = "5" ]
}

@test "a writer past the threshold is refused at the tenth write-open and nine files carry a byte" {
    local dir="${DATA_DIR}/watched/run"
    run _write "${dir}" "${ATTEMPTS}"
    [ "$status" -eq 0 ]
    [ "$(grep -cx ok <<<"${output}")" -eq $((THRESHOLD - 1)) ]
    [ "$(grep -cx EPERM <<<"${output}")" -eq $((ATTEMPTS - THRESHOLD + 1)) ]
    [ "$(sed -n "${THRESHOLD}p" <<<"${output}")" = "EPERM" ]
    [ "$(find "${dir}" -type f -size +0 | wc -l)" -eq $((THRESHOLD - 1)) ]
}

@test "reading the same files again and again is never counted" {
    run _read "${DATA_DIR}/watched/read" 10
    [ "$status" -eq 0 ]
    [ "${output}" = "0" ]
}

@test "writes outside the watched paths are never counted" {
    run _write "${DATA_DIR}/outside" "${ATTEMPTS}"
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
}

@test "under a system path the first write by an unexpected executable is refused" {
    run _write "${DATA_DIR}/system" 3
    [ "$(head -n 1 <<<"${output}")" = "EPERM" ]
    [ "$(grep -cx ok <<<"${output}")" -eq 0 ]
    run tee "${DATA_DIR}/held.conf" <<<"tampered"
    [ "$status" -ne 0 ]
    [ "$(cat "${DATA_DIR}/held.conf")" = "original" ]
    run cat "${DATA_DIR}/held.conf"
    [ "$status" -eq 0 ]
}

@test "the expected writer writes under a system path, and a file beside the held one is free" {
    run "${DATA_DIR}/bin/expected-writer" "${DATA_DIR}/system/unit.conf" <<<"expected"
    [ "$status" -eq 0 ]
    [ "$(cat "${DATA_DIR}/system/unit.conf")" = "expected" ]
    run "${DATA_DIR}/bin/expected-writer" "${DATA_DIR}/held.conf" <<<"updated"
    [ "$status" -eq 0 ]
    [ "$(cat "${DATA_DIR}/held.conf")" = "updated" ]
    run tee "${DATA_DIR}/beside.conf" <<<"free"
    [ "$status" -eq 0 ]
}

@test "the alerts and the route's counters say what was refused" {
    local alert
    alert="$(wait_for_alert "[.[] | select(.rule_id == \"write-refusal\" and (.message | contains(\"${DATA_DIR}/watched\")))] | first" 30 1)"
    [ -n "${alert}" ]
    jq -e '.message | contains("opening for writing `doc9.txt`")' <<<"${alert}"
    alert="$(wait_for_alert "[.[] | select(.rule_id == \"write-refusal\" and (.message | contains(\"under the system path\")))] | first" 30 1)"
    [ -n "${alert}" ]
    local refused expected
    refused="$(wait_for_metric ebpfsentinel_packets_total 1 30 '{interface="WRITE_REFUSAL_FALLBACK",action="refused"}')"
    [ "${refused%.*}" -ge $((ATTEMPTS - THRESHOLD + 1)) ]
    expected="$(wait_for_metric ebpfsentinel_packets_total 1 30 '{interface="WRITE_REFUSAL_FALLBACK",action="expected"}')"
    [ "${expected%.*}" -ge 2 ]
}

@test "with the agent stopped every write goes through: closing the group fails open" {
    stop_ebpf_agent
    local dir="${DATA_DIR}/watched/run"
    rm -f "${dir}"/doc*.txt
    run _write "${dir}" "${ATTEMPTS}"
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
    run tee "${DATA_DIR}/held.conf" <<<"after"
    [ "$status" -eq 0 ]
}
