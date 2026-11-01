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
#   * Under a system directory, and on a system file, the first write-open
#     by an executable that is not expected there is refused, while the
#     expected writer writes, and a file beside the held one is not held.
#   * The refusal under a system path names it as one, and the counters
#     count the expected writer's writes as expected.
#   * With the agent stopped, the same run writes every file: the refusal
#     fails open.
#   * Killed with SIGKILL while a writer is working, the agent leaves the
#     node writable at once: no open hangs and nothing more is refused.
#   * In shadow every write goes through, no alert is raised, and the
#     reading at /api/v1/host-rules/write-refusal counts the writer that
#     would have been refused under its workload, with when it started
#     counting.
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
    mkdir -p "${DATA_DIR}/watched" "${DATA_DIR}/outside" "${DATA_DIR}/system" "${DATA_DIR}/bin"
    # The expected writer is a copy, so it is a file of its own and the
    # original stays an executable nobody expects.
    install -m 0755 "$(command -v tee)" "${DATA_DIR}/bin/expected-writer"
    echo original >"${DATA_DIR}/held.conf"

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

# _wait_enforcing [false] - the refusal reports itself attached and in
# force, or with `false` attached and counting in shadow.
_wait_enforcing() {
    local attempt=0 body
    while [ "${attempt}" -lt 30 ]; do
        body="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null)" || body=""
        [ "$(jq -r '.write_refusal.attached' <<<"${body}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.write_refusal.enforcing' <<<"${body}" 2>/dev/null)" = "${1:-true}" ] &&
            [ "$(jq -r '.write_refusal.directories' <<<"${body}" 2>/dev/null)" = "3" ] &&
            [ "$(jq -r '.write_refusal.system_paths' <<<"${body}" 2>/dev/null)" = "2" ] &&
            [ "$(jq -r '.write_refusal.expected_writers' <<<"${body}" 2>/dev/null)" = "1" ] && return 0
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

# _kill_agent_while_writing <dir> - SIGKILL the agent's whole group while a
# second writer is creating files under <dir>, and wait for it to be gone.
# Prints the background writer's exit status: 124 means an open hung.
_kill_agent_while_writing() {
    local dir="$1" pid bg n=0
    mkdir -p "${dir}"
    timeout 15 bash -c 'for n in $(seq 0 199); do echo x >"$1/bg${n}.txt" 2>/dev/null; sleep 0.01; done; exit 0' _ "${dir}" &
    bg=$!
    sleep 0.3
    pid="$(cat "${AGENT_PID_FILE}")"
    kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "${pid}"
    while kill -0 "${pid}" 2>/dev/null && [ "${n}" -lt 50 ]; do
        sleep 0.1
        n=$((n + 1))
    done
    wait "${bg}"
    echo "$?"
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

@test "under a system path the first write by an unexpected executable is refused" {
    run _write "${DATA_DIR}/system" 3
    [ "$(head -n 1 <<<"${output}")" = "EACCES" ]
    [ "$(grep -cx ok <<<"${output}")" -eq 0 ]
    run tee "${DATA_DIR}/held.conf" <<<"tampered"
    [ "$status" -ne 0 ]
    [ "$(cat "${DATA_DIR}/held.conf")" = "original" ]
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

@test "a refusal under a system path says so, and the expected writes are counted" {
    local alert
    alert="$(wait_for_alert "[.[] | select(.rule_id == \"write-refusal\" and (.message | contains(\"under the system path\")))] | first" 30 1)"
    [ -n "${alert}" ]
    jq -e '.message | contains("is not one expected to write there")' <<<"${alert}"
    local expected
    expected="$(wait_for_metric ebpfsentinel_packets_total 1 30 '{interface="WRITE_REFUSAL_METRICS",action="expected"}')"
    [ "${expected%.*}" -ge 2 ]
}

@test "with the agent stopped the same run writes every file: the refusal fails open" {
    stop_ebpf_agent
    local dir="${DATA_DIR}/watched/after"
    mkdir -p "${dir}"
    run _write "${dir}" "${ATTEMPTS}"
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
    [ "$(tail -n 1 <<<"${output}")" = "truncate ok" ]
    run tee "${DATA_DIR}/held.conf" <<<"after"
    [ "$status" -eq 0 ]
}

@test "killed with SIGKILL mid-enforcement, the agent leaves the node writable at once" {
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30
    _wait_enforcing
    # In force: the same run is refused before the kill.
    local before="${DATA_DIR}/watched/run/before"
    mkdir -p "${before}"
    run _write "${before}" "${ATTEMPTS}"
    grep -qx EACCES <<<"${output}"
    run tee "${DATA_DIR}/held.conf" <<<"refused"
    [ "$status" -ne 0 ]

    run _kill_agent_while_writing "${DATA_DIR}/watched/run/during"
    [ "$(tail -n 1 <<<"${output}")" = "0" ]
    ! kill -0 "$(cat "${AGENT_PID_FILE}")" 2>/dev/null

    local after="${DATA_DIR}/watched/run/after"
    mkdir -p "${after}"
    run timeout 10 bash -c "$(declare -f _write); _write '${after}' ${ATTEMPTS}"
    [ "$status" -eq 0 ]
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
    run timeout 5 tee "${DATA_DIR}/held.conf" <<<"after the kill"
    [ "$status" -eq 0 ]
}

@test "in shadow every write goes through, nothing is raised and the reading counts what would be refused" {
    stop_ebpf_agent 2>/dev/null || true
    local shadow_config="${PREPARED_CONFIG}.shadow"
    sed 's/^    mode: enforce$/    mode: shadow/' "${PREPARED_CONFIG}" >"${shadow_config}"
    grep -qx '    mode: shadow' "${shadow_config}"
    start_ebpf_agent "${shadow_config}"
    wait_for_ebpf_loaded 30
    _wait_enforcing false
    # The alerts the enforcing runs above raised are kept across restarts, so
    # what this run raises is the difference.
    local before
    before="$(api_get /api/v1/alerts | jq '[(.alerts // .)[] | select(.rule_id == "write-refusal")] | length')"

    local dir="${DATA_DIR}/watched/run/shadow"
    mkdir -p "${dir}"
    run _write "${dir}" "${ATTEMPTS}"
    ! grep -qx EACCES <<<"${output}"
    [ "$(grep -cx ok <<<"${output}")" -eq "${ATTEMPTS}" ]
    [ "$(tail -n 1 <<<"${output}")" = "truncate ok" ]

    local body="" attempt=0
    while [ "${attempt}" -lt 30 ]; do
        body="$(api_get /api/v1/host-rules/write-refusal 2>/dev/null)" || body=""
        [ "$(jq -r '.shadow.events // 0' <<<"${body}" 2>/dev/null)" -ge 1 ] && break
        sleep 0.5
        attempt=$((attempt + 1))
    done
    jq -e '.enabled == true and .mode == "shadow" and .counting_since_ns > 0' <<<"${body}"
    # One count per writer and window, as one alert would have been.
    jq -e '.shadow.events >= 1' <<<"${body}"
    jq -e '.shadow.workloads | length > 0' <<<"${body}"
    jq -e '.recent | last | .message | contains("would refuse")' <<<"${body}"
    local raised
    raised="$(api_get /api/v1/alerts | jq '[(.alerts // .)[] | select(.rule_id == "write-refusal")] | length')"
    [ "${raised}" -eq "${before}" ]
    rm -f "${shadow_config}"
}
