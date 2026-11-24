#!/usr/bin/env bats
# 94-file-watch.bats - a change to a watched path, or to the agent's own
# configuration, is an alert naming the process that made it.
#
# The suite asserts:
#
#   * Rewriting a file under the watched directory raises
#     watched-path-changed naming the writer's pid and the content drift.
#   * A file created under the watched directory raises
#     watched-path-appeared naming the process that put it there.
#   * A mode change raises watched-path-changed with the mode drift.
#   * A file changed outside every watched path raises nothing.
#   * Another process changing the agent's configuration raises
#     agent-configuration-changed naming it.
#   * A rename under the watched directory matches a host rule on its
#     previous name, and the alert carries the process that moved the file
#     and the shell above it.
#
# Requires: root, kernel >= 6.18, jq.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 18
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 94 writes its files on the agent's host (local lane only)"
    fi

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-file-watch-$$"
    mkdir -p "${DATA_DIR}/watched" "${DATA_DIR}/elsewhere"
    echo "first" > "${DATA_DIR}/watched/settings.conf"
    echo "first" > "${DATA_DIR}/watched/mode.conf"
    echo "first" > "${DATA_DIR}/elsewhere/notes.txt"
    echo "first" > "${DATA_DIR}/watched/report.txt"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-file-watch.yaml" \
        "${DATA_DIR}/agent.yaml")"
    export PREPARED_CONFIG
    cat >> "$PREPARED_CONFIG" <<EOF

host_rules:
  rules:
    - id: fw-renamed-report
      description: the suite's report moved to another name
      severity: high
      when:
        file.renames:
          previous_path: [${DATA_DIR}/watched/report.txt]
      then: [alert]
      mode: enforce
EOF
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    local attempt=0
    while ! grep -q "file watch running" "$AGENT_LOG_FILE" && [ "$attempt" -lt 30 ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    grep -q "file watch running" "$AGENT_LOG_FILE" || {
        tail -30 "$AGENT_LOG_FILE" >&2
        return 1
    }
    # The baselines are read once the watch is open.
    sleep 3
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-file-watch-$$}"
}

# _writer <shell line> - run the line in a shell that stays a moment after
# it, so the writer is still there to be named; prints the shell's pid.
_writer() {
    bash -c "$1; sleep 3" >/dev/null 2>&1 &
    echo $!
}

_alert_for() {
    wait_for_alert ".[] | select(.rule_id == \"$1\" and (.message | contains(\"$2\")))" "${3:-20}" 1
}

_dump() {
    api_get /api/v1/alerts | jq -c '[.alerts // . | .[] | select(.rule_id | startswith("watched-path") or startswith("agent-"))]' >&3
}

@test "rewriting a watched file names the writer and the content drift" {
    local file="${DATA_DIR}/watched/settings.conf" pid
    pid="$(_writer "echo second > ${file}")"
    run _alert_for watched-path-changed "$file"
    [ "$status" -eq 0 ] || { _dump; false; }
    echo "$output" | jq -e '.component == "file_integrity"' >/dev/null
    local message
    message="$(echo "$output" | jq -r '.message')"
    assert_contains "$message" "was changed by process ${pid}"
    assert_contains "$message" "content"
    assert_contains "$message" "watched through configuration"
}

@test "a file created under the watched directory names the process that put it there" {
    local file="${DATA_DIR}/watched/dropped.sh" pid
    pid="$(_writer "echo payload > ${file}")"
    run _alert_for watched-path-appeared "$file"
    [ "$status" -eq 0 ] || { _dump; false; }
    assert_contains "$(echo "$output" | jq -r '.message')" "put there by process ${pid}"
}

@test "a mode change on a watched file is reported as mode drift" {
    local file="${DATA_DIR}/watched/mode.conf"
    _writer "chmod 0700 ${file}" >/dev/null
    run _alert_for watched-path-changed "$file"
    [ "$status" -eq 0 ] || { _dump; false; }
    assert_contains "$(echo "$output" | jq -r '.message')" "mode"
}

@test "a file outside every watched path raises nothing" {
    local file="${DATA_DIR}/elsewhere/notes.txt"
    _writer "echo second > ${file}" >/dev/null
    sleep 6
    [ "$(api_get /api/v1/alerts | jq --arg f "$file" \
        '[.alerts // . | .[] | select(.message | contains($f))] | length')" = "0" ]
}

@test "another process changing the agent's configuration is named" {
    local pid
    pid="$(_writer "echo '# touched by the suite' >> ${PREPARED_CONFIG}")"
    run _alert_for agent-configuration-changed "$PREPARED_CONFIG"
    [ "$status" -eq 0 ] || { _dump; false; }
    echo "$output" | jq -e '.component == "agent_files"' >/dev/null
    assert_contains "$(echo "$output" | jq -r '.message')" "was changed by process ${pid}"
}

@test "a rename matches its previous name and names the mover and the shell above it" {
    local shell
    shell="$(_writer "mv ${DATA_DIR}/watched/report.txt ${DATA_DIR}/watched/report.txt.locked")"
    run wait_for_alert '[.[] | select(.rule_id == "fw-renamed-report")] | first' 20 1
    [ "$status" -eq 0 ] || { _dump; false; }
    echo "$output" | jq -c '{rule_id, message, workload}'
    local mover
    mover="$(echo "$output" | jq -r '.workload.pid // empty')"
    [ -n "$mover" ]
    [ "$mover" != "$shell" ]
    [ "$(echo "$output" | jq -r '.workload.ancestry.ancestors[0].pid // empty')" = "$shell" ]
}

@test "the file watch counters say what it covered, saw and found drifted" {
    local metrics
    metrics="$(scrape_metrics)"
    _at_least() {
        echo "$metrics" | awk -v s="$1" -v n="$2" 'index($0, s) == 1 && $NF >= n { ok = 1 } END { exit !ok }' || {
            echo "no ${1} at ${2} or more" >&2
            echo "$metrics" | grep -E '^ebpfsentinel_file_' >&2
            return 1
        }
    }
    # The watched directory sits on a filesystem the watch marked.
    _at_least 'ebpfsentinel_file_watch_filesystems ' 1
    _at_least 'ebpfsentinel_file_watch_filesystems_refused ' 0
    # The files the suite rewrote and created were seen as such.
    _at_least 'ebpfsentinel_file_changes_total{kind="written"}' 1
    _at_least 'ebpfsentinel_file_changes_total{kind="created"}' 1
    # The baselines taken at start-up named the content and the mode drift.
    _at_least 'ebpfsentinel_file_baselines ' 1
    _at_least 'ebpfsentinel_file_drifts_total{what="content"}' 1
    _at_least 'ebpfsentinel_file_drifts_total{what="mode"}' 1
    # A handful of writes neither overflows the kernel's queue nor runs out
    # of room for a baseline.
    echo "$metrics" | grep -qx 'ebpfsentinel_file_change_overflows_total 0'
    echo "$metrics" | grep -qx 'ebpfsentinel_file_baselines_refused_total 0'
}
