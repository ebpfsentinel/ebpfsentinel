#!/usr/bin/env bats
# 80-the-surface-of-this-host.bats - what is installed on this host, in its
# own root and in every other one.
#
# The host's dpkg database is read by the agent and by dpkg itself, and the
# two must agree. Two more roots are made with chroot: one carrying an Alpine
# database, which must be read and named as a root no runtime names, and one
# whose database is a symbolic link climbing out of the root towards the
# host's own dpkg status, which must resolve inside the root and find nothing.
#
# The suite asserts:
#
#   * The host's installed packages are the ones dpkg-query reports, count and
#     version alike.
#   * A chroot's Alpine database is read, under kind `other`.
#   * A link climbing out of a root does not reach the host's files.
#   * No field of the answer names a vulnerability, a severity or a score.
#   * The CLI prints the same packages the route answers.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_kernel 6 12
    require_tool python3
    require_tool jq
    require_tool dpkg-query

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 80 builds roots on the agent's host (local lane only)"
    fi

    export DATA_DIR="/tmp/ebpfsentinel-test-data-surface-$$"
    export ROOTS_PIDS_FILE="${DATA_DIR}/roots.pids"
    export APK_ROOT="${DATA_DIR}/alpine"
    export ESCAPE_ROOT="${DATA_DIR}/escape"
    mkdir -p "${DATA_DIR}"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    _make_roots

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-surface.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    if [ -f "${ROOTS_PIDS_FILE:-}" ]; then
        xargs -r kill 2>/dev/null < "${ROOTS_PIDS_FILE}" || true
    fi
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-surface-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

# _hold_root <dir> - a process whose root is <dir> until teardown. Python is
# already loaded when it changes root, so the root needs no binary of its own.
_hold_root() {
    python3 -c 'import os, sys, time
os.chroot(sys.argv[1]); os.chdir("/"); time.sleep(3600)' "$1" &
    echo "$!" >> "${ROOTS_PIDS_FILE}"
}

# _make_roots - one root with an Alpine database, one whose database is a
# link climbing out of it.
_make_roots() {
    mkdir -p "${APK_ROOT}/lib/apk/db"
    cat > "${APK_ROOT}/lib/apk/db/installed" <<'APK'
C:Q1placeholderchecksumAAAAAAAAAAAAAAAA=
P:musl
V:1.2.5-r10
A:x86_64
F:lib
R:ld-musl-x86_64.so.1
R:libc.musl-x86_64.so.1

C:Q1placeholderchecksumBBBBBBBBBBBBBBBB=
P:busybox
V:1.37.0-r18
A:x86_64
F:bin
R:busybox
APK
    mkdir -p "${ESCAPE_ROOT}/lib/apk/db"
    ln -s ../../../../../../../../var/lib/dpkg/status "${ESCAPE_ROOT}/lib/apk/db/installed"
    _hold_root "${APK_ROOT}"
    _hold_root "${ESCAPE_ROOT}"
}

# _packages - the inventory, empty when the route did not answer.
_packages() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/surface/packages" || true
}

# _wait_read <timeout_s> - polls until a reading finished, and prints it.
_wait_read() {
    local timeout="$1" body i
    for ((i = 0; i < timeout; i++)); do
        body="$(_packages)"
        if [ "$(echo "${body:-{\}}" | jq -r '.scanned_at_ns // 0')" -gt 0 ]; then
            echo "$body"
            return 0
        fi
        sleep 1
    done
    return 1
}

# _root_of <body> <pid> - the root entry read through <pid>, or through the
# process holding the same root.
_root_of() {
    echo "$1" | jq -c --argjson pid "$2" '.roots[] | select(.pid == $pid)'
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the host's packages are the ones dpkg reports" {
    local body host installed listed want got
    body="$(_wait_read 60)"
    [ "$(echo "$body" | jq -r '.reading')" = "true" ]
    host="$(echo "$body" | jq -c '.roots[] | select(.kind == "host")')"
    [ -n "$host" ]
    installed="$(dpkg-query -W -f='${db:Status-Status}\n' \
        | grep -cE '^(installed|triggers-awaited|triggers-pending)$')"
    listed="$(echo "$host" | jq '[.databases[] | select(.manager == "dpkg")
        | .packages[] | select(.state == "installed")] | length')"
    [ "$listed" -eq "$installed" ] || {
        echo "agent lists ${listed}, dpkg-query ${installed}" >&2
        return 1
    }
    want="$(dpkg-query -W -f='${Version}' bash)"
    got="$(echo "$host" | jq -r '[.databases[].packages[] | select(.name == "bash")][0].version')"
    [ "$got" = "$want" ]
    [ "$(echo "$host" | jq -r '[.databases[].packages[] | select(.name == "bash")][0].files')" -gt 0 ]
}

@test "a chroot's Alpine database is read under a root no runtime names" {
    local body pid root
    body="$(_wait_read 60)"
    pid="$(sed -n 1p "${ROOTS_PIDS_FILE}")"
    root="$(_root_of "$body" "$pid")"
    [ -n "$root" ] || {
        echo "no root read through pid ${pid}: $(echo "$body" | jq -c '[.roots[] | {kind, pid}]')" >&2
        return 1
    }
    [ "$(echo "$root" | jq -r '.kind')" = "other" ]
    [ "$(echo "$root" | jq -r '.databases[0].manager')" = "apk" ]
    [ "$(echo "$root" | jq -r '[.databases[0].packages[].name] | sort | join(",")')" = "busybox,musl" ]
    [ "$(echo "$root" | jq -r '.databases[0].packages[] | select(.name == "musl") | .files')" -eq 3 ]
}

@test "a link climbing out of a root does not reach the host's files" {
    local body pid root
    body="$(_wait_read 60)"
    pid="$(sed -n 2p "${ROOTS_PIDS_FILE}")"
    root="$(_root_of "$body" "$pid")"
    [ -n "$root" ]
    [ "$(echo "$root" | jq -r '.kind')" = "other" ]
    [ "$(echo "$root" | jq -r '.databases | length')" -eq 0 ] || {
        echo "the escape root read: $(echo "$root" | jq -c '.databases')" >&2
        return 1
    }
}

@test "a running Go program states the modules it was built from" {
    local body pid exe entry
    pid="$(pgrep -xo containerd || pgrep -xo dockerd || true)"
    [ -n "$pid" ] || soft_skip "no containerd or dockerd runs on this host"
    exe="$(readlink "/proc/${pid}/exe")"
    body="$(_wait_read 60)"
    [ "$(echo "$body" | jq '.executables_examined')" -gt 1 ]
    entry="$(echo "$body" | jq -c --arg exe "$exe" --argjson pid "$pid" \
        '[.go_executables[] | select(.path == $exe and (.pids | index($pid)))][0]')"
    [ "$entry" != "null" ] || {
        echo "${exe} (pid ${pid}) not listed: $(echo "$body" | jq -c '[.go_executables[].path]')" >&2
        return 1
    }
    [ "$(echo "$entry" | jq -r '.kind')" = "host" ]
    echo "$entry" | jq -e '.go_version | startswith("go1.")'
    echo "$entry" | jq -e '[.modules[] | select(.path | startswith("github.com/"))] | length > 0'
    # bash is no Go program, and running is what it takes to be listed.
    [ "$(echo "$body" | jq --arg bash "$(readlink -f "$(command -v bash)")" \
        '[.go_executables[] | select(.path == $bash)] | length')" -eq 0 ]
}

@test "no field names a vulnerability, a severity or a score" {
    local body
    body="$(_wait_read 60)"
    [ "$(echo "$body" | jq '[paths | map(strings) | .[]
        | select(test("cve|severity|score|vulnerab|cvss|risk"; "i"))] | length')" -eq 0 ]
}

@test "the CLI prints the packages the route answers" {
    local body out
    body="$(_wait_read 60)"
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" packages 2>&1)"
    echo "$out" | grep -qE '^host +dpkg +bash '
    echo "$out" | grep -qE ' +apk +musl +1\.2\.5-r10 '
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" packages --output json)"
    [ "$(echo "$out" | jq '.roots | length')" -eq "$(echo "$body" | jq '.roots | length')" ]
    if [ "$(echo "$body" | jq '[.go_executables[].modules[]] | length')" -gt 0 ]; then
        out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" packages 2>&1)"
        echo "$out" | grep -qE 'running executable\(s\) examined'
        echo "$out" | grep -qE '^host +/[^ ]+ +go1\.[0-9]+'
    fi
}
