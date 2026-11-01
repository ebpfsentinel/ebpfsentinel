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
#   * A program started during the suite is listed with the files it maps
#     and the package owning its C library, and leaves once it is stopped.
#   * What a chrooted process maps is attributed to its own root.
#   * The CLI prints the mapped files the route answers.
#   * A server started during the suite is listed among the listeners with
#     the packages its process maps, the connection it took and who the
#     policy lets reach it, and leaves once it is stopped.
#   * The CLI prints the listeners the route answers.
#   * The surface sums agree with themselves: every installed package is
#     mapped or not, every listener has one origin, and a server reachable
#     from anywhere is listed with its packages, in the route and the CLI.

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

# _loaded - the mapped files, empty when the route did not answer.
_loaded() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/surface/loaded" || true
}

# _wait_loaded <timeout_s> [jq args...] <jq filter> - polls until the mapped
# files satisfy the filter, and prints them.
_wait_loaded() {
    local timeout="$1" body i
    shift
    for ((i = 0; i < timeout; i++)); do
        body="$(_loaded)"
        if echo "${body:-{\}}" | jq -e "$@" >/dev/null 2>&1; then
            echo "$body"
            return 0
        fi
        sleep 1
    done
    echo "${body:-}" | jq -c '{processes_listed, processes_reread, processes_not_read,
        objects: (.objects | length)}' >&2
    return 1
}

# _listening - the listeners with their packages, empty when the route did
# not answer.
_listening() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/surface/listening" || true
}

# _wait_listening <timeout_s> [jq args...] <jq filter> - polls until the
# listeners satisfy the filter, and prints them.
_wait_listening() {
    local timeout="$1" body i
    shift
    for ((i = 0; i < timeout; i++)); do
        body="$(_listening)"
        if echo "${body:-{\}}" | jq -e "$@" >/dev/null 2>&1; then
            echo "$body"
            return 0
        fi
        sleep 1
    done
    echo "${body:-}" | jq -c '{listeners_read, inventory_read,
        listeners: [.listeners[]? | {port, pid, mapped_read}]}' >&2
    return 1
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

@test "a program started now is listed with what it maps, and leaves when stopped" {
    local svc pid body libc
    svc="${DATA_DIR}/surface-service"
    cp "$(readlink -f "$(command -v sleep)")" "$svc"
    "$svc" 3600 &
    pid=$!
    echo "$pid" >> "${ROOTS_PIDS_FILE}"
    body="$(_wait_loaded 150 --argjson pid "$pid" --arg svc "$svc" \
        '.objects | any(.path == $svc and (.pids | index($pid)))')" || {
        kill "$pid" 2>/dev/null || true
        echo "${svc} (pid ${pid}) never listed" >&2
        return 1
    }
    [ "$(echo "$body" | jq -r --arg svc "$svc" '.objects[] | select(.path == $svc) | .kind')" = "host" ]
    # Nothing installed it, so no package owns it.
    [ "$(echo "$body" | jq -r --arg svc "$svc" '.objects[] | select(.path == $svc) | .owner')" = "null" ]
    # Every process on the host maps the C library, so the new one is
    # counted there rather than among the sixteen pids named.
    libc="$(echo "$body" | jq -c \
        '[.objects[] | select(.kind == "host" and (.path | test("/libc\\.so\\.6$")))][0]')"
    [ "$libc" != "null" ]
    [ "$(echo "$libc" | jq -r '.owner.manager + " " + .owner.name')" = "dpkg libc6" ]
    [ "$(echo "$libc" | jq -r '.owner.version')" = "$(dpkg-query -W -f='${Version}' libc6)" ]
    [ "$(echo "$libc" | jq '.processes')" -gt 1 ]
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    _wait_loaded 150 --arg svc "$svc" '.objects | all(.path != $svc)' >/dev/null
}

@test "what a chrooted process maps is attributed to its own root" {
    local pid body entry
    pid="$(sed -n 1p "${ROOTS_PIDS_FILE}")"
    body="$(_wait_loaded 150 --argjson pid "$pid" \
        '.objects | any((.pids | index($pid)) and .root_pid == $pid)')" || {
        echo "nothing mapped by pid ${pid} is under its own root" >&2
        return 1
    }
    entry="$(echo "$body" | jq -c --argjson pid "$pid" \
        '[.objects[] | select((.pids | index($pid)) and (.path | test("python")))][0]')"
    [ "$entry" != "null" ]
    [ "$(echo "$entry" | jq -r '.kind')" = "other" ]
    [ "$(echo "$entry" | jq -r '.root_pid')" = "$pid" ]
    # The Alpine database of that root owns no python, whatever the host's says.
    [ "$(echo "$entry" | jq -r '.owner')" = "null" ]
}

@test "the CLI prints the mapped files the route answers" {
    local body out
    body="$(_wait_loaded 150 '.objects | length > 0')"
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" loaded 2>&1)"
    echo "$out" | grep -qE 'process\(es\) listed'
    echo "$out" | grep -qE '^host +/[^ ]*libc\.so\.6 +libc6 '
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" loaded --output json)"
    echo "$out" | jq -e '.objects | length > 0'
    [ "$(echo "$out" | jq '[paths | map(strings) | .[]
        | select(test("cve|severity|score|vulnerab|cvss|risk"; "i"))] | length')" -eq 0 ]
}

@test "a server started now is listed with the packages behind it, and leaves when stopped" {
    local port=18480 pid body row i
    python3 -m http.server --bind 0.0.0.0 "$port" >/dev/null 2>&1 &
    pid=$!
    echo "$pid" >> "${ROOTS_PIDS_FILE}"
    # The first request that answers is the connection it takes.
    for ((i = 0; i < 20; i++)); do
        curl -sf --max-time 2 "http://127.0.0.1:${port}/" >/dev/null && break
        sleep 0.5
    done
    body="$(_wait_listening 150 --argjson pid "$pid" --argjson port "$port" \
        '.listeners | any(.port == $port and .pid == $pid and .mapped_read
            and (.accepted // 0) > 0)')" || {
        kill "$pid" 2>/dev/null || true
        echo "port ${port} (pid ${pid}) never listed with its packages" >&2
        return 1
    }
    row="$(echo "$body" | jq -c --argjson port "$port" '[.listeners[] | select(.port == $port)][0]')"
    [ "$(echo "$row" | jq -r '.protocol + " " + .scope')" = "tcp all_addresses" ]
    # The firewall only alerts and lets everything through.
    [ "$(echo "$row" | jq -r '.origin')" = "anywhere" ]
    [ "$(echo "$row" | jq -r '.class')" = "exposed_used" ]
    echo "$row" | jq -e --arg v "$(dpkg-query -W -f='${Version}' libc6)" \
        '.packages | any(.manager == "dpkg" and .name == "libc6" and .version == $v)'
    # The interpreter itself is installed by a python3 package.
    echo "$row" | jq -e '.packages | any(.name | startswith("libpython3") or startswith("python3"))'
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    _wait_listening 60 --argjson port "$port" '.listeners | all(.port != $port)' >/dev/null
}

@test "the CLI prints the listeners the route answers" {
    local port=18481 pid out
    # The agent's own port was bound before its hooks attached, so it is not
    # listed: a server started now is.
    python3 -m http.server --bind 0.0.0.0 "$port" >/dev/null 2>&1 &
    pid=$!
    echo "$pid" >> "${ROOTS_PIDS_FILE}"
    _wait_listening 150 --argjson port "$port" \
        '.listeners | any(.port == $port and .mapped_read)' >/dev/null || {
        kill "$pid" 2>/dev/null || true
        return 1
    }
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" listening 2>&1)"
    echo "$out" | grep -qE "^0\\.0\\.0\\.0 +${port} +tcp +${pid} +anywhere +exposed_unused +0 +.*libc6 "
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" listening --output json)"
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    echo "$out" | jq -e '.listeners_read and .inventory_read'
    [ "$(echo "$out" | jq '[paths | map(strings) | .[]
        | select(test("cve|severity|score|vulnerab|cvss|risk"; "i"))] | length')" -eq 0 ]
}

@test "the surface sums what is installed, mapped, listening and reachable" {
    local port=18482 pid body out
    python3 -m http.server --bind 0.0.0.0 "$port" >/dev/null 2>&1 &
    pid=$!
    echo "$pid" >> "${ROOTS_PIDS_FILE}"
    _wait_listening 150 --argjson port "$port" \
        '.listeners | any(.port == $port and .mapped_read)' >/dev/null || {
        kill "$pid" 2>/dev/null || true
        return 1
    }
    body="$(curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/surface")"
    # The command reads the same route while the server still listens, so
    # the reachable table it prints is not empty.
    out="$("$AGENT_BIN" surface --host "$AGENT_HOST" --port "$AGENT_HTTP_PORT" 2>&1)"
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    echo "$body" | jq -e '.inventory_read and .listeners_read and .scanned_at_ns > 0'
    # Every installed package is either mapped by a live process or not.
    echo "$body" | jq -e '.installed.packages > 0
        and .runs.packages_mapped > 0
        and .runs.packages_mapped + .runs.packages_not_mapped == .installed.packages'
    echo "$body" | jq -e '.listens | .sockets == .anywhere + .private_only + .blocked + .loopback
        and .sockets == .took_traffic + .took_no_traffic + .unmeasured'
    echo "$body" | jq -e '(.reachable | length) == .listens.anywhere + .listens.private_only
        and (.blocked | length) == .listens.blocked'
    echo "$body" | jq -e --argjson port "$port" \
        '.reachable | any(.port == $port and (.packages | any(.name == "libc6")))'
    [ "$(echo "$body" | jq '[paths | map(strings) | .[]
        | select(test("cve|severity|score|vulnerab|cvss|risk"; "i"))] | length')" -eq 0 ]

    echo "$out" | grep -qE "^Installed: [0-9]+ package\\(s\\) in [0-9]+ root\\(s\\)"
    echo "$out" | grep -qE "^Runs: +[0-9]+ process\\(es\\) map [0-9]+ file\\(s\\)"
    echo "$out" | grep -qE "^Reach: +[0-9]+ from anywhere"
    echo "$out" | grep -q "^Reachable:"
}
