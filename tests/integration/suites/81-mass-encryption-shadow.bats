#!/usr/bin/env bats
# 81-mass-encryption-shadow.bats - the mass encryption verdict stays quiet
# through the work a host does every day, counts an encryption in shadow,
# and raises it once promoted.
#
# The suite asserts:
#
#   * The verdict is evaluated where the file watch is open, in shadow by
#     default, and says so on its route.
#   * Real tools over a tree of a few hundred documents - an archive
#     extraction, `rsync -a`, a `git` checkout between two branches, `cp -a`,
#     `gzip` over a directory of logs, `find -delete` - reach no verdict, in
#     shadow or otherwise.
#   * A program rewriting the same documents in place with random bytes and
#     renaming each is counted in shadow under its workload, raises no alert
#     and runs to its end.
#   * The same verdict promoted to `mode: enforce` raises the alert.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# Documents in the tree, spread over directories, so every count the
# verdict keeps is past its threshold.
DOCUMENTS=240
DIRECTORIES=60

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_tool tar
    require_tool gzip
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 81 writes its files on the agent's host (local lane only)"
    fi

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-mass-encryption-$$"
    mkdir -p "${DATA_DIR}/work"
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/me-encrypt"
    chmod 0755 "${DATA_DIR}/me-encrypt"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mass-encryption.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_enabled || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the mass encryption verdict never reported itself evaluated" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-mass-encryption-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_verdict() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/host-rules/mass-encryption"
}

_shadow_events() {
    _verdict | jq -r '.shadow.events'
}

# _wait_enabled - poll until the route reports the verdict evaluated: the
# file watch opens after the datapath reports itself up.
_wait_enabled() {
    local attempt=0
    while [ "${attempt}" -lt 30 ]; do
        [ "$(_verdict 2>/dev/null | jq -r '.enabled')" = "true" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _settle - give the watch time to read back what the last tool wrote: a
# change is reported once the file is closed and read again.
_settle() {
    sleep 5
}

# _tree <dir> - a tree of documents carrying the heads their names promise,
# with a readme and a build file in every directory.
_tree() {
    python3 - "$1" "${DOCUMENTS}" "${DIRECTORIES}" <<'PY'
import os, sys
root, documents, directories = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
text = ("ledger line with ordinary words in it\n" * 400).encode()
for d in range(directories):
    os.makedirs(f"{root}/d{d}", exist_ok=True)
    for name in ("README.md", "Makefile"):
        with open(f"{root}/d{d}/{name}", "wb") as f:
            f.write(text[:600])
for n in range(documents):
    with open(f"{root}/d{n % directories}/report{n}.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n" + text)
PY
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the verdict is evaluated in shadow by default" {
    local body
    body="$(_verdict)"
    [ "$(jq -r '.enabled' <<<"${body}")" = "true" ]
    [ "$(jq -r '.mode' <<<"${body}")" = "shadow" ]
    [ "$(jq -r '.shadow.events' <<<"${body}")" -eq 0 ]
}

@test "an archive extraction, rsync, cp and gzip reach no verdict" {
    local work="${DATA_DIR}/work"
    _tree "${work}/source"
    _settle
    tar -C "${work}" -cf "${work}/source.tar" source
    mkdir -p "${work}/extracted"
    tar -C "${work}/extracted" -xf "${work}/source.tar"
    cp -a "${work}/source" "${work}/copy"
    if command -v rsync >/dev/null 2>&1; then
        mkdir -p "${work}/mirror"
        rsync -a "${work}/source/" "${work}/mirror/"
        # A second pass over changed files writes each beside itself and
        # renames it over the old one.
        find "${work}/source" -name '*.pdf' -exec sh -c 'printf "\n%%%%EOF\n" >>"$1"' _ {} \;
        rsync -a "${work}/source/" "${work}/mirror/"
    fi
    mkdir -p "${work}/logs"
    for n in $(seq 1 "${DOCUMENTS}"); do
        seq 1 2000 | sed 's/^/request served in 12 ms /' >"${work}/logs/app${n}.log"
    done
    _settle
    gzip -r "${work}/logs"
    find "${work}/copy" -name '*.pdf' -delete
    _settle
    [ "$(_shadow_events)" -eq 0 ]
    run wait_for_alert '.[] | select(.rule_id == "mass-encryption")' 3 1
    [ "$status" -ne 0 ]
}

@test "a git checkout between two branches reaches no verdict" {
    command -v git >/dev/null 2>&1 || env_skip "git is not installed on this host"
    local repo="${DATA_DIR}/work/repo"
    _tree "${repo}"
    git -C "${repo}" init -q -b one
    git -C "${repo}" -c user.name=t -c user.email=t@t add -A
    git -C "${repo}" -c user.name=t -c user.email=t@t commit -qm one
    git -C "${repo}" checkout -q -b two
    find "${repo}" -path "${repo}/.git" -prune -o -name '*.pdf' -exec sh -c 'printf "\n%%%%EOF\n" >>"$1"' _ {} \;
    git -C "${repo}" -c user.name=t -c user.email=t@t commit -qam two
    _settle
    git -C "${repo}" checkout -q one
    git -C "${repo}" checkout -q two
    _settle
    [ "$(_shadow_events)" -eq 0 ]
}

@test "an encryption in shadow is counted by workload and raises nothing" {
    local victim="${DATA_DIR}/work/victim"
    _tree "${victim}"
    _settle
    local before
    before="$(_shadow_events)"
    run "${DATA_DIR}/me-encrypt" - "${victim}" <<'PY'
import os, sys
for directory, _, names in os.walk(sys.argv[1]):
    for name in names:
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
        os.rename(path, path + ".lockd")
PY
    [ "$status" -eq 0 ]
    local attempt=0
    while [ "${attempt}" -lt 20 ] && [ "$(_shadow_events)" -le "${before}" ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    [ "$(_shadow_events)" -gt "${before}" ]
    local body
    body="$(_verdict)"
    [ "$(jq '.shadow.workloads | length' <<<"${body}")" -ge 1 ]
    jq -e '.recent | last | .exe | endswith("/me-encrypt")' <<<"${body}"
    jq -e '.recent | last | .message | startswith("mass encryption by")' <<<"${body}"
    run wait_for_alert '.[] | select(.rule_id == "mass-encryption")' 3 1
    [ "$status" -ne 0 ]
}

@test "the verdict promoted to enforce raises the alert" {
    stop_ebpf_agent
    sed -i 's/^    mode: shadow$/    mode: enforce/' "${PREPARED_CONFIG}"
    grep -q '^    mode: enforce$' "${PREPARED_CONFIG}"
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30
    _wait_enabled
    [ "$(_verdict | jq -r '.mode')" = "enforce" ]

    local victim="${DATA_DIR}/work/enforced"
    _tree "${victim}"
    _settle
    run "${DATA_DIR}/me-encrypt" - "${victim}" <<'PY'
import os, sys
for directory, _, names in os.walk(sys.argv[1]):
    for name in names:
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
        os.rename(path, path + ".lockd")
PY
    [ "$status" -eq 0 ]
    wait_for_alert '.[] | select(.rule_id == "mass-encryption" and .component == "mass_encryption")' 20 1
    [ "$(_shadow_events)" -eq 0 ]
}
