#!/usr/bin/env bats
# 82-mass-encryption-detected-and-stopped.bats - a verdict in force kills
# the run it names, the whole of it, and says what the run had cost.
#
# The suite asserts:
#
#   * A program rewriting documents with random bytes one after the other
#     is killed before it reaches the end of the tree, a second alert says
#     how many files it had written by then, and that count matches the
#     documents found rewritten on disk once it is dead.
#   * The same program forking one worker per directory is stopped whole:
#     the parent and every worker are gone, and the alert counts them.
#   * Both alerts carry the signals the verdict was reached on.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# More documents than a run gets through before it is stopped, written
# slowly enough that the stop lands in the middle of the tree.
DOCUMENTS=1200
DIRECTORIES=40
PACE_SECONDS=0.01

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 82 writes its files on the agent's host (local lane only)"
    fi

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-mass-encryption-stop-$$"
    mkdir -p "${DATA_DIR}/work"
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/me-encrypt"
    chmod 0755 "${DATA_DIR}/me-encrypt"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mass-encryption-stop.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_enforced || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the mass encryption verdict never reported itself in force" >&2; return 1; }
    }
}

teardown_file() {
    pkill -9 -x me-encrypt 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-mass-encryption-stop-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_wait_enforced() {
    local attempt=0 body
    while [ "${attempt}" -lt 30 ]; do
        body="$(curl -sf --max-time "${HTTP_TIMEOUT}" \
            "${BASE_URL}/api/v1/host-rules/mass-encryption" 2>/dev/null)" || body=""
        [ "$(jq -r '.enabled' <<<"${body}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.mode' <<<"${body}" 2>/dev/null)" = "enforce" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _tree <dir> - documents carrying the heads their names promise.
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
    sleep 5
}

# _rewritten <dir> - documents the run got to: rewritten and renamed.
_rewritten() {
    find "$1" -name '*.pdf.lockd' | wc -l
}

# _stop_alert <tree> - the stop raised for a run over <tree>, once present.
_stop_alert() {
    wait_for_alert "[.[] | select(.rule_id == \"mass-encryption\" and .mitigation_status != null and (.message | contains(\"$1/\")))] | last" 30 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "one process encrypting a tree is killed in the middle of it and the files lost are counted" {
    local victim="${DATA_DIR}/work/one"
    _tree "${victim}"
    run "${DATA_DIR}/me-encrypt" - "${victim}" "${PACE_SECONDS}" <<'PY'
import os, sys, time
for directory, _, names in sorted(os.walk(sys.argv[1])):
    for name in sorted(names):
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
        os.rename(path, path + ".lockd")
        time.sleep(float(sys.argv[2]))
PY
    # Killed by the signal the stop sends, not run to its end.
    [ "$status" -eq 137 ]
    local alert
    alert="$(_stop_alert "${victim}")"
    [ "$(jq -r '.mitigation_status' <<<"${alert}")" = "stopped" ]
    jq -e '.message | test("^[0-9]+ files written before the run was stopped; 1 of 1 processes of the run gone [0-9]+ ms after the verdict")' <<<"${alert}"
    jq -e '.message | contains("mass encryption by")' <<<"${alert}"
    jq -e '.executable_path | endswith("/me-encrypt")' <<<"${alert}"
    local counted lost
    counted="$(jq -r '.message | capture("^(?<n>[0-9]+) files").n' <<<"${alert}")"
    lost="$(_rewritten "${victim}")"
    [ "${lost}" -gt 0 ]
    [ "${lost}" -lt "${DOCUMENTS}" ]
    # The count is what the watch read back: every file it names was
    # rewritten, and at most the one being written as the signal landed is
    # missing from it.
    [ "${counted}" -le "${lost}" ]
    [ "$((lost - counted))" -le 1 ]
}

@test "a run forking one worker per directory is stopped whole" {
    local victim="${DATA_DIR}/work/forked"
    _tree "${victim}"
    run "${DATA_DIR}/me-encrypt" - "${victim}" "${PACE_SECONDS}" <<'PY'
import os, sys, time
root, pace = sys.argv[1], float(sys.argv[2])
workers = []
for directory in sorted(os.listdir(root)):
    pid = os.fork()
    if pid == 0:
        for name in sorted(os.listdir(os.path.join(root, directory))):
            if not name.endswith(".pdf"):
                continue
            path = os.path.join(root, directory, name)
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.write(os.urandom(size))
            os.rename(path, path + ".lockd")
            time.sleep(pace)
        os._exit(0)
    workers.append(pid)
with open(os.path.join(os.path.dirname(root), "workers"), "w") as f:
    f.write("\n".join(str(p) for p in workers))
for pid in workers:
    os.waitpid(pid, 0)
PY
    [ "$status" -eq 137 ]
    local alert
    alert="$(_stop_alert "${victim}")"
    [ "$(jq -r '.mitigation_status' <<<"${alert}")" = "stopped" ]
    # Every process of the run still alive at the verdict was killed: the
    # parent and the workers that had not finished their directory.
    local killed total
    killed="$(jq -r '.message | capture("; (?<k>[0-9]+) of").k' <<<"${alert}")"
    total="$(jq -r '.message | capture("; [0-9]+ of (?<n>[0-9]+) processes").n' <<<"${alert}")"
    [ "${total}" -gt 1 ]
    [ "${killed}" -eq "${total}" ]
    # No worker outlived its parent.
    local pid
    while read -r pid; do
        [ ! -d "/proc/${pid}" ] || [ "$(cat "/proc/${pid}/comm")" != "me-encrypt" ]
    done <"${DATA_DIR}/work/workers"
    ! pgrep -x me-encrypt
    [ "$(_rewritten "${victim}")" -lt "${DOCUMENTS}" ]
}
