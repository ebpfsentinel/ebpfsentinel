#!/usr/bin/env bats
# 96-entropy-blind-spots.bats - what a sampled entropy cannot see, and the
# signal that sees it instead.
#
# The entropy of a file is sampled over its first 64 KiB, so a run that
# encrypts only part of each file can leave it flat. The suite asserts:
#
#   * A run encrypting only the first 4 KiB of each document, in place and
#     without renaming it, is raised on one decisive signal, the header that
#     no longer matches the name, and the verdict carries no entropy rise.
#   * A run encrypting only what lies past the first 64 KiB of each
#     document, header left intact and name unchanged, reaches no verdict:
#     the blind spot the sampling documents, asserted so that it stays
#     documented.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# Documents of 128 KiB, so the sampled window is half of each one.
DOCUMENTS=40
DIRECTORIES=10

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 96 writes its files on the agent's host (local lane only)"
    fi

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-entropy-$$"
    mkdir -p "${DATA_DIR}/work"
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/me-encrypt"
    chmod 0755 "${DATA_DIR}/me-encrypt"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mass-encryption.yaml")"
    export PREPARED_CONFIG
    sed -i 's/^    mode: shadow$/    mode: enforce/' "${PREPARED_CONFIG}"
    grep -q '^    mode: enforce$' "${PREPARED_CONFIG}"
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
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-entropy-$$}"
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

# _tree <dir> - documents of 128 KiB of ordinary text, each starting with
# the head its name promises, left for the watch to read once.
_tree() {
    python3 - "$1" "${DOCUMENTS}" "${DIRECTORIES}" <<'PY'
import os, sys
root, documents, directories = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
line = b"ledger line with ordinary words in it\n"
body = (line * (131072 // len(line) + 1))[:131072 - 9]
for n in range(documents):
    os.makedirs(f"{root}/d{n % directories}", exist_ok=True)
    with open(f"{root}/d{n % directories}/report{n}.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n" + body)
PY
    sleep 5
}

# _encrypt <dir> <offset> <length> - rewrite <length> bytes at <offset> of
# every document with random bytes, in place, names unchanged.
_encrypt() {
    "${DATA_DIR}/me-encrypt" - "$@" <<'PY'
import os, sys
root, offset, length = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for directory, _, names in sorted(os.walk(root)):
    for name in sorted(names):
        if not name.endswith(".pdf"):
            continue
        with open(os.path.join(directory, name), "r+b") as f:
            f.seek(offset)
            f.write(os.urandom(length))
PY
}

_verdict_for() {
    wait_for_alert "[.[] | select(.rule_id == \"mass-encryption\" and .mitigation_status == null and (.message | contains(\"$1\")))] | last" "$2" 1
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the first 4 KiB encrypted in place is raised on the header, with no entropy rise" {
    local victim="${DATA_DIR}/work/head"
    _tree "${victim}"
    run _encrypt "${victim}" 0 4096
    [ "$status" -eq 0 ]
    run _verdict_for "on one decisive signal" 30
    [ "$status" -eq 0 ] || {
        api_get /api/v1/host-rules/mass-encryption | jq -c '.recent' >&3
        false
    }
    local message
    message="$(jq -r '.message' <<<"${output}")"
    assert_contains "${message}" "header_mismatch"
    [[ "${message}" != *"entropy_rise"* ]]
}

@test "everything past the sampled 64 KiB encrypted, header intact, reaches no verdict" {
    local before
    before="$(api_get /api/v1/alerts | jq '[.alerts // . | .[] | select(.rule_id == "mass-encryption")] | length')"
    local victim="${DATA_DIR}/work/tail"
    _tree "${victim}"
    run _encrypt "${victim}" 65536 65536
    [ "$status" -eq 0 ]
    sleep 10
    local after
    after="$(api_get /api/v1/alerts | jq '[.alerts // . | .[] | select(.rule_id == "mass-encryption")] | length')"
    [ "${after}" -eq "${before}" ]
    # The documents were rewritten: the blind spot is in the reading, not
    # in a run that did nothing.
    python3 - "${victim}" <<'PY'
import os, sys
for directory, _, names in os.walk(sys.argv[1]):
    for name in names:
        with open(os.path.join(directory, name), "rb") as f:
            data = f.read()
        assert data.startswith(b"%PDF-1.7\n"), name
        assert b"ledger line" not in data[65536:], name
PY
}
