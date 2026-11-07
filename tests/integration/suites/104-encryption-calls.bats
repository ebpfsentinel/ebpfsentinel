#!/usr/bin/env bats
# 104-encryption-calls.bats - calls into the system crypto library counted
# per process and read beside the files the same process rewrites.
#
# The suite asserts:
#
#   * The crypto call counter loads and probes the libcrypto this host maps.
#   * A program rewriting the body of each document in place with bytes it
#     generated itself, leaving the header alone and renaming nothing,
#     carries only supporting signals and reaches no verdict.
#   * The same program producing those bytes through EVP_EncryptUpdate, a
#     few calls per file, reaches the verdict in shadow, on the evidence
#     that its encryption calls tracked its rewrites.
#   * The self-made rewrite, run by a process that has just destroyed a
#     snapshot, reaches the verdict on the prior: the exec is read on the
#     boot clock and the rewrites on the wall clock, so the two are only
#     paired inside one window when the exec is moved onto the wall clock.
#
# Requires: root, kernel >= 6.12, jq, python3, libcrypto.so.3.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# Past the distinct rewrites one actor may make, so the self-made run carries
# two supporting signals and the library run the strong one beside them.
DOCUMENTS=120
DIRECTORIES=12

setup_file() {
    require_kernel 6 12
    require_tool jq
    require_tool python3
    require_root

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 104 writes its files on the agent's host (local lane only)"
    fi
    python3 -c 'import ctypes; ctypes.CDLL("libcrypto.so.3")' 2>/dev/null \
        || env_skip "libcrypto.so.3 is not installed on this host"

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-crypto-calls-$$"
    mkdir -p "${DATA_DIR}/work"
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/me-encrypt"
    chmod 0755 "${DATA_DIR}/me-encrypt"
    # A `zfs destroy` with no pool behind it: an interpreter under the name
    # the prior is read from, running a script called `destroy` that stays
    # alive long enough for the table to read its command line.
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/zfs"
    chmod 0755 "${DATA_DIR}/zfs"
    printf 'import time\ntime.sleep(2)\n' >"${DATA_DIR}/destroy"

    # The library is probed where a running process maps it, so one process
    # holds it mapped from before the agent starts.
    python3 -c 'import ctypes, time; ctypes.CDLL("libcrypto.so.3"); time.sleep(3600)' &
    export HOLDER_PID=$!

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
    kill "${HOLDER_PID:-}" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-crypto-calls-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_verdict() {
    curl -sf --max-time "${HTTP_TIMEOUT}" "${BASE_URL}/api/v1/host-rules/mass-encryption"
}

_shadow_events() {
    _verdict | jq -r '.shadow.events'
}

_wait_enabled() {
    local attempt=0
    while [ "${attempt}" -lt 30 ]; do
        [ "$(_verdict 2>/dev/null | jq -r '.enabled')" = "true" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

_settle() {
    sleep 5
}

# _tree <dir> - documents carrying the head their name promises.
_tree() {
    python3 - "$1" "${DOCUMENTS}" "${DIRECTORIES}" <<'PY'
import os, sys
root, documents, directories = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
text = ("ledger line with ordinary words in it\n" * 400).encode()
for d in range(directories):
    os.makedirs(f"{root}/d{d}", exist_ok=True)
for n in range(documents):
    with open(f"{root}/d{n % directories}/report{n}.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n" + text)
PY
}

# _rewrite <dir> <evp|self|prior> [pause] - rewrite every document's body in
# place, the header kept, through EVP_EncryptUpdate or through os.urandom
# (`prior` destroys a snapshot first, then writes as `self` does), pausing
# `pause` seconds after each. The calls are read once a second and a file
# counts against a run only once its writer was seen calling the library, so
# a run over in a few milliseconds would end before the first reading.
_rewrite() {
    "${DATA_DIR}/me-encrypt" - "$@" <<'PY'
import ctypes, os, sys, time
root, how = sys.argv[1], sys.argv[2]
HEAD = len(b"%PDF-1.7\n")
CHUNK = 2048
if how == "evp":
    lib = ctypes.CDLL("libcrypto.so.3")
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_aes_256_ctr.restype = ctypes.c_void_p
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    ctx = lib.EVP_CIPHER_CTX_new()
    assert lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_ctr(), None, os.urandom(32), os.urandom(16)) == 1

    def seal(data):
        out = bytearray()
        for i in range(0, len(data), CHUNK):
            part = data[i:i + CHUNK]
            buf = ctypes.create_string_buffer(len(part) + 32)
            n = ctypes.c_int(0)
            assert lib.EVP_EncryptUpdate(ctx, buf, ctypes.byref(n), part, len(part)) == 1
            out += buf.raw[:n.value]
        return bytes(out)
else:
    if how == "prior":
        import subprocess
        here = os.path.dirname(os.path.realpath(sys.executable))
        subprocess.run([os.path.join(here, "zfs"), "destroy", "tank/home@daily"],
                       cwd=here, check=True)
        time.sleep(1)

    def seal(data):
        return os.urandom(len(data))

for directory, _, names in os.walk(root):
    for name in sorted(names):
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        with open(path, "r+b") as f:
            body = f.read()[HEAD:]
            f.seek(HEAD)
            f.write(seal(body))
        if len(sys.argv) > 3:
            time.sleep(float(sys.argv[3]))
PY
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the crypto call counter loads and probes libcrypto" {
    wait_for_ebpf_program "uprobe-crypto" 30 || {
        echo "uprobe-crypto not loaded; agent log:" >&2
        grep -i 'encryption calls' "${AGENT_LOG_FILE:-/dev/null}" >&2 || true
        return 1
    }
}

@test "a rewrite of every body with self-made bytes reaches no verdict" {
    local victim="${DATA_DIR}/work/plain"
    _tree "${victim}"
    _settle
    local before
    before="$(_shadow_events)"
    run _rewrite "${victim}" self 0.05
    [ "$status" -eq 0 ] || { echo "$output" >&2; return 1; }
    _settle
    [ "$(_shadow_events)" -eq "${before}" ] || {
        echo "a rewrite without the library reached a verdict: $(_verdict)" >&2
        return 1
    }
}

@test "the same rewrite through EVP_EncryptUpdate reaches the verdict on the crypto rate" {
    local victim="${DATA_DIR}/work/sealed"
    _tree "${victim}"
    _settle
    local before
    before="$(_shadow_events)"
    run _rewrite "${victim}" evp 0.05
    [ "$status" -eq 0 ] || { echo "$output" >&2; return 1; }
    local attempt=0
    while [ "${attempt}" -lt 30 ] && [ "$(_shadow_events)" -le "${before}" ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    local body
    body="$(_verdict)"
    [ "$(jq -r '.shadow.events' <<<"${body}")" -gt "${before}" ] || {
        echo "no verdict for an encryption through the library: ${body}" >&2
        grep -iE 'crypto|encryption|ransom|me-encrypt' "${AGENT_LOG_FILE}" | tail -15 | cut -c1-400 >&2
        return 1
    }
    jq -e '.recent | last | .exe | endswith("/me-encrypt")' <<<"${body}" >/dev/null || { echo "${body}" >&2; return 1; }
    jq -e '.recent | last | .message | contains("encryption calls beside")' <<<"${body}" >/dev/null || {
        echo "the verdict does not name the crypto rate: ${body}" >&2
        return 1
    }
}

@test "the self-made rewrite after a snapshot destroyed reaches the verdict on the prior" {
    local victim="${DATA_DIR}/work/after-prior"
    _tree "${victim}"
    _settle
    local before
    before="$(_shadow_events)"
    run _rewrite "${victim}" prior 0.05
    [ "$status" -eq 0 ] || { echo "$output" >&2; return 1; }
    local attempt=0
    while [ "${attempt}" -lt 30 ] && [ "$(_shadow_events)" -le "${before}" ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    local body
    body="$(_verdict)"
    [ "$(jq -r '.shadow.events' <<<"${body}")" -gt "${before}" ] || {
        echo "no verdict for a rewrite after a snapshot destroyed: ${body}" >&2
        grep -iE 'backups destroyed|ransom|me-encrypt' "${AGENT_LOG_FILE}" | tail -15 | cut -c1-400 >&2
        return 1
    }
    jq -e '.recent | last | .exe | endswith("/me-encrypt")' <<<"${body}" >/dev/null || { echo "${body}" >&2; return 1; }
    jq -e '.recent | last | .message | contains("after backups were destroyed")' <<<"${body}" >/dev/null || {
        echo "the verdict does not rest on the prior: ${body}" >&2
        return 1
    }
    jq -e '.recent | last | .message | contains("zfs dataset or snapshot destroyed")' <<<"${body}" >/dev/null || {
        echo "the verdict does not name the snapshot destroyed: ${body}" >&2
        return 1
    }
}
