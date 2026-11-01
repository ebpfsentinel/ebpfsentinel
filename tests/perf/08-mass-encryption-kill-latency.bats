#!/usr/bin/env bats
# 08-mass-encryption-kill-latency.bats - how long a run lives once the
# verdict against it is reached.
#
# The promise is a bound and not a prevention: the files written before the
# run dies are lost. That bound is a time, from the verdict to the last
# process of the run reported gone, and this suite measures it rather than
# deriving it. Each run is a fresh encryptor over a fresh tree, alone and
# then forking one worker per directory, and the figure is the one the
# agent's own stop alert states, with the files the run had written by then.
#
# Requires: root, kernel >= 6.12, python3, jq.
# Nightly tier. Outputs JSON to /tmp/ebpfsentinel-mass-encryption-kill-latency.json

FIXTURE_DIR="${BATS_TEST_DIRNAME}/../integration/fixtures"
load '../integration/lib/helpers'
load '../integration/lib/ebpf_helpers'

LATENCY_REPORT="/tmp/ebpfsentinel-mass-encryption-kill-latency.json"
RUNS="${RUNS:-5}"
DOCUMENTS="${DOCUMENTS:-2000}"
DIRECTORIES="${DIRECTORIES:-20}"

# The signal program looks for an armed target for two seconds; a run alive
# past that was never reached, which is a failure rather than a slow figure.
MAX_LATENCY_MS="${MAX_LATENCY_MS:-2000}"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "the encryptor runs on the agent host itself (local lane only)"
    fi
    require_root
    require_kernel 6 12
    require_tool python3
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-kill-latency-$$"
    mkdir -p "${DATA_DIR}"
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/me-encrypt"
    chmod 0755 "${DATA_DIR}/me-encrypt"

    stop_ebpf_agent 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mass-encryption-stop.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30
    sleep 3

    echo '{}' >"${LATENCY_REPORT}"
}

teardown_file() {
    pkill -9 -x me-encrypt 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-kill-latency-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

_report_set() {
    local tmp; tmp="$(jq --arg k "$1" --argjson v "$2" '. + {($k): $v}' "${LATENCY_REPORT}")"; echo "${tmp}" >"${LATENCY_REPORT}"
}

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

# _run <tree> <forked> - one encryption at full speed, then the stop alert's
# latency and file count as "ms files".
_run() {
    local tree="$1" forked="$2"
    "${DATA_DIR}/me-encrypt" - "${tree}" "${forked}" <<'PY' || true
import os, sys
root, forked = sys.argv[1], sys.argv[2] == "1"
def encrypt(directory):
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        with open(path, "r+b") as f:
            f.write(os.urandom(os.path.getsize(path)))
        os.rename(path, path + ".lockd")
workers = []
for directory in sorted(os.listdir(root)):
    if not forked:
        encrypt(os.path.join(root, directory))
        continue
    pid = os.fork()
    if pid == 0:
        encrypt(os.path.join(root, directory))
        os._exit(0)
    workers.append(pid)
for pid in workers:
    os.waitpid(pid, 0)
PY
    local attempt=0 stop lost
    lost="$(find "${tree}" -name '*.pdf.lockd' | wc -l)"
    while [ "${attempt}" -lt 30 ]; do
        stop="$(api_get "/api/v1/alerts?component=mass_encryption&limit=1000" |
            jq -c --arg t "${tree}/" '[(.alerts // .)[] | select(.mitigation_status != null and (.message | contains($t)))] | first')"
        if [ -n "${stop}" ] && [ "${stop}" != "null" ]; then
            jq -r --arg lost "${lost}" '(.message | capture("^(?<f>[0-9]+) files.* gone (?<ms>[0-9]+) ms after")) as $m | "\($m.ms) \($m.f) \($lost) \(.mitigation_status)"' <<<"${stop}"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

_series() {
    local forked="$1" label="$2" n ms files lost status
    local latencies="[]" counts="[]" losses="[]" statuses="[]"
    for n in $(seq 1 "${RUNS}"); do
        _tree "${DATA_DIR}/${label}-${n}"
        read -r ms files lost status < <(_run "${DATA_DIR}/${label}-${n}" "${forked}")
        [ -n "${status}" ]
        # A run still alive at the verdict is dead within the bound. One that
        # finished before it is reported as such, with nothing left to kill.
        if [ "${status}" != "not_stopped" ]; then
            [ "${ms}" -le "${MAX_LATENCY_MS}" ]
        fi
        latencies="$(jq -c --argjson v "${ms}" '. + [$v]' <<<"${latencies}")"
        counts="$(jq -c --argjson v "${files}" '. + [$v]' <<<"${counts}")"
        losses="$(jq -c --argjson v "${lost}" '. + [$v]' <<<"${losses}")"
        statuses="$(jq -c --arg v "${status}" '. + [$v]' <<<"${statuses}")"
        rm -rf "${DATA_DIR:?}/${label}-${n}"
    done
    _report_set "${label}_latency_ms" "${latencies}"
    _report_set "${label}_files_counted" "${counts}"
    _report_set "${label}_files_lost" "${losses}"
    _report_set "${label}_status" "${statuses}"
}

@test "a single encryptor is dead within the bound once the verdict is reached" {
    _series 0 single
}

@test "an encryptor forking a worker per directory is dead whole within the bound or reported finished" {
    _series 1 forked
    _report_set kernel "$(jq -n --arg k "$(uname -r)" '$k')"
    _report_set documents "${DOCUMENTS}"
    cat "${LATENCY_REPORT}" >&3
}
