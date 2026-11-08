#!/usr/bin/env bash
# capture-refusals.sh - record the two refusals only a host running the BPF LSM
# can show, as demo/capture.sh records the lab's scenarios.
#
#   refused-connect  an executable outside the network list is refused its
#                    connection, the listed one goes through, and the alert
#                    names the binary by device and inode
#   refused-write    one process creating files under a watched directory is
#                    refused at the tenth, and the alert names it
#
# The lab cannot show either: its agent runs in a container on whatever host
# the reader has, and both need `bpf` among the host's security modules. The
# agent VM boots with lsm=bpf, so this runs there, as root, on the local lane:
#
#   sudo PROJECT_ROOT=/home/vagrant/ebpfsentinel \
#       EBPFSENTINEL_CAPTURE_COMMIT=<sha the build came from> \
#       bash tests/integration/scripts/capture-refusals.sh
#
# Writes demo/captures/refused-connect.json and refused-write.json. The agent
# is the one this tree built, started by the lane's own helpers.
#
# No `set -e`: the lane's helpers are written for bats, which runs them
# without it, so every step that matters is checked here instead.

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
export PROJECT_ROOT
FIXTURE_DIR="${PROJECT_ROOT}/tests/integration/fixtures"
export FIXTURE_DIR
# shellcheck source=SCRIPTDIR/../lib/helpers.bash
source "${PROJECT_ROOT}/tests/integration/lib/helpers.bash"
# shellcheck source=SCRIPTDIR/../lib/ebpf_helpers.bash
source "${PROJECT_ROOT}/tests/integration/lib/ebpf_helpers.bash"

CAPTURE="${PROJECT_ROOT}/demo/capture.sh"
export DATA_DIR=/var/tmp/ebpfsentinel-capture
WATCHED="${DATA_DIR}/watched"

die() {
    echo "capture-refusals: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || die "run as root"
tr ',' '\n' </sys/kernel/security/lsm | grep -qx bpf ||
    die "the BPF LSM is not active on this host (lsm=bpf at boot)"
_has_local_ebpf || die "no local build: cargo xtask ebpf-build and cargo build --release first"

cleanup() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

rm -rf "$DATA_DIR"
mkdir -p "$WATCHED" "${DATA_DIR}/system" "${DATA_DIR}/bin"
install -m 0755 "$(command -v tee)" "${DATA_DIR}/bin/expected-writer"
echo original >"${DATA_DIR}/held.conf"
create_test_netns

# The CLI a reader runs is the agent's own binary, so the one on PATH here is
# the staged copy the agent runs from: the network list always lets the agent
# reach the network, and an unrelated copy of the same build is another inode.
mkdir -p "${DATA_DIR}/path"
ln -sf /tmp/ebpfsentinel-agent-staged "${DATA_DIR}/path/ebpfsentinel-agent"
export PATH="${DATA_DIR}/path:${PATH}"

# start <fixture> - prepare and start the agent on a fixture, eBPF loaded.
start() {
    PREPARED_CONFIG="$(prepare_ebpf_config "$1" "${DATA_DIR}/config.yaml")"
    start_ebpf_agent "$PREPARED_CONFIG" || die "the agent did not start on $1"
    wait_for_ebpf_loaded 30 || die "the eBPF programs did not load"
}

# until_true <tries> <command...> - poll a command, half a second apart.
until_true() {
    local tries="$1" n=0
    shift
    until "$@" >/dev/null 2>&1; do
        n=$((n + 1))
        [ "$n" -lt "$tries" ] || return 1
        sleep 0.5
    done
}

# ── refused-connect ─────────────────────────────────────────────────

curl_bin="$(readlink -f "$(command -v curl)")"
sed -e "s|__EXEC_MODE__|enforce|" -e "s|__CURL__|${curl_bin}|" \
    "${FIXTURE_DIR}/config-ebpf-network-executables.yaml" >"${DATA_DIR}/network-executables.yaml"
start "${DATA_DIR}/network-executables.yaml"
until_true 60 grep -q "network executables enforce" "$AGENT_LOG_FILE" ||
    die "the network list did not start in enforce"

"$CAPTURE" begin refused-connect host || die "could not begin refused-connect"
"$CAPTURE" step refused-connect host -- \
    curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthz
"$CAPTURE" step refused-connect host -- \
    python3 -c 'import socket; socket.create_connection(("127.0.0.1", 8080))'
wait_for_alert '.[] | select(.rule_id == "network-executables") | .id' 30 1 >/dev/null ||
    die "no network-executables alert"
"$CAPTURE" step refused-connect host -- \
    ebpfsentinel-agent alerts list --component workload-firewall --limit 1

stop_ebpf_agent

# ── refused-write ───────────────────────────────────────────────────

start "${FIXTURE_DIR}/config-ebpf-write-refusal.yaml"
enforcing() {
    api_get /api/v1/ebpf/kernel-features | jq -e '.write_refusal.attached and .write_refusal.enforcing'
}
until_true 60 enforcing || die "the write refusal never reported itself in force"

"$CAPTURE" begin refused-write host || die "could not begin refused-write"
"$CAPTURE" step refused-write host -- \
    sh -c "for n in \$(seq 1 12); do echo payload >${WATCHED}/doc\$n.txt && echo doc\$n.txt written; done"
wait_for_alert '.[] | select(.rule_id == "write-refusal") | .id' 30 1 >/dev/null ||
    die "no write-refusal alert"
"$CAPTURE" step refused-write host -- \
    ebpfsentinel-agent alerts list --component mass_encryption --limit 1
"$CAPTURE" step refused-write host -- ebpfsentinel-agent host-rules write-refusal

echo "capture-refusals: wrote refused-connect and refused-write under ${PROJECT_ROOT}/demo/captures"
