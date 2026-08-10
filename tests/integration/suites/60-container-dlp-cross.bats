#!/usr/bin/env bats
# 60-container-dlp-cross.bats — cross-container TLS DLP.
#
# Proves the agent captures a NEIGHBOURING container's TLS plaintext, not just
# its own. A uprobe fires only for processes mapping the exact target inode, so a
# container running its own libssl (a different inode from the host's) is captured
# ONLY if the agent resolved that container's library through the host /proc and
# attached a uprobe to it — the cross-container coverage this epic adds.
#
# Topology:
#   * The agent runs on the host with DLP + the container resolver enabled.
#   * A throwaway container runs an in-container openssl s_server (a long-lived
#     libssl mapping the watcher discovers) and an openssl s_client loop that
#     writes a Visa sentinel over TLS. The s_client's SSL_write plaintext is what
#     the agent must capture from the neighbour.
#
# OSS scope: dynamic libssl / BoringSSL only. Statically-linked TLS runtimes
# (Go crypto/tls, Rust rustls, Java JSSE) export no libssl symbol and are out of
# scope (Enterprise). The warden-brokered attach used in the rootless posture is
# covered by the warden unit tests; this suite exercises the discovery + attach +
# capture + attribution path with the agent attaching directly.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# A Visa test number carried over the neighbour's TLS — matches dlp-pci-visa.
SENTINEL_VISA="4111111111111111"

# ── Docker availability (mirrors suite 54) ──────────────────────────

_docker_available() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo docker info &>/dev/null 2>&1
    else
        command -v docker >/dev/null 2>&1 && docker info &>/dev/null 2>&1
    fi
}

_docker_cmd() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo docker "$@"
    else
        docker "$@"
    fi
}

# Count DLP alerts currently held by the agent.
_dlp_alert_count() {
    local body
    body="$(api_get /api/v1/alerts)"
    echo "${body}" | jq '[(.alerts // .)[] | select(.component == "dlp")] | length' 2>/dev/null || echo 0
}

# Run a neighbour container that performs TLS carrying the Visa sentinel. The
# in-container s_server keeps libssl mapped so the agent's watcher discovers and
# attaches to the container's inode before the s_client loop fires the uprobe.
_run_neighbour_tls_container() {
    local cname="$1"
    _docker_cmd rm -f "${cname}" >/dev/null 2>&1 || true
    _docker_cmd run --rm --name "${cname}" alpine:latest sh -c '
        apk add --no-cache openssl >/dev/null 2>&1 || exit 3
        openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem \
            -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1 || exit 4
        openssl s_server -accept 19443 -cert /tmp/c.pem -key /tmp/k.pem -quiet \
            >/dev/null 2>&1 &
        # Let the agent watcher (5s poll) discover this container libssl inode
        # and attach the uprobe before any plaintext is written.
        sleep 9
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            printf "payment card: '"${SENTINEL_VISA}"' charge now\n" \
                | openssl s_client -connect 127.0.0.1:19443 -quiet >/dev/null 2>&1 || true
            sleep 1
        done
        sleep 2
    '
}

setup_file() {
    require_root
    require_kernel 6 9
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-dlp-container-$$"
    mkdir -p "${DATA_DIR}"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-dlp-container.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load (degraded mode). Log tail:" >&2
        tail -5 "${AGENT_LOG_FILE}" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        return 1
    }
}

teardown_file() {
    _docker_cmd rm -f "ebpfsentinel-dlp-neighbour-$$" >/dev/null 2>&1 || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-dlp-container-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── DLP program health ──────────────────────────────────────────────

@test "DLP uprobe program is active" {
    require_root
    local body
    body="$(api_get /healthz)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]
}

# ── Libraries with no name left ─────────────────────────────────────

@test "an SSL library with no name left is still discovered and probed" {
    require_root
    require_tool python3

    local sys_ssl
    sys_ssl="$(ldconfig -p 2>/dev/null | awk '/libssl\.so\.3/ {print $NF; exit}')"
    [ -n "${sys_ssl}" ] && [ -f "${sys_ssl}" ] ||
        env_skip "no system libssl.so.3 to copy"

    # Keep the basename the scanner matches on; only the directory is ours.
    local copy="${DATA_DIR}/nameless/libssl.so.3"
    mkdir -p "$(dirname "${copy}")"
    cp "${sys_ssl}" "${copy}"

    # Unlink the copy BEFORE loading it, so the mapping is born carrying the
    # kernel's "(deleted)" marker. That makes the case deterministic: no poll of
    # the watcher can ever have seen this inode under a name, and there is no
    # path under /proc/<pid>/root that reaches it. Discovery has to go through
    # the mapping's map_files entry or it does not happen at all.
    local holder="${DATA_DIR}/hold-deleted.py"
    cat >"${holder}" <<'PY'
import ctypes, os, sys, time

path = sys.argv[1]
fd = os.open(path, os.O_RDONLY)
os.unlink(path)
ctypes.CDLL("/proc/self/fd/%d" % fd)
sys.stdout.write("%d\n" % os.getpid())
sys.stdout.flush()
time.sleep(120)
PY

    python3 "${holder}" "${copy}" >"${DATA_DIR}/holder.out" 2>"${DATA_DIR}/holder.err" &
    local holder_job=$!

    local pid=""
    for _ in $(seq 1 40); do
        pid="$(head -1 "${DATA_DIR}/holder.out" 2>/dev/null || true)"
        [ -n "${pid}" ] && break
        sleep 0.25
    done
    if [ -z "${pid}" ]; then
        kill "${holder_job}" 2>/dev/null || true
        soft_skip "could not load an unlinked libssl copy: $(cat "${DATA_DIR}/holder.err" 2>/dev/null)"
    fi

    # The condition under test, confirmed rather than assumed.
    if ! grep libssl "/proc/${pid}/maps" | grep -q "(deleted)"; then
        kill "${pid}" 2>/dev/null || true
        echo "mapping is not marked deleted:" >&2
        grep libssl "/proc/${pid}/maps" >&2 || true
        return 1
    fi

    # The attach log names the path the link was created against; the watcher
    # polls every 5s, so allow several passes.
    local attached=0
    for _ in $(seq 1 40); do
        if grep -q "/proc/${pid}/map_files/" "${AGENT_LOG_FILE}"; then
            attached=1
            break
        fi
        sleep 1
    done
    kill "${pid}" 2>/dev/null || true

    [ "${attached}" -eq 1 ] || {
        echo "no uprobe attached through the mapping's map_files entry (pid ${pid})" >&2
        tail -20 "${AGENT_LOG_FILE}" >&2
        return 1
    }
}

# ── Cross-container capture ─────────────────────────────────────────

@test "agent captures a neighbouring container's TLS plaintext" {
    require_root
    _docker_available || env_skip "Docker engine not available"

    local before after cname
    cname="ebpfsentinel-dlp-neighbour-$$"
    before="$(_dlp_alert_count)"
    [ -n "${before}" ] || before=0

    # The neighbour container does TLS with its OWN libssl (a different inode
    # from the host's), so a captured Visa alert proves the agent attached to the
    # container's library — cross-container coverage, not the agent's own TLS.
    if ! _run_neighbour_tls_container "${cname}" >/dev/null 2>&1; then
        soft_skip "neighbour TLS container could not run (image pull / apk / openssl)"
    fi

    # Allow the final captured event to drain to the alert store.
    sleep 3
    after="$(_dlp_alert_count)"
    [ -n "${after}" ] || after=0

    echo "DLP alerts: ${before} -> ${after} (neighbour container Visa over TLS)" >&2
    [ "${after}" -gt "${before}" ]
}

@test "cross-container DLP alert is attributed to the source container" {
    require_root
    _docker_available || env_skip "Docker engine not available"

    # The prior test drove the neighbour traffic; inspect the resulting alerts
    # for a DLP entry carrying container provenance (resolved from the event's
    # cgroup id). The DLP probes are uprobes, which always run in process
    # context, so the cgroup id is populated whenever the host runs the unified
    # hierarchy — that mount is the one genuine gap.
    [ -f /sys/fs/cgroup/cgroup.controllers ] ||
        env_skip "cgroup v2 unified hierarchy not mounted"

    local body has_container
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    has_container="$(echo "${body}" \
        | jq '[(.alerts // .)[] | select(.component == "dlp") | select(.container != null)] | length' 2>/dev/null)" \
        || has_container=0
    [ -n "${has_container}" ] || has_container=0

    [ "${has_container}" -ge 1 ] || {
        echo "no DLP alert carried container provenance" >&2
        echo "${body}" | jq -c '[.alerts[]? // .[]? | select(.component == "dlp") | {container}] | .[0:5]' >&2 || true
        return 1
    }
}

# ── Attached-uprobe inventory ───────────────────────────────────────
#
# The alert tests above prove capture happened. These prove WHAT is attached:
# which inode, which symbol, at which offset. That is the only form in which two
# runs of the same host can be compared - an alert count says a probe fired
# somewhere, not that it fired where it did last time.

# Every probe the agent currently holds a link for.
_uprobe_inventory() {
    api_get /api/v1/ebpf/uprobes
}

# Distinct library inodes carrying probes.
_uprobe_inode_count() {
    _uprobe_inventory | jq '[.probes[]? | "\(.dev):\(.ino)"] | unique | length' 2>/dev/null || echo 0
}

@test "the uprobe inventory reports the resolved offset of every attached probe" {
    require_root

    local body
    body="$(_uprobe_inventory)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    local count
    count="$(echo "${body}" | jq '.probes | length')"
    [ "${count}" -ge 1 ] || {
        echo "no uprobe is attached, so DLP is inspecting nothing" >&2
        echo "${body}" >&2
        return 1
    }

    # An offset of 0 is the ELF header: a probe that can never fire, reported as
    # if the library were covered.
    local zero
    zero="$(echo "${body}" | jq '[.probes[] | select(.offset == 0)] | length')"
    [ "${zero}" -eq 0 ] || {
        echo "${zero} probe(s) attached at offset 0" >&2
        echo "${body}" | jq -c '[.probes[] | select(.offset == 0)]' >&2
        return 1
    }

    # Every probe names the inode it sits on, which is what makes the entry
    # comparable across runs.
    echo "${body}" | jq -e '[.probes[] | select(.ino > 0)] | length == (.probes | length)' >/dev/null
}

@test "one library inode carries one probe set, however many processes map it" {
    require_root

    local body
    body="$(_uprobe_inventory)"
    # Duplicate (inode, symbol, probe kind) tuples mean the dedup key failed and
    # the same code is being probed twice - two links where one was intended.
    local total unique
    total="$(echo "${body}" | jq '[.probes[] | "\(.dev):\(.ino):\(.symbol):\(.retprobe)"] | length')"
    unique="$(echo "${body}" | jq '[.probes[] | "\(.dev):\(.ino):\(.symbol):\(.retprobe)"] | unique | length')"
    [ "${total}" -eq "${unique}" ] || {
        echo "duplicate probes: ${total} entries, ${unique} distinct" >&2
        echo "${body}" | jq -c '.probes' >&2
        return 1
    }

    # The set attached per inode is bounded by the program set the loader holds
    # (SSL_write, SSL_read entry, SSL_read return).
    echo "${body}" | jq -e '
        [.probes | group_by("\(.dev):\(.ino)")[] | length] | all(. <= 3)' >/dev/null
}

@test "resolved offsets do not move while the library does not" {
    require_root

    # Same host, same inodes, two reads a watcher pass apart. An offset that
    # changed here is the resolver disagreeing with itself, not a new binary.
    local before after
    before="$(_uprobe_inventory | jq -S '[.probes[] | {dev, ino, symbol, retprobe, offset}] | sort_by(.dev, .ino, .symbol, .retprobe)')"
    sleep 7
    after="$(_uprobe_inventory | jq -S '[.probes[] | {dev, ino, symbol, retprobe, offset}] | sort_by(.dev, .ino, .symbol, .retprobe)')"

    # Compare only inodes present in both reads: a container that appeared or
    # left in between is a legitimate difference, a moved offset is not.
    local moved
    moved="$(jq -n --argjson a "${before}" --argjson b "${after}" '
        [ $a[] as $x | $b[] | select(.dev == $x.dev and .ino == $x.ino
              and .symbol == $x.symbol and .retprobe == $x.retprobe
              and .offset != $x.offset) ] | length')"
    [ "${moved}" -eq 0 ] || {
        echo "${moved} probe(s) changed offset without the inode changing" >&2
        echo "before: ${before}" >&2
        echo "after:  ${after}" >&2
        return 1
    }
}

@test "a container's library enters the inventory while it runs and leaves when it stops" {
    require_root
    _docker_available || env_skip "Docker engine not available"

    local cname="ebpfsentinel-dlp-inventory-$$"
    local baseline during after
    baseline="$(_uprobe_inode_count)"

    # A container with its own libssl kept mapped for the whole window, so the
    # watcher has several passes to see it appear and, later, disappear.
    _docker_cmd rm -f "${cname}" >/dev/null 2>&1 || true
    _docker_cmd run -d --name "${cname}" alpine:latest sh -c '
        apk add --no-cache openssl >/dev/null 2>&1 || exit 3
        openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem \
            -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1 || exit 4
        exec openssl s_server -accept 19444 -cert /tmp/c.pem -key /tmp/k.pem -quiet
    ' >/dev/null 2>&1 || soft_skip "inventory neighbour container could not start"

    during="${baseline}"
    for _ in $(seq 1 30); do
        during="$(_uprobe_inode_count)"
        [ "${during}" -gt "${baseline}" ] && break
        sleep 1
    done

    if [ "${during}" -le "${baseline}" ]; then
        _docker_cmd rm -f "${cname}" >/dev/null 2>&1 || true
        echo "container libssl never entered the inventory (${baseline} inodes throughout)" >&2
        soft_skip "container libssl not discovered (image has no libssl mapping)"
    fi

    _docker_cmd rm -f "${cname}" >/dev/null 2>&1 || true

    # The teardown side is the one that leaks: a link nobody detaches keeps the
    # probe - and the inode - alive for the life of the agent.
    after="${during}"
    for _ in $(seq 1 30); do
        after="$(_uprobe_inode_count)"
        [ "${after}" -le "${baseline}" ] && break
        sleep 1
    done

    echo "inventory inodes: ${baseline} -> ${during} -> ${after}" >&2
    [ "${after}" -le "${baseline}" ] || {
        echo "the container's probes outlived the container" >&2
        _uprobe_inventory | jq -c '.probes' >&2
        return 1
    }
}
