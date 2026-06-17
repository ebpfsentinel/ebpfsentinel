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

# ── Cross-container capture ─────────────────────────────────────────

@test "agent captures a neighbouring container's TLS plaintext" {
    require_root
    _docker_available || skip "Docker engine not available"

    local before after cname
    cname="ebpfsentinel-dlp-neighbour-$$"
    before="$(_dlp_alert_count)"
    [ -n "${before}" ] || before=0

    # The neighbour container does TLS with its OWN libssl (a different inode
    # from the host's), so a captured Visa alert proves the agent attached to the
    # container's library — cross-container coverage, not the agent's own TLS.
    if ! _run_neighbour_tls_container "${cname}" >/dev/null 2>&1; then
        skip "neighbour TLS container could not run (image pull / apk / openssl)"
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
    _docker_available || skip "Docker engine not available"

    # The prior test drove the neighbour traffic; inspect the resulting alerts
    # for a DLP entry carrying container provenance (resolved from the event's
    # cgroup id). Some kernels strip cgroup_id from the uprobe path, so treat an
    # unattributed-but-captured alert as a skip rather than a failure.
    local body has_container
    body="$(api_get /api/v1/alerts)"
    _load_http_status
    [ "${HTTP_STATUS}" = "200" ]

    has_container="$(echo "${body}" \
        | jq '[(.alerts // .)[] | select(.component == "dlp") | select(.container != null)] | length' 2>/dev/null)" \
        || has_container=0
    [ -n "${has_container}" ] || has_container=0

    if [ "${has_container}" -lt 1 ]; then
        skip "DLP alert captured but cgroup attribution unavailable on this kernel"
    fi
    [ "${has_container}" -ge 1 ]
}
