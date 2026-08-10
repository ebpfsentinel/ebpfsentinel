#!/usr/bin/env bats
# 54-container-cgroup-enrichment.bats — Container cgroup → identity surface.
#
# Asserts that with the cgroup resolver + Docker enricher enabled the
# agent (a) exposes the container resolver Prometheus surface and (b)
# learns at least one cgroup → container mapping when a Docker container
# generates traffic that triggers a tc-ids signature.
#
# Coverage matrix maps:
#
#   * cgroup resolver — container_resolver_cache_{hits,misses,errors}
#     counters are registered when container.resolver.enabled=true and
#     advance once a containerised process emits events.
#   * Docker enricher — docker.enabled=true ensures the agent attempts
#     to talk to /var/run/docker.sock; on success the enricher records
#     name/image metadata against the resolved cgroup.
#
# Attribution path: the container dials a server in the test netns through
# the inspected veth, so its outbound request crosses the veth EGRESS hook.
# With ids.inspect_egress enabled the IDS classifier runs there too, and on
# egress the kernel has bound the originating socket to the skb, so
# bpf_skb_cgroup_id yields the container's cgroup. The dst_port rule matches
# that outbound request and the alert is emitted with the container identity
# attached.
#
# OSS scope: container (Docker cgroup) enrichment, plus the cgroup → tenant
# datapath mechanism (TENANT_CGROUP_MAP and its kernel lookup). Kubernetes pod
# enrichment is exercised by suite 10. Deciding *which* tenant owns a cgroup —
# label conventions, container lifecycle, map upkeep — is an enterprise feature
# and is tested in the enterprise repo; here the map is written by hand.

load '../lib/helpers'
load '../lib/ebpf_helpers'

# Probe port the test netns server listens on and the IDS src_port rule
# matches. Kept in one place so the fixture and the traffic agree.
PROBE_PORT=65501

# ── Probe listener (test netns) ─────────────────────────────────────

# Spawn a re-listening TCP server inside the test netns so every container
# connection to ${EBPF_NS_IP}:${PROBE_PORT} is accepted and replied to.
_start_probe_listener() {
    ip netns exec "${EBPF_TEST_NS}" sh -c \
        "while true; do nc -l -p ${PROBE_PORT} -w 2 >/dev/null 2>&1 || sleep 0.2; done" &
    PROBE_LISTENER_PID=$!
    export PROBE_LISTENER_PID
}

_stop_probe_listener() {
    if [ -n "${PROBE_LISTENER_PID:-}" ]; then
        kill "${PROBE_LISTENER_PID}" 2>/dev/null || true
        pkill -P "${PROBE_LISTENER_PID}" 2>/dev/null || true
    fi
    # Belt-and-braces: clear any stray netns listener.
    ip netns exec "${EBPF_TEST_NS}" pkill -f "nc -l -p ${PROBE_PORT}" 2>/dev/null || true
}

# ── Tenant cgroup map (datapath mechanism) ──────────────────────────

# Tenant id written into TENANT_CGROUP_MAP. Any non-zero value works: the
# probe rule is global (tenant 0), and a tenant-scoped lookup falls back to
# the global rule, so the alert still fires whatever tenant is resolved.
TENANT_PROBE_ID=7

# Cgroup the probe traffic is issued from. Created empty under the unified
# hierarchy so its id belongs to this suite alone and cannot collide with a
# live workload's.
TENANT_CGROUP_DIR="/sys/fs/cgroup/ebpfsentinel-tenant-probe"

# Prometheus mirror of tc-ids metric index 5 (cgroup → tenant resolutions).
CGROUP_RESOLVED_LABELS='{interface="IDS_METRICS",action="cgroup_resolved"}'

# Little-endian hex byte string for bpftool's `key hex` / `value hex`.
_le_hex() {
    local value="$1" width="$2" out="" i
    for ((i = 0; i < width; i++)); do
        out+="$(printf '%02x ' $(((value >> (8 * i)) & 0xff)))"
    done
    echo "${out% }"
}

# Kernel object names are capped at 15 characters, so TENANT_CGROUP_MAP
# surfaces as TENANT_CGROUP_M. Match on the prefix and take the first id:
# the map is shared by every tc-ids attachment, so there is only ever one.
_tenant_cgroup_map_id() {
    bpftool -j map show 2>/dev/null |
        jq -r 'first(.[] | select((.name // "") | startswith("TENANT_CGROUP")) | .id) // empty'
}

# Create the probe cgroup and echo its id. The cgroup v2 id the kernel
# reports to bpf_get_current_cgroup_id is the directory's inode number.
# Attribution reads the cgroup v2 id of the emitting task. A host running the
# legacy v1 hierarchy exposes no unified controller file and has no such id, so
# nothing downstream can be attributed — the only genuine environment gap here.
_require_cgroup_v2() {
    [ -f /sys/fs/cgroup/cgroup.controllers ] ||
        env_skip "cgroup v2 unified hierarchy not mounted"
}

_probe_cgroup_id() {
    [ -f /sys/fs/cgroup/cgroup.controllers ] || return 1
    mkdir -p "${TENANT_CGROUP_DIR}" 2>/dev/null || return 1
    stat -c %i "${TENANT_CGROUP_DIR}" 2>/dev/null
}

# Dial the probe port a few times from inside the probe cgroup. The request
# leg leaves through the inspected veth on egress, where the sending task is
# still current, so tc-ids can read its cgroup.
_probe_from_cgroup() {
    local i
    for i in 1 2 3 4 5; do
        sh -c "echo \$\$ > '${TENANT_CGROUP_DIR}/cgroup.procs' 2>/dev/null || exit 0
               (echo probe; sleep 0.1) | nc -w 1 '${EBPF_NS_IP}' '${PROBE_PORT}' >/dev/null 2>&1 || true" || true
    done
}

_cgroup_resolved_count() {
    local value
    value="$(get_metrics_value ebpfsentinel_packets_total "${CGROUP_RESOLVED_LABELS}" 2>/dev/null)"
    echo "${value:-0}"
}

# Poll until the resolution counter climbs past `floor`. The kernel metrics
# loop mirrors the map every 10s, so a single read proves nothing.
_wait_cgroup_resolved_above() {
    local floor="$1" max="${2:-30}" i value=0
    for ((i = 0; i < max; i++)); do
        value="$(_cgroup_resolved_count)"
        if [ "${value%%.*}" -gt "${floor}" ]; then
            echo "${value}"
            return 0
        fi
        sleep 1
    done
    echo "${value}"
    return 1
}

# True when a bpftool lookup dump holds the probe tenant id, in either the
# BTF-decoded form (`"value": 7`) or the untyped hex form (`07 00 00 00`).
_lookup_holds_probe_tenant() {
    local dump="$1"
    [ "$(echo "${dump}" | jq -r '.value // empty' 2>/dev/null)" = "${TENANT_PROBE_ID}" ] && return 0
    echo "${dump}" | grep -q "$(_le_hex "${TENANT_PROBE_ID}" 4)"
}

_tenant_cgroup_cleanup() {
    local map_id="${1:-}" cgroup_id="${2:-}"
    if [ -n "${map_id}" ] && [ -n "${cgroup_id}" ]; then
        # shellcheck disable=SC2046  # the hex bytes must expand to separate args
        bpftool map delete id "${map_id}" key hex $(_le_hex "${cgroup_id}" 8) >/dev/null 2>&1 || true
    fi
    rmdir "${TENANT_CGROUP_DIR}" 2>/dev/null || true
}

# ── Docker availability ─────────────────────────────────────────────

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

setup_file() {
    require_root
    require_kernel 5 17
    require_tool curl
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-container-$$"
    mkdir -p "${DATA_DIR}"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-container.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    # Re-listening TCP server in the test netns on the probe port. A client
    # that dials ${EBPF_NS_IP}:${PROBE_PORT} through the test veth gets a
    # reply, so both legs cross a tc-ids hook: the request on egress (where
    # the originating socket is still bound to the skb, so the cgroup is
    # recoverable) and the reply on ingress.
    _start_probe_listener
}

teardown_file() {
    if _docker_available; then
        _docker_cmd rm -f "ebpfsentinel-cgroup-probe-$$" >/dev/null 2>&1 || true
    fi
    _stop_probe_listener 2>/dev/null || true
    rmdir "${TENANT_CGROUP_DIR}" 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-container-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Resolver surface ───────────────────────────────────────────────

@test "container resolver metrics are exposed when enabled" {
    local metrics
    metrics="$(curl -sf --max-time 5 "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || true
    [ -n "${metrics}" ]

    local missing=()
    for m in \
        ebpfsentinel_container_resolver_cache_hits \
        ebpfsentinel_container_resolver_cache_misses \
        ebpfsentinel_container_resolver_errors; do
        if ! echo "${metrics}" | grep -qE "^${m}(_total)?\b"; then
            missing+=("${m}")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "container resolver metrics missing from /metrics:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        return 1
    fi
}

# ── Docker-driven cgroup resolution ────────────────────────────────

@test "Docker container traffic advances container resolver counters" {
    _docker_available || env_skip "Docker engine not available"
    _require_cgroup_v2

    # Snapshot resolver cache miss counter before the workload.
    local before
    before="$(get_metrics_value ebpfsentinel_container_resolver_cache_misses_total 2>/dev/null)"
    [ -n "${before}" ] || before=0

    local cname="ebpfsentinel-cgroup-probe-$$"
    _docker_cmd rm -f "${cname}" >/dev/null 2>&1 || true

    # Trigger the ids-container-probe signature on TCP/65501 from inside a
    # container so the resolver maps the emitting cgroup_id → container_id.
    _docker_cmd run --rm --name "${cname}" \
        --network host \
        busybox:latest sh -c \
            'for i in 1 2 3 4 5; do
                (echo probe; sleep 0.1) | nc -w 1 '"${EBPF_NS_IP}"' '"${PROBE_PORT}"' >/dev/null 2>&1 || true
             done; sleep 1' >/dev/null 2>&1 || soft_skip "busybox container could not run"

    sleep 2

    local after
    after="$(get_metrics_value ebpfsentinel_container_resolver_cache_misses_total 2>/dev/null)"
    [ -n "${after}" ] || after=0

    # The egress hook carries the emitting task's cgroup and is attached
    # whenever the resolver is on, so a container that generated matching
    # traffic must have produced at least one resolver lookup.
    [ "$(echo "${after} > ${before}" | bc -l 2>/dev/null)" = "1" ] || {
        echo "container resolver observed no miss (${before} → ${after})" >&2
        echo "resolver errors: $(get_metrics_value ebpfsentinel_container_resolver_errors_total 2>/dev/null)" >&2
        return 1
    }
}

# ── REST AlertResponse container surface ───────────────────────────

@test "alerts REST surface exposes container identity" {
    _docker_available || env_skip "Docker engine not available"
    _require_cgroup_v2

    local cname="ebpfsentinel-cgroup-alert-$$"
    _docker_cmd rm -f "${cname}" >/dev/null 2>&1 || true

    # Drive the ids-container-probe signature (TCP/65501) from inside a
    # container so tc-ids emits an alert carrying the resolved cgroup_id, which
    # the resolver maps to a container identity surfaced on the REST DTO.
    _docker_cmd run --rm --name "${cname}" \
        --network host \
        busybox:latest sh -c \
            'for i in 1 2 3 4 5; do
                (echo probe; sleep 0.1) | nc -w 1 '"${EBPF_NS_IP}"' '"${PROBE_PORT}"' >/dev/null 2>&1 || true
             done; sleep 1' >/dev/null 2>&1 || soft_skip "busybox container could not run"

    sleep 2

    # Pull recent alerts and look for one carrying a container identity with the
    # full {kind,runtime,id,cgroup_path} surface.
    local alerts
    alerts="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/api/v1/alerts?limit=200" 2>/dev/null)" || true
    [ -n "${alerts}" ] || soft_skip "alerts endpoint returned nothing"

    local matched
    matched="$(echo "${alerts}" | jq '[.alerts[]
        | select(.container != null)
        | select(.container.kind == "container"
                 and (.container.runtime | length) > 0
                 and (.container.id | length) > 0
                 and (.container.cgroup_path | length) > 0)] | length' 2>/dev/null)" || matched=0

    [ "${matched:-0}" -ge 1 ] || {
        echo "no alert carried a complete container identity" >&2
        echo "${alerts}" | jq -c '[.alerts[] | {component, container}] | .[0:5]' >&2 || true
        return 1
    }
}

# ── cgroup → tenant datapath ───────────────────────────────────────

@test "TENANT_CGROUP_MAP is present in the loaded IDS datapath" {
    require_tool bpftool
    require_tool jq

    local map_id
    map_id="$(_tenant_cgroup_map_id)"
    [ -n "${map_id}" ]

    # Geometry is the contract between the kernel program and the userspace
    # manager: u64 cgroup id → u32 tenant id, one entry per live container.
    # bpftool renamed these keys (key_size/value_size before v7, bytes_key/
    # bytes_value after), so read whichever the installed version emits — a
    # missing key would otherwise read as a geometry change that never happened.
    local geometry
    geometry="$(bpftool -j map show id "${map_id}" 2>/dev/null |
        jq -r '"\(.bytes_key // .key_size) \(.bytes_value // .value_size) \(.max_entries)"')"
    [ "${geometry}" = "8 4 4096" ]
}

@test "tenant cgroup entry survives a write/read round-trip" {
    require_tool bpftool
    require_tool jq

    local map_id
    map_id="$(_tenant_cgroup_map_id)"
    [ -n "${map_id}" ]

    local cgroup_id
    cgroup_id="$(_probe_cgroup_id)" ||
        env_skip "cgroup v2 unified hierarchy not mounted"
    [ -n "${cgroup_id}" ]

    # shellcheck disable=SC2046  # the hex bytes must expand to separate args
    run bpftool map update id "${map_id}" \
        key hex $(_le_hex "${cgroup_id}" 8) \
        value hex $(_le_hex "${TENANT_PROBE_ID}" 4)
    [ "${status}" -eq 0 ]

    # shellcheck disable=SC2046
    run bpftool map lookup id "${map_id}" key hex $(_le_hex "${cgroup_id}" 8)
    [ "${status}" -eq 0 ]
    # The map carries BTF, so bpftool decodes the entry to typed JSON instead
    # of printing raw bytes. Read the decoded value, and fall back to the hex
    # form for a bpftool that has no type information to work from.
    _lookup_holds_probe_tenant "${output}" || {
        echo "lookup returned a value the write never put there" >&2
        echo "  map id   : ${map_id}" >&2
        echo "  cgroup id: ${cgroup_id} (key $(_le_hex "${cgroup_id}" 8))" >&2
        echo "  expected : $(_le_hex "${TENANT_PROBE_ID}" 4)" >&2
        echo "  lookup   : ${output}" >&2
        _tenant_cgroup_cleanup "${map_id}" "${cgroup_id}"
        return 1
    }

    _tenant_cgroup_cleanup "${map_id}" "${cgroup_id}"
}

@test "egress traffic from a mapped cgroup resolves its tenant" {
    require_tool bpftool
    require_tool jq
    require_tool nc

    local map_id
    map_id="$(_tenant_cgroup_map_id)"
    [ -n "${map_id}" ]

    local cgroup_id
    cgroup_id="$(_probe_cgroup_id)" ||
        env_skip "cgroup v2 unified hierarchy not mounted"

    local before
    before="$(_cgroup_resolved_count)"

    # shellcheck disable=SC2046
    bpftool map update id "${map_id}" \
        key hex $(_le_hex "${cgroup_id}" 8) \
        value hex $(_le_hex "${TENANT_PROBE_ID}" 4)

    _probe_from_cgroup

    local after
    if ! after="$(_wait_cgroup_resolved_above "${before%%.*}" 30)"; then
        _tenant_cgroup_cleanup "${map_id}" "${cgroup_id}"
        echo "cgroup tenant resolution did not advance (${before} → ${after})" >&2
        return 1
    fi

    _tenant_cgroup_cleanup "${map_id}" "${cgroup_id}"
}

@test "removing a cgroup entry stops tenant resolution" {
    require_tool bpftool
    require_tool jq
    require_tool nc

    local map_id
    map_id="$(_tenant_cgroup_map_id)"
    [ -n "${map_id}" ]

    local cgroup_id
    cgroup_id="$(_probe_cgroup_id)" ||
        env_skip "cgroup v2 unified hierarchy not mounted"

    # Cgroup ids are recycled once a cgroup is destroyed, so a stale entry
    # would attribute the next container's traffic to the wrong tenant. The
    # removal path is what keeps that from happening.
    _tenant_cgroup_cleanup "${map_id}" "${cgroup_id}"
    mkdir -p "${TENANT_CGROUP_DIR}"

    # A cleanup that quietly failed would make the rest of this test assert
    # nothing, so prove the entry is gone before drawing any conclusion from
    # the counter. Re-read the id: recreating the directory can hand out a
    # different inode, and only the live one is what the probe will use.
    cgroup_id="$(stat -c %i "${TENANT_CGROUP_DIR}")"
    _tenant_cgroup_cleanup "${map_id}" "${cgroup_id}"
    # shellcheck disable=SC2046
    run bpftool map lookup id "${map_id}" key hex $(_le_hex "${cgroup_id}" 8)
    if [ "${status}" -eq 0 ] && _lookup_holds_probe_tenant "${output}"; then
        echo "cgroup ${cgroup_id} still maps to the probe tenant after removal" >&2
        echo "${output}" >&2
        return 1
    fi

    # Let any resolution still in flight land before the snapshot.
    sleep 12
    local before
    before="$(_cgroup_resolved_count)"

    _probe_from_cgroup

    # Two full metric poll intervals: enough for a resolution to surface if
    # the entry were still live.
    sleep 25
    local after
    after="$(_cgroup_resolved_count)"

    rmdir "${TENANT_CGROUP_DIR}" 2>/dev/null || true

    if [ "${after%%.*}" -ne "${before%%.*}" ]; then
        echo "tenant resolved from an unmapped cgroup (${before} → ${after})" >&2
        return 1
    fi
}
