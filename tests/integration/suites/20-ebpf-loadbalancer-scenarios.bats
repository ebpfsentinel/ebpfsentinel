#!/usr/bin/env bats
# 20-ebpf-loadbalancer-scenarios.bats - Load balancer eBPF scenario tests
# Requires: root, kernel >= 6.12, bpftool, ncat, python3
#
# The spread tests send UDP datagrams from the client namespace to a service
# on the host side, which the agent rewrites to backends in a second
# namespace reached through the host. Each datagram leaves from a socket of
# its own, so each is a new flow the algorithm places; the backends count
# what reaches each port. The path is one way, so no reply has to be
# translated back, and the round trip is suite 139's.

load '../lib/helpers'
load '../lib/ebpf_helpers'

setup_file() {
    require_root
    require_kernel 6 12
    require_tool bpftool
    require_tool ncat

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-lb-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns
    if _spread_lane; then
        require_tool python3
        _create_backend_ns || return 1
    fi

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-loadbalancer.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    _destroy_backend_ns
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-lb-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Backends behind the host ─────────────────────────────────────

LB_BE_NS="lb-backend-ns"
LB_BE_HOST_IF="veth-lbbe0"
LB_BE_NS_IF="veth-lbbe1"
LB_BE_HOST_IP="10.201.0.1"
LB_BE_ADDR="10.201.0.2"
LB_FORWARD_SAVED="${BATS_FILE_TMPDIR:-/tmp}/lb-ip-forward"

# The spread is read where the suite owns both namespaces; on the VM lanes
# the client is another machine, and suite 139 reads the spread there.
_spread_lane() {
    [ "${EBPF_2VM_MODE:-false}" != "true" ] && [ "${EBPF_3VM_MODE:-false}" != "true" ]
}

# _create_backend_ns - a namespace holding the backends, reached from the
# host through a veth pair. The agent's DNAT routes a rewritten datagram
# with a FIB lookup, which answers only with forwarding on, and redirects it
# into the host veth, whose peer receives redirected frames only while it
# carries an XDP program of its own.
_create_backend_ns() {
    _destroy_backend_ns
    sysctl -n net.ipv4.ip_forward >"$LB_FORWARD_SAVED"
    sysctl -qw net.ipv4.ip_forward=1
    ip netns add "$LB_BE_NS"
    ip link add "$LB_BE_HOST_IF" type veth peer name "$LB_BE_NS_IF"
    ip link set "$LB_BE_NS_IF" netns "$LB_BE_NS"
    ip addr add "${LB_BE_HOST_IP}/24" dev "$LB_BE_HOST_IF"
    ip link set "$LB_BE_HOST_IF" up
    ip netns exec "$LB_BE_NS" ip addr add "${LB_BE_ADDR}/24" dev "$LB_BE_NS_IF"
    ip netns exec "$LB_BE_NS" ip link set "$LB_BE_NS_IF" up
    ip netns exec "$LB_BE_NS" ip link set lo up
    ip netns exec "$LB_BE_NS" ip route add default via "$LB_BE_HOST_IP"
    local obj="${EBPF_PROGRAM_DIR:-${PROJECT_ROOT}/target/bpfel-unknown-none/release}/xdp-pass"
    [ -f "$obj" ] || {
        echo "no xdp-pass object at ${obj}: the backend veth would drop every redirected frame" >&2
        return 1
    }
    ip netns exec "$LB_BE_NS" ip link set dev "$LB_BE_NS_IF" xdpdrv obj "$obj" sec xdp 2>/dev/null \
        || ip netns exec "$LB_BE_NS" ip link set dev "$LB_BE_NS_IF" xdp obj "$obj" sec xdp || {
            echo "xdp-pass did not attach to ${LB_BE_NS_IF}" >&2
            return 1
        }
    # The neighbour is resolved before the first datagram, so the FIB
    # lookup answers with both MACs instead of handing it to the stack.
    ping -c1 -W2 "$LB_BE_ADDR" >/dev/null || {
        echo "the host does not reach ${LB_BE_ADDR}" >&2
        return 1
    }
}

_destroy_backend_ns() {
    ip netns del "$LB_BE_NS" 2>/dev/null || true
    ip link delete "$LB_BE_HOST_IF" 2>/dev/null || true
    if [ -s "$LB_FORWARD_SAVED" ]; then
        sysctl -qw "net.ipv4.ip_forward=$(cat "$LB_FORWARD_SAVED")"
        rm -f "$LB_FORWARD_SAVED"
    fi
}

# _udp_service <id> <listen_port> <algo> <port:weight:enabled>... - a UDP
# service whose backends are ports of the backend namespace.
_udp_service() {
    local id="$1" listen="$2" algo="$3" backends="" be port weight enabled
    shift 3
    for be in "$@"; do
        IFS=':' read -r port weight enabled <<<"$be"
        [ -z "$backends" ] || backends+=","
        backends+="{\"id\":\"b${port}\",\"addr\":\"${LB_BE_ADDR}\",\"port\":${port},\"weight\":${weight},\"enabled\":${enabled}}"
    done
    api_post /api/v1/lb/services \
        "{\"id\":\"${id}\",\"name\":\"${id}\",\"protocol\":\"udp\",\"listen_port\":${listen},\"algorithm\":\"${algo}\",\"enabled\":true,\"backends\":[${backends}]}" \
        >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "201" ] || {
        echo "creating ${id} answered ${HTTP_STATUS}" >&2
        return 1
    }
    # The service reaches the kernel maps on the next sync.
    sleep 2
}

# _spread <listen_port> <flows> <out> <backend port>... - send one datagram
# per flow to the service and write the backend port each one reached, one
# line per datagram, to <out>.
_spread() {
    local listen="$1" flows="$2" out="$3" listener port i
    shift 3
    local ports
    ports="$(IFS=,; echo "$*")"
    ip netns exec "$LB_BE_NS" python3 -c '
import select, socket, sys, time
out, ports, deadline = sys.argv[1], sys.argv[2].split(","), time.time() + float(sys.argv[3])
socks = []
for p in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", int(p)))
    socks.append(s)
with open(out, "w", buffering=1) as f:
    while time.time() < deadline:
        ready, _, _ = select.select(socks, [], [], 0.2)
        for s in ready:
            s.recvfrom(64)
            f.write("%d\n" % s.getsockname()[1])
' "$out" "$ports" 60 &
    listener=$!
    for port in "$@"; do
        for i in $(seq 1 20); do
            ip netns exec "$LB_BE_NS" ss -Hlun "sport = :${port}" | grep -q . && break
            sleep 0.2
        done
    done
    ip netns exec "$EBPF_TEST_NS" python3 -c '
import socket, sys
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for _ in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"x", (host, port))
    s.close()
' "$EBPF_HOST_IP" "$listen" "$flows"
    sleep 1
    kill "$listener" 2>/dev/null || true
    wait "$listener" 2>/dev/null || true
}

# _reached <out> <port> - datagrams that reached one backend port.
_reached() {
    grep -cx "$2" "$1" || true
}

# ── XDP program attachment ───────────────────────────────────────

@test "XDP loadbalancer program attached to interface" {
    require_root
    require_tool bpftool

    sleep 2
    local output
    output="$(bpftool net show 2>&1)" || true
    assert_contains "$output" "$EBPF_VETH_HOST"
}

# ── LB status ────────────────────────────────────────────────────

@test "LB status returns enabled via API" {
    require_root

    local body
    body="$(api_get /api/v1/lb/status)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    local enabled
    enabled="$(echo "$body" | jq -r '.enabled' 2>/dev/null)" || true
    [ "$enabled" = "true" ]
}

# ── Dynamic service management ───────────────────────────────────

@test "LB services initially empty" {
    require_root

    local body
    body="$(api_get /api/v1/lb/services)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    assert_json_array_length "$body" '.' '0'
}

@test "LB service creation syncs to eBPF maps" {
    require_root

    # Create a TCP service on port 9500 with one backend
    local svc='{"id":"lb-ebpf-001","name":"test-svc","protocol":"tcp","listen_port":9500,"algorithm":"round_robin","backends":[{"id":"be-1","addr":"10.200.0.2","port":8080,"weight":1,"enabled":true}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    _load_http_status

    [ "$HTTP_STATUS" = "201" ]

    # Wait for eBPF map sync
    sleep 2

    # Verify service is listed
    body="$(api_get /api/v1/lb/services)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    assert_json_array_length "$body" '.' '1'
}

@test "LB service detail shows backend" {
    require_root

    local body
    body="$(api_get /api/v1/lb/services/lb-ebpf-001)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    assert_json_field "$body" '.id' 'lb-ebpf-001'
    assert_json_array_length "$body" '.backends' '1'

    # Its one enabled backend is counted healthy under the service's id.
    local value
    value="$(get_metrics_value ebpfsentinel_lb_backends_healthy '{service="lb-ebpf-001"}')" || value=""
    [ "${value:-}" = "1" ] || {
        echo "lb_backends_healthy for lb-ebpf-001: '${value}'" >&2
        return 1
    }
}

@test "LB service deletion removes from eBPF maps" {
    require_root

    api_delete /api/v1/lb/services/lb-ebpf-001 >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "204" ]

    # Wait for eBPF map sync
    sleep 2

    local body
    body="$(api_get /api/v1/lb/services)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    assert_json_array_length "$body" '.' '0'
}

# ── CRUD lifecycle (round-robin service) ─────────────────────────

@test "LB service CRUD - create TCP service" {
    require_root

    # listen_port must not collide with the agent's own management ports
    # (http 8080 / metrics 9090 / grpc 50051): the XDP load balancer keys on
    # listen_port and would otherwise hijack the management API's traffic,
    # wedging every subsequent API call.
    local svc='{"id":"test-svc","name":"test-svc","protocol":"tcp","listen_port":18080,"algorithm":"round_robin","backends":[{"id":"be-1","addr":"10.200.0.1","port":8080,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local id
    id="$(echo "$body" | jq -r '.id // empty' 2>/dev/null)" || true
    [ "$id" = "test-svc" ]
}

@test "LB service detail accessible" {
    require_root

    local body
    body="$(api_get /api/v1/lb/services/test-svc)"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ]
    assert_json_field "$body" '.id' 'test-svc'
}

@test "LB service CRUD - delete service" {
    require_root

    api_delete /api/v1/lb/services/test-svc >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "204" ]

    sleep 1

    # Confirm deletion
    api_get /api/v1/lb/services/test-svc >/dev/null || true
    _load_http_status
    [ "$HTTP_STATUS" = "404" ]
}

@test "LB weighted algorithm via API" {
    require_root

    local svc='{"id":"weighted-svc","name":"weighted-svc","protocol":"tcp","listen_port":8081,"algorithm":"weighted","backends":[{"id":"be-1","addr":"10.200.0.2","port":8081,"weight":3},{"id":"be-2","addr":"10.200.0.3","port":8081,"weight":1}]}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    _load_http_status

    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]
    local algo
    algo="$(echo "$body" | jq -r '.algorithm // empty' 2>/dev/null)" || true
    [ "$algo" = "weighted" ]

    # Cleanup
    api_delete /api/v1/lb/services/weighted-svc >/dev/null || true
}

# ── Extended LB algorithm & protocol tests ────────────────────────

@test "round robin places new flows on every backend in turn" {
    require_root
    _spread_lane || env_skip "per-backend spread is read on the local lane; the VM lanes read it in suite 139"

    _udp_service lb-rr-spread 19089 round_robin 9091:1:true 9092:1:true 9093:1:true
    _spread 19089 30 "${DATA_DIR}/rr.txt" 9091 9092 9093
    api_delete /api/v1/lb/services/lb-rr-spread >/dev/null 2>&1 || true

    local port n total=0
    for port in 9091 9092 9093; do
        n="$(_reached "${DATA_DIR}/rr.txt" "$port")"
        total=$((total + n))
        [ "$n" -ge 5 ] || {
            echo "backend ${port} received ${n} of 30 flows, round robin gives it 10" >&2
            sort "${DATA_DIR}/rr.txt" | uniq -c >&2
            return 1
        }
    done
    [ "$total" -eq 30 ] || {
        echo "${total} of 30 datagrams reached a backend" >&2
        return 1
    }
}

@test "weighted algorithm distributes traffic by weight" {
    require_root
    _spread_lane || env_skip "per-backend spread is read on the local lane; the VM lanes read it in suite 139"

    _udp_service lb-weighted-001 19090 weighted 9091:3:true 9092:1:true
    _spread 19090 100 "${DATA_DIR}/weighted.txt" 9091 9092
    api_delete /api/v1/lb/services/lb-weighted-001 >/dev/null 2>&1 || true

    local heavy light
    heavy="$(_reached "${DATA_DIR}/weighted.txt" 9091)"
    light="$(_reached "${DATA_DIR}/weighted.txt" 9092)"
    echo "# weighted spread: 9091=${heavy} 9092=${light}" >&3
    [ $((heavy + light)) -eq 100 ] || {
        echo "$((heavy + light)) of 100 datagrams reached a backend" >&2
        return 1
    }
    # Expected 75/25; the bounds sit about four standard deviations out.
    [ "$heavy" -ge 58 ] && [ "$heavy" -le 92 ] || {
        echo "9091 took ${heavy} of 100 flows, weight 3 of 4 gives it about 75" >&2
        return 1
    }
}

@test "ip_hash algorithm configured via API" {
    require_root

    local svc='{"id":"lb-iphash-001","name":"iphash-test","protocol":"tcp","listen_port":9093,"algorithm":"ip_hash","backends":[{"id":"b1","addr":"10.200.0.1","port":9094,"enabled":true}],"enabled":true}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Read the service back: a handler that answered 201 and fell back to
    # its default algorithm would serve round_robin here.
    local algorithm
    body="$(api_get /api/v1/lb/services/lb-iphash-001)"
    _load_http_status
    algorithm="$(echo "$body" | jq -r '.algorithm' 2>/dev/null)" || algorithm=""
    # The delete below sets HTTP_STATUS again, so the read's answer is kept.
    local read_status="$HTTP_STATUS"

    api_delete /api/v1/lb/services/lb-iphash-001 >/dev/null 2>&1 || true

    [ "$read_status" = "200" ] || {
        echo "the created service could not be read back (${read_status}): ${body}" >&2
        return 1
    }
    [ "$algorithm" = "ip_hash" ] || {
        echo "the service reads algorithm '${algorithm}' after being created with ip_hash" >&2
        return 1
    }
}

@test "UDP service configured and listed" {
    require_root

    local svc='{"id":"lb-udp-001","name":"udp-test","protocol":"udp","listen_port":5353,"algorithm":"round_robin","backends":[{"id":"b1","addr":"10.200.0.1","port":5354,"enabled":true}],"enabled":true}'
    local body
    body="$(api_post /api/v1/lb/services "$svc")"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]

    # Verify it appears in list
    body="$(api_get /api/v1/lb/services)"
    _load_http_status
    [ "$HTTP_STATUS" = "200" ]
    local found
    found="$(echo "$body" | jq '[.[] | select(.id == "lb-udp-001")] | length' 2>/dev/null)" || found="0"
    [ "${found:-0}" -ge 1 ]

    api_delete /api/v1/lb/services/lb-udp-001 >/dev/null 2>&1 || true
}

@test "unhealthy backend is skipped in selection" {
    require_root
    _spread_lane || env_skip "per-backend spread is read on the local lane; the VM lanes read it in suite 139"

    _udp_service lb-health-001 19095 round_robin 9096:1:false 9097:1:true
    _spread 19095 20 "${DATA_DIR}/health.txt" 9096 9097
    api_delete /api/v1/lb/services/lb-health-001 >/dev/null 2>&1 || true

    local skipped served
    skipped="$(_reached "${DATA_DIR}/health.txt" 9096)"
    served="$(_reached "${DATA_DIR}/health.txt" 9097)"
    [ "$skipped" -eq 0 ] || {
        echo "the disabled backend received ${skipped} of 20 flows" >&2
        return 1
    }
    [ "$served" -eq 20 ] || {
        echo "the enabled backend received ${served} of 20 flows" >&2
        return 1
    }
}

@test "the forwarded counter counts the datagrams the balancer rewrote" {
    require_root
    _spread_lane || env_skip "per-backend spread is read on the local lane; the VM lanes read it in suite 139"

    wait_for_ebpf_counters LB_METRICS
    local before after
    before="$(ebpf_counter LB_METRICS forwarded)"
    _udp_service lb-count-001 19098 round_robin 9099:1:true
    _spread 19098 25 "${DATA_DIR}/count.txt" 9099
    api_delete /api/v1/lb/services/lb-count-001 >/dev/null 2>&1 || true

    after="$(ebpf_counter_above LB_METRICS forwarded "${before:-0}")"
    [ "$after" -ge $(( ${before:-0} + 25 )) ] || {
        echo "forwarded went from ${before:-0} to ${after}, 25 datagrams were rewritten" >&2
        dump_ebpf_counters LB_METRICS >&2
        return 1
    }
}

@test "a Maglev service past the rings reserved at start is refused" {
    require_root

    # The fixture lists no Maglev service and sets no max_maglev_services,
    # so the kernel table was created with one ring: the first service takes
    # it and the second is refused whole, naming the key to raise.
    local first='{"id":"lb-maglev-001","name":"maglev-a","protocol":"tcp","listen_port":19101,"algorithm":"maglev","backends":[{"id":"b1","addr":"10.200.0.1","port":9101,"enabled":true}],"enabled":true}'
    local second='{"id":"lb-maglev-002","name":"maglev-b","protocol":"tcp","listen_port":19102,"algorithm":"maglev","backends":[{"id":"b1","addr":"10.200.0.1","port":9102,"enabled":true}],"enabled":true}'

    api_post /api/v1/lb/services "$first" >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "201" ]

    local body
    body="$(api_post /api/v1/lb/services "$second")"
    _load_http_status
    # api_delete sets HTTP_STATUS in this shell, so keep the refusal's own.
    local refused="$HTTP_STATUS"
    api_delete /api/v1/lb/services/lb-maglev-001 >/dev/null 2>&1 || true
    api_delete /api/v1/lb/services/lb-maglev-002 >/dev/null 2>&1 || true

    [ "$refused" = "400" ]
    [[ "$body" == *"loadbalancer.max_maglev_services"* ]]
}
