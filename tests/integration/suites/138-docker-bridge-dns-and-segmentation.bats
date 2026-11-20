#!/usr/bin/env bats
# 138-docker-bridge-dns-and-segmentation.bats - the two Docker host policies
# that only a real bridge and real containers can show.
#
# The suite asserts:
#
#   * The agent's own resolver, listening on the default bridge's gateway,
#     answers a governed container the names its list carries and refuses
#     the rest with REFUSED, alerting on and counting each refusal; a
#     container the list does not name is forwarded untouched.
#   * A learning window over three containers on a user-defined bridge
#     (client reaching web, web reaching db) proposes a segmentation that
#     keeps those two paths, writes Docker's embedded resolver out ahead of
#     the closing deny, and once loaded refuses the client the database
#     while every learned path and name resolution still works.
#
# Requires: root, kernel >= 6.12, jq, docker, python3, a static busybox.

load '../lib/helpers'
load '../lib/ebpf_helpers'

IMAGE="ebpfsentinel-test-bridge:busybox"
PREFIX="ebpfsentinel-test-bridge"
NETWORK="ebpfsentinel-test-seg"

setup_file() {
    require_root
    require_kernel 6 12
    require_tool jq
    require_tool docker
    require_tool python3

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 138 runs its containers beside the agent (local lane only)"
    fi
    docker info >/dev/null 2>&1 || env_skip "docker daemon not reachable"
    local busybox
    busybox="$(command -v busybox || true)"
    [ -n "$busybox" ] && file -L "$busybox" 2>/dev/null | grep -q "statically linked" \
        || env_skip "no statically linked busybox to build the test image from"

    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-bridge-$$"
    mkdir -p "${DATA_DIR}/rootfs/bin"
    cp "$busybox" "${DATA_DIR}/rootfs/bin/busybox"
    local applet
    for applet in sh nc sleep nslookup; do
        ln -s busybox "${DATA_DIR}/rootfs/bin/${applet}"
    done
    tar -C "${DATA_DIR}/rootfs" -c . | docker import - "$IMAGE" >/dev/null

    export GATEWAY UPSTREAM
    GATEWAY="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
    [ -n "$GATEWAY" ] || { echo "no gateway on the default bridge" >&2; return 1; }
    # The host's own resolver, the one the agent forwards to.
    UPSTREAM="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
    [ -n "$UPSTREAM" ] || { echo "no nameserver in /etc/resolv.conf" >&2; return 1; }
    UPSTREAM="${UPSTREAM}:53"

    # Default bridge: one container the list governs, one it does not.
    _start governed --dns "$GATEWAY"
    _start stranger --dns "$GATEWAY"

    # User-defined bridge: Docker's embedded resolver answers the names.
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker network create "$NETWORK" >/dev/null
    _serve web 8080 --network "$NETWORK"
    _serve db 5432 --network "$NETWORK"
    _start client --network "$NETWORK"

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-docker-bridge.yaml")"
    sed -i -e "s|__GATEWAY__|${GATEWAY}|g" -e "s|__UPSTREAM__|${UPSTREAM}|g" \
        -e "s|__GOVERNED__|${PREFIX}-governed|g" "$PREPARED_CONFIG"
    export PREPARED_CONFIG
    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
}

teardown_file() {
    local name
    for name in governed stranger web db client; do
        docker rm -f "${PREFIX}-${name}" >/dev/null 2>&1 || true
    done
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-bridge-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# _start <name> [docker run options...] - one container that stays up.
_start() {
    local name="$1"
    shift
    docker run -d --name "${PREFIX}-${name}" "$@" "$IMAGE" /bin/sleep 3600 >/dev/null
}

# _serve <name> <port> [docker run options...] - a container accepting
# connections on the port and closing each at once.
_serve() {
    local name="$1" port="$2"
    shift 2
    docker run -d --name "${PREFIX}-${name}" "$@" "$IMAGE" \
        /bin/sh -c "while :; do nc -l -p ${port} </dev/null >/dev/null; done" >/dev/null
}

# _reach <from> <to> <port> - whether the connect goes through, the peer
# named through Docker's embedded resolver.
_reach() {
    docker exec "${PREFIX}-$1" nc -w 2 "${PREFIX}-$2" "$3" </dev/null >/dev/null 2>&1
}

# _lookup <container> <name> [server] - the resolver's answer as nslookup
# prints it. Names are passed rooted: a bare one gets the host's search
# domain appended, and the list is asked about a name it never carried.
_lookup() {
    docker exec "${PREFIX}-$1" nslookup "$2" ${3:+"$3"} 2>&1
}

# _counted <container> <verdict> - the resolver's count for that pair.
_counted() {
    scrape_metrics \
        | awk -v c="${PREFIX}-$1" -v v="$2" '
            /^ebpfsentinel_dns_allowlist_queries_total\{/ && index($0, "container=\"" c "\"") && index($0, "verdict=\"" v "\"") {sum += $NF}
            END {print sum + 0}'
}

@test "the resolver answers a governed container a name its list carries" {
    local out
    out="$(_lookup governed localhost.)" || true
    echo "$out"
    [[ "$out" != *REFUSED* ]] || false
    assert_contains "$out" "127.0.0.1"
    [ "$(_counted governed allowed)" -ge 1 ]
}

@test "a name the list does not carry is refused at the resolver, alerted and counted" {
    local out
    out="$(_lookup governed example.org.)" || true
    echo "$out"
    assert_contains "$out" "REFUSED"
    [ "$(_counted governed refused)" -ge 1 ]
    run wait_for_alert ".[] | select(tojson | contains(\"example.org\"))" 15 1
    [ "$status" -eq 0 ] || { tail -5 "$AGENT_LOG_FILE" >&3; false; }
}

@test "a container the list does not name is forwarded untouched" {
    local out
    out="$(_lookup stranger example.org.)"
    [[ "$out" != *REFUSED* ]] || { echo "$out" >&3; false; }
    [ "$(_counted stranger refused)" -eq 0 ]
}

@test "a learning window proposes a segmentation that keeps the paths it saw" {
    # Before anything is loaded the bridge is flat.
    _reach client db 5432

    local body id k
    body="$(api_post /api/v1/learning/sessions '{"scope":{"kind":"node"},"duration_secs":600}')"
    id="$(jq -r '.id' <<<"$body")"
    [ -n "$id" ] && [ "$id" != null ] || { echo "start answered: ${body}" >&3; false; }
    for k in $(seq 1 10); do
        _reach client web 8080 || true
        _reach web db 5432 || true
        sleep 1
    done
    sleep 4
    # While the window is open the scrape counts what it learned: the edges
    # it holds, and each path first seen as a new edge.
    local metrics
    metrics="$(scrape_metrics)"
    echo "$metrics" | awk '$1 == "ebpfsentinel_learning_edges" && $2 >= 2 { ok = 1 } END { exit !ok }' || {
        echo "$metrics" | grep '^ebpfsentinel_learning' >&3
        api_post "/api/v1/learning/sessions/${id}/stop" '{}' >/dev/null
        false
    }
    echo "$metrics" | awk 'index($0, "ebpfsentinel_learning_observations_total{outcome=\"new_edge\"}") == 1 && $NF >= 2 { ok = 1 } END { exit !ok }' || {
        echo "$metrics" | grep '^ebpfsentinel_learning' >&3
        api_post "/api/v1/learning/sessions/${id}/stop" '{}' >/dev/null
        false
    }
    api_post "/api/v1/learning/sessions/${id}/stop" '{}' >/dev/null

    body="$(api_get "/api/v1/learning/sessions/${id}/segmentation")"
    echo "$body" | jq -c '{bridges, containers, rules, peer_rules, unlearned, unnamed}'
    [ "$(jq -r '.rules' <<<"$body")" -ge 1 ]
    local yaml
    yaml="$(jq -r '.yaml' <<<"$body")"
    # The embedded resolver is written out explicitly, ahead of the deny.
    assert_contains "$yaml" "127.0.0.11"
    assert_contains "$yaml" "dst_port: 8080"
    assert_contains "$yaml" "dst_port: 5432"
    printf '%s\n' "$yaml" > "${DATA_DIR}/segmentation.yaml"
}

@test "the segmentation loaded refuses the client the database and keeps every learned path" {
    [ -s "${DATA_DIR}/segmentation.yaml" ] || {
        echo "the test before proposed no segmentation" >&2
        return 1
    }
    # The proposal observes, as every proposal does; moving it to enforce is
    # the operator's step, taken here. The rules then replace the empty rule
    # list and the watcher reloads.
    python3 - "$PREPARED_CONFIG" "${DATA_DIR}/segmentation.yaml" <<'PY'
import sys
config_path, seg_path = sys.argv[1], sys.argv[2]
text = open(seg_path).read()
assert "mode: observe" in text, "the proposal observes"
seg = text.replace("mode: observe", "mode: enforce").splitlines()
start = seg.index("  rules:") + 1
rules = "\n".join(seg[start:]) + "\n"
config = open(config_path).read()
assert config.count("  rules: []\n") == 1, "the fixture holds one empty rule list"
open(config_path, "w").write(config.replace("  rules: []\n", "  rules:\n" + rules))
PY
    local k refused=0
    for k in $(seq 1 20); do
        if ! _reach client db 5432; then
            refused=1
            break
        fi
        sleep 1
    done
    [ "$refused" -eq 1 ] || {
        api_get /api/v1/firewall/workload/rules >&3
        grep -i 'reload\|rule' "$AGENT_LOG_FILE" | tail -10 >&3
        false
    }
    # Three refusals in a row: each exec is a new task in the cgroup.
    for k in 1 2 3; do
        run _reach client db 5432
        [ "$status" -ne 0 ]
    done
    _reach client web 8080
    _reach web db 5432
    # Docker's embedded resolver still answers the client.
    assert_contains "$(_lookup client "${PREFIX}-web")" "Address"
}
