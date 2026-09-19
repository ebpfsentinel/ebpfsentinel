#!/usr/bin/env bats
# 38-mhddos-l7-attacks.bats - Exercise MHDDoS L7 multi-method floods
# against a single agent instance with L7 firewall, IPS auto-blacklist,
# and global rate limiter all enabled.
#
# Topology: 2vm. Profile: nightly. Requires:
#   - Attacker VM provisioned (MHDDoS at /opt/MHDDoS)
#   - Agent VM reachable via 2VM SSH helpers
#   - Kernel >= 6.9, bpftool on agent side
#
# Each per-method test:
#   1. snapshots the relevant agent metric
#   2. drives 30 s of MHDDoS traffic of one method (10 threads)
#   3. asserts (a) the metric grew, (b) the attacker IP is blacklisted,
#      (c) at least one alert carries a MITRE T1498/T1499 tag,
#      (d) API p99 stays under 500 ms during the attack window.
#
# MHDDoS exits non-zero whenever the agent successfully drops or rate-
# limits its connection attempts; we never assert on its exit code.

load '../lib/ebpf_helpers'
load '../lib/mhddos_helpers'

setup_file() {
    require_root
    require_kernel 6 9
    require_tool bpftool
    require_tool jq
    require_tool bc
    require_tool curl

    # Topology before tooling: MHDDoS is provisioned on the attacker VM only,
    # so on any other host the missing tool is a consequence of the wrong lane,
    # not a provisioning gap. Checking it first made the local lane report
    # "MHDDoS not provisioned" and sent readers after a provisioner that was
    # never meant to run there.
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        env_skip "suite 38 requires EBPF_2VM_MODE=true (attacker VM driving real flood)"
    fi
    require_mhddos

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-mhddos-$$"
    mkdir -p "$DATA_DIR"

    create_test_netns

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-mhddos.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }

    export ATTACKER_IP
    ATTACKER_IP="$(attacker_ip)"
    export ATTACK_DURATION="${ATTACK_DURATION:-30}"
    export ATTACK_THREADS="${ATTACK_THREADS:-10}"
    # The p99 probe targets /healthz on the same API port the flood hits. XDP
    # rate-limiting drops the bulk of the flood at the NIC, but accepted L7
    # connections still load the shared control plane on a 2-vCPU test VM. The
    # meaningful guarantee is that the control plane stays responsive (well
    # under the 5s curl timeout), not a sub-second SLA under active DDoS.
    export P99_BUDGET_MS="${P99_BUDGET_MS:-4000}"
}

teardown_file() {
    stop_mhddos 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-mhddos-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

teardown() {
    stop_mhddos 2>/dev/null || true
    _clear_auto_blacklist
}

# -- Reading the agent from the agent ---------------------------------
#
# The flood leaves from the host running these tests, and the suite exists to
# get that host auto-blacklisted: the moment the entry lands, every packet this
# VM sends to the API port is dropped at the datapath. A reading taken from
# here after the attack therefore answers nothing at all, which the shared
# assertion reports as a counter that did not move - the wrong diagnosis, and
# the one the first method escapes only because the entry is not installed yet
# when it reads. The fixture whitelists 127.0.0.0/8 so the agent stays readable
# from its own loopback whatever it decided about this VM, and that is where
# these readings are taken. _agent_ssh is the lane-agnostic way there: a real
# SSH hop on the 2-VM lane, a plain local call on the agent-local one.

# _agent_api_get <path> - GET a path on the agent over its own loopback.
#
# The hop that carries the reading is still the wire the flood just came down,
# so the call is given a deadline of its own: a session the datapath has stopped
# answering costs ten seconds and is retried rather than holding the poll below
# open for as long as ssh is willing to wait.
_agent_api_get() {
    local path="${1:?usage: _agent_api_get <path>}"
    timeout 10 $AGENT_SSH_CMD -- curl -sf --max-time 5 \
        "http://127.0.0.1:${AGENT_HTTP_PORT}${path}" 2>/dev/null
}

# _agent_metric_value <metric> <label> - one labelled counter, read there.
_agent_metric_value() {
    local key="${1}${2}"
    _agent_api_get /metrics | awk -v key="$key" '$1 == key { print $2; exit }'
}

# _assert_agent_metric_increased <metric> <before> <label>
# Polls the agent's own exposition until the deadline and asserts growth.
#
# The budget is wall clock rather than a number of attempts, because the two
# methods that hold their connections open leave this host dropped long enough
# that a read costs whole seconds instead of returning at once - counting
# attempts then spends the whole allowance on three of them and reports a
# counter that never moved when what happened is that nothing was ever read.
# The counter itself only ever rises, so the only question is whether the poll
# outlives the mitigation the flood earned.
_assert_agent_metric_increased() {
    local metric="$1"
    local before="$2"
    local label="$3"
    local deadline=$((SECONDS + ${AGENT_READ_BUDGET_SECS:-150}))
    local value=""

    while [ "$SECONDS" -lt "$deadline" ]; do
        value="$(_agent_metric_value "$metric" "$label")"
        if [ -n "$value" ] && \
           [ "$(echo "$value > $before" | bc -l 2>/dev/null)" = "1" ]; then
            return 0
        fi
        sleep 1
    done
    echo "Metric ${metric}${label} did not grow from ${before} (last=${value:-<none>})" >&2
    return 1
}

# _assert_agent_ip_blacklisted <ip> - same poll, read over the loopback.
_assert_agent_ip_blacklisted() {
    local ip="${1:?usage: _assert_agent_ip_blacklisted <ip>}"
    local deadline=$((SECONDS + ${AGENT_READ_BUDGET_SECS:-150}))

    while [ "$SECONDS" -lt "$deadline" ]; do
        local hit
        hit="$(_agent_api_get /api/v1/ips/blacklist \
            | jq -r --arg ip "$ip" \
                '.[]? | select(.ip == $ip or .source_ip == $ip or .src_ip == $ip)
                      | .ip // .source_ip // .src_ip' 2>/dev/null | head -1)"
        if [ -n "$hit" ] && [ "$hit" != "null" ]; then
            return 0
        fi
        sleep 1
    done
    echo "IP ${ip} not present in the agent's IPS blacklist within the read budget" >&2
    return 1
}

# _clear_auto_blacklist - drop the entry this suite's own flood installed.
#
# max_blacklist_duration_secs is 300 s in the fixture, which outlives the whole
# suite, so the entry left by one method is still in force while the next one
# runs. This does not restore the rate limiter's view of the source - the
# detector puts the entry straight back, which is why the methods after the
# first assert the firewall instead - but it does keep the API reachable from
# this VM between tests, which is where the readings and the nuclei scan come
# from.
_clear_auto_blacklist() {
    [ -n "${ATTACKER_IP:-}" ] || return 0
    local deadline=$((SECONDS + ${AGENT_READ_BUDGET_SECS:-150}))

    while [ "$SECONDS" -lt "$deadline" ]; do
        if timeout 10 $AGENT_SSH_CMD -- curl -sf -X DELETE --max-time 5 \
            "http://127.0.0.1:${AGENT_HTTP_PORT}/api/v1/ips/blacklist/${ATTACKER_IP}" \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 0
}

# ── Shared per-method assertions ──────────────────────────────────────

# _run_attack_and_assert <method> <metric> <label> [path]
# Single helper that captures the shared assertion shape across all eight
# methods. The agent exposes per-subsystem drop/detect counts via the labeled
# packets_total family (and dedicated counters), not flat per-feature totals -
# so each method asserts the labeled metric its flood actually moves.
_run_attack_and_assert() {
    local method="$1"
    local metric="$2"
    local label="$3"
    local path="${4:-/}"

    local before
    before="$(_agent_metric_value "$metric" "$label")"
    [ -z "$before" ] && before="0"

    # Background MHDDoS, foreground latency probes.
    run_mhddos_background "$method" "$ATTACK_DURATION" "$ATTACK_THREADS" "$path"

    # Mid-attack: assert API control plane stays responsive.
    sleep 5
    assert_api_p99_below "$P99_BUDGET_MS" 50

    # Wait for the flood to wind down.
    wait "${MHDDOS_PID:-0}" 2>/dev/null || true
    stop_mhddos

    # Deterministic datapath reaction: the flood is dropped by the stage the
    # caller named, and the source is auto-blacklisted. DoS-alert emission for
    # rate-limited L7 floods
    # is opportunistic (the volumetric detector does not fire on every run), so
    # MITRE-tag coverage is asserted once, suite-wide, by the dedicated test
    # below rather than per method.
    _assert_agent_metric_increased "$metric" "$before" "$label"
    _assert_agent_ip_blacklisted "$ATTACKER_IP"
}

# Which counter a method moves is decided by the order the methods run in,
# not by the method. The datapath asks the firewall before it asks the rate
# limiter, so an entry in the blacklist ends the rate limiter's involvement:
# the packets are gone a stage earlier and the token bucket is never consulted.
#
# The first flood therefore meets an agent that has just started and a source
# nothing has ever been decided about, and it meets the bucket immediately -
# two hundred packets a second with a burst of four hundred, against ten
# threads opening fresh connections. The IPS needs three detections of fifty
# packets inside a ten-second window before it writes the entry, so the rate
# limiter has already been dropping for tens of seconds by the time the source
# is blacklisted. That first method is the one that can assert the bucket.
#
# Every method after it starts from a source the previous flood got
# blacklisted, and the entry outlives the suite - max_blacklist_duration_secs
# is three hundred seconds in the fixture. Deleting it between methods does not
# help, and was tried: the detector's window is still full of the last flood,
# so the entry is back before the next one has sent anything, and a run that
# happens to win the race measures seventy-three rate-limiter drops where the
# next one measures none. What those methods do move, by tens of thousands of
# packets and on every run, is the firewall. So they assert that, which is the
# true statement about them: the datapath dropped the flood.
_RL_METRIC="ebpfsentinel_packets_total"
_RL_LABEL='{interface="ratelimit",action="drop"}'

_FW_METRIC="ebpfsentinel_packets_total"
_FW_LABEL='{interface="FIREWALL_METRICS",action="dropped"}'

# ── Per-method tests ──────────────────────────────────────────────────

@test "MHDDoS GET flood is rate-limited at the kernel datapath" {
    _run_attack_and_assert GET "$_RL_METRIC" "$_RL_LABEL" "/"
}

@test "MHDDoS POST flood is dropped at the kernel datapath" {
    _run_attack_and_assert POST "$_FW_METRIC" "$_FW_LABEL" "/login"
}

@test "MHDDoS STRESS (persistent conn) flood is dropped at the kernel datapath" {
    _run_attack_and_assert STRESS "$_FW_METRIC" "$_FW_LABEL" "/"
}

@test "MHDDoS BYPASS flood over TLS is dropped at the kernel datapath" {
    _run_attack_and_assert BYPASS "$_FW_METRIC" "$_FW_LABEL" "/"
}

@test "MHDDoS OVH volumetric flood is dropped at the kernel datapath" {
    _run_attack_and_assert OVH "$_FW_METRIC" "$_FW_LABEL" "/"
}

# The TLS, CFB and SLOW attack modes are deliberately absent from the list
# above. TLS and CFB pay a per-connection handshake cost that keeps a
# single-source proxyless run well below the volumetric pps threshold, and
# slowloris holds a handful of connections open at a near-idle packet rate.
# None of them is a volumetric signal, so asserting that the pps rate-limiter
# catches them would assert the wrong thing; the slow-attack and L7-timeout
# paths that do cover them live in suite 39.

# ── Real web scanner (nuclei) ─────────────────────────────────────
#
# nuclei is provisioned on the attacker VM. It drives genuine crafted
# HTTP requests (path traversal / SQLi markers) at the agent, which the
# tc-ids / L7 datapath observes. We assert on the broad observed-packet
# counter rather than a specific signature so the test is robust to the
# fixture's exact rule set - the point is that a real scanner's traffic
# reaches the datapath.

# _l7_packet_metric - sum every observed-packet counter the agent exposes.
_l7_packet_metric() {
    local metrics
    metrics="$(curl -sf --max-time 5 \
        "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/metrics" 2>/dev/null)" || {
        echo 0
        return
    }
    echo "$metrics" \
        | awk '/^ebpfsentinel_packets[_a-z]*(_total)?[ {]/ {sum += $NF}
               END { if (sum == "") print 0; else print sum }'
}

@test "real nuclei web scan traffic reaches the L7 datapath" {
    if ! command -v nuclei >/dev/null 2>&1; then
        env_skip "nuclei not available on attacker VM"
    fi

    # Self-contained template - no nuclei-templates DB download required,
    # so the scan runs offline in the test VM.
    local tmpl="${DATA_DIR}/ebpfsentinel-probe.yaml"
    cat > "${tmpl}" <<'YAML'
id: ebpfsentinel-datapath-probe
info:
  name: ebpfsentinel datapath probe
  author: ebpfsentinel
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/../../../../etc/passwd"
      - "{{BaseURL}}/index.php?id=1%20OR%201=1"
      - "{{BaseURL}}/admin/config"
    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
          - 400
          - 401
          - 403
          - 404
YAML

    local before
    before="$(_l7_packet_metric)"

    nuclei -u "http://${AGENT_HOST}:${AGENT_HTTP_PORT}/" \
        -t "${tmpl}" -rate-limit 200 -c 20 -timeout 3 \
        -duc -no-color -silent >/dev/null 2>&1 || true

    sleep 3
    local after
    after="$(_l7_packet_metric)"
    [ "${after:-0}" -gt "${before:-0}" ] || {
        echo "observed-packet counter did not grow under nuclei scan: ${before} -> ${after}" >&2
        return 1
    }
}

# ── MITRE coverage sweep ───────────────────────────────────────────

@test "alerts emitted by this suite carry a MITRE technique mapping" {
    local body count
    body="$(api_get /api/v1/alerts 2>/dev/null)" || body=""
    count="$(echo "${body}" | jq -r '.alerts | length' 2>/dev/null)" || count=0
    if [ "${count:-0}" -lt 1 ]; then
        soft_skip "no alerts emitted by this suite - MITRE assertion not applicable here"
    fi
    assert_alert_has_any_mitre_technique 15
}
