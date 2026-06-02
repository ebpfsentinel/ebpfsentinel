#!/usr/bin/env bats
# 51-conntrack-kernel-ct-kill.bats — kernel-CT kill-flow path, 3-VM.
#
# Exercises the kill_flow_via_xdp_ct / kill_flow_via_skb_ct kfunc path:
# an established TCP flow is forwarded through the agent (which acts as
# an IP router in transit mode, so netfilter conntrack tracks the
# 4-tuple), a block rule is injected mid-flow, and the XDP firewall's
# drop verdict triggers destruction of the kernel CT entry.
#
# Asserted:
#   1. an established attacker → backend:5201 TCP flow shows up in the
#      agent's `conntrack -L` table
#   2. POSTing a deny rule for that destination causes the CT entry to
#      disappear within a few seconds (kfunc-driven destroy)
#   3. follow-up packets on the same 4-tuple no longer carry CT info
#      (no new ESTABLISHED entry materializes immediately)
#
# Requires: 3-VM mode, kernel >= 6.9, conntrack-tools on the agent,
# iperf3 on attacker + backend.

load '../lib/helpers'
load '../lib/ebpf_helpers'
load '../lib/ct_helpers'

setup_file() {
    skip_if_not_3vm
    require_kernel 6 9

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-ctkill-$$"
    mkdir -p "$DATA_DIR"

    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-conntrack-kill.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }

    route_via_agent backend >/dev/null 2>&1 || true
    start_backend_service iperf3 5201 || skip "backend iperf3 listener did not start"
    ensure_conntrack_tool || skip "agent VM is missing the 'conntrack' tool (apt install conntrack)"
}

teardown_file() {
    api_delete "/api/v1/firewall/rules/fw-ctkill-block-5201" >/dev/null 2>&1 || true
    stop_ebpf_agent 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-ctkill-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── End-to-end: flow tracked → rule injected → CT entry killed ───────

@test "kernel CT entry tracked, then destroyed when block rule applied mid-flow" {
    skip_if_not_3vm

    local dst="${BACKEND_VM_IP:-192.168.57.30}"
    local dport=5201
    local iperf_pid

    iperf_pid="$(establish_iperf_flow "$dst" "$dport" 60)" || {
        echo "failed to launch iperf3 from attacker" >&2
        return 1
    }

    # Step 1 — wait for the kernel CT entry to land on the agent.
    local pre_count
    pre_count="$(wait_for_ct_entry "$dst" "$dport" tcp 15 1)" || {
        stop_iperf_flow "$iperf_pid"
        echo "no CT entry observed on agent for ${dst}:${dport} within 15s" >&2
        return 1
    }
    [ "${pre_count:-0}" -gt 0 ]

    # Step 2 — inject a deny rule covering this destination. The XDP
    # firewall's next match should drop and invoke kill_flow_via_xdp_ct.
    local rule
    rule='{"id":"fw-ctkill-block-5201","priority":1,"action":"deny","protocol":"tcp","dst_port":5201,"scope":"global","enabled":true}'
    api_post /api/v1/firewall/rules "$rule" >/dev/null
    _load_http_status
    [ "$HTTP_STATUS" = "201" ] || [ "$HTTP_STATUS" = "200" ] || {
        stop_iperf_flow "$iperf_pid"
        echo "firewall rule POST returned HTTP ${HTTP_STATUS}" >&2
        return 1
    }

    # Step 3 — the CT entry should be gone shortly after the next
    # packet on the 4-tuple traverses XDP. iperf3 is still emitting
    # data, so packets keep arriving; allow up to 15s for the kfunc
    # destroy to land and the table to settle.
    local final_count
    final_count="$(assert_ct_entry_absent "$dst" "$dport" tcp 15 1)" || {
        stop_iperf_flow "$iperf_pid"
        echo "CT entry for ${dst}:${dport} still present after block rule (count=${final_count})" >&2
        return 1
    }
    [ "${final_count:-0}" -eq 0 ]

    stop_iperf_flow "$iperf_pid"
}

# ── No CT re-establishment while the deny rule is active ─────────────

@test "blocked 4-tuple does not re-establish a CT entry" {
    skip_if_not_3vm

    local dst="${BACKEND_VM_IP:-192.168.57.30}"
    local dport=5201

    # Rule from the previous test is still in place — but be defensive
    # in case the suite is re-entered out of order.
    local rule
    rule='{"id":"fw-ctkill-block-5201","priority":1,"action":"deny","protocol":"tcp","dst_port":5201,"scope":"global","enabled":true}'
    api_post /api/v1/firewall/rules "$rule" >/dev/null 2>&1 || true

    # Try once more — XDP should still drop the SYN, so no fresh CT
    # entry should appear. Pass the whole pipeline as one argument so the
    # remote login shell runs it (a nested `sh -c` would only run the first
    # word and silently never launch iperf3).
    _attacker_ssh \
        "nohup iperf3 -c '${dst}' -p '${dport}' -t 3 -b 1M >/dev/null 2>&1 &" >/dev/null 2>&1 || true
    sleep 3

    local count
    count="$(ct_entry_count "$dst" "$dport" tcp)"
    [ "${count:-0}" -eq 0 ] || {
        echo "CT entry re-appeared while deny rule active (count=${count})" >&2
        return 1
    }
}

# ── Cleanup behaviour: removing the rule restores forwarding ─────────

@test "removing the deny rule allows a new CT entry to form" {
    skip_if_not_3vm

    local dst="${BACKEND_VM_IP:-192.168.57.30}"
    local dport=5201

    api_delete "/api/v1/firewall/rules/fw-ctkill-block-5201" >/dev/null 2>&1 || true
    sleep 1

    # The mid-flow deny rule blocked the earlier connection's teardown (its
    # FIN/RST never reached the backend through the dropped port), so the
    # single-test iperf3 server can still be wedged on the now-dead flow.
    # Restart the listener unconditionally so a fresh client connects on a
    # clean server (a plain `start` is a no-op while the daemon is listening).
    _backend_ssh_sudo systemctl restart iperf3-backend.service >/dev/null 2>&1 || true
    sleep 2

    local iperf_pid
    iperf_pid="$(establish_iperf_flow "$dst" "$dport" 15)" || {
        echo "iperf3 launch failed after rule removal" >&2
        return 1
    }

    local count
    count="$(wait_for_ct_entry "$dst" "$dport" tcp 15 1)" || count=0
    stop_iperf_flow "$iperf_pid"

    [ "${count:-0}" -gt 0 ] || {
        echo "CT entry never re-appeared after rule removal" >&2
        return 1
    }
}
