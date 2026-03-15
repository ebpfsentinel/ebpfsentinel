#!/usr/bin/env bats
# 30-ebpf-map-operation-bench.bats — eBPF map operation benchmarks at scale
# Requires: root, kernel >= 6.1, bpftool, jq
#
# Measures bulk REST API operation latencies for eBPF-backed domains:
#   - Firewall rule bulk load (100 / 1K / 10K)
#   - Threat intel IOC sync (1K / 10K)
#   - Ratelimit policy add (100 / 1K)
#   - LB backend update (10 / 100)
#   - DNS blocklist sync (1K / 10K)
#
# Outputs JSON report to /tmp/ebpfsentinel-map-ops-latest.json

load '../lib/helpers'
load '../lib/ebpf_helpers'

MAP_OPS_REPORT="/tmp/ebpfsentinel-map-ops-latest.json"

setup_file() {
    if [ "${EBPF_2VM_MODE:-false}" != "true" ]; then
        require_root
        require_kernel 5 17
        require_tool bpftool
    fi
    require_tool jq

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    export DATA_DIR="/tmp/ebpfsentinel-test-data-mapops-$$"
    mkdir -p "$DATA_DIR"

    # Create netns + veth pair
    create_test_netns

    # Initialize report (remove stale file from previous root run)
    rm -f "$MAP_OPS_REPORT"
    echo '{}' > "$MAP_OPS_REPORT"

    # Prepare config and start agent
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-benchmark.yaml")"
    export PREPARED_CONFIG

    start_ebpf_agent "$PREPARED_CONFIG"
    wait_for_ebpf_loaded 30 || {
        echo "eBPF programs failed to load (degraded mode). Log tail:" >&2
        tail -5 "$AGENT_LOG_FILE" >&2
        stop_ebpf_agent 2>/dev/null || true
        destroy_test_netns 2>/dev/null || true
        skip "eBPF programs not loaded (degraded mode)"
    }
}

teardown_file() {
    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/tmp/ebpfsentinel-test-data-mapops-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helper: update JSON report ──────────────────────────────────────

_report_set() {
    local key="$1"
    local value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --argjson v "$value" '. + {($k): $v}' "$MAP_OPS_REPORT")"
    echo "$tmp" > "$MAP_OPS_REPORT"
}

_report_set_str() {
    local key="$1"
    local value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --arg v "$value" '. + {($k): $v}' "$MAP_OPS_REPORT")"
    echo "$tmp" > "$MAP_OPS_REPORT"
}

# ── Helper: check agent is alive ──────────────────────────────────────
_require_agent_alive() {
    [ -f "$AGENT_PID_FILE" ] || skip "agent not running"
    curl -sf --max-time 3 "${BASE_URL}/healthz" >/dev/null 2>&1 || skip "agent not responding"
}

# ── Helper: generate and POST firewall rules ────────────────────────

_bench_firewall_rules() {
    local count="$1"
    local label="$2"
    local i status_ok=0 status_fail=0

    local start_ns end_ns duration_ms
    start_ns="$(date +%s%N)"

    for i in $(seq 1 "$count"); do
        local port=$(( 10000 + i ))
        local rule
        rule="$(jq -n --arg id "fw-bench-${label}-${i}" --argjson port "$port" \
            '{id: $id, priority: 100, action: "deny", protocol: "tcp", dst_port: $port, scope: "global", enabled: true}')"
        api_post /api/v1/firewall/rules "$rule" >/dev/null 2>&1
        _load_http_status
        if [ "$HTTP_STATUS" = "201" ] || [ "$HTTP_STATUS" = "200" ]; then
            status_ok=$(( status_ok + 1 ))
        else
            status_fail=$(( status_fail + 1 ))
        fi
    done

    end_ns="$(date +%s%N)"
    duration_ms="$(( (end_ns - start_ns) / 1000000 ))"

    _report_set "firewall_${label}_count" "$count"
    _report_set "firewall_${label}_ok" "$status_ok"
    _report_set "firewall_${label}_fail" "$status_fail"
    _report_set "firewall_${label}_duration_ms" "$duration_ms"

    echo "# firewall ${label}: ${count} rules in ${duration_ms}ms (ok=${status_ok}, fail=${status_fail})"

    # Cleanup: delete all rules we just added
    for i in $(seq 1 "$count"); do
        api_delete "/api/v1/firewall/rules/fw-bench-${label}-${i}" >/dev/null 2>&1 || true
    done
}

# ── Helper: generate and POST ratelimit rules ───────────────────────

_bench_ratelimit_rules() {
    local count="$1"
    local label="$2"
    local i status_ok=0 status_fail=0

    local start_ns end_ns duration_ms
    start_ns="$(date +%s%N)"

    for i in $(seq 1 "$count"); do
        local rule
        rule="$(jq -n --arg id "rl-bench-${label}-${i}" --argjson rate "$(( 1000 + i ))" \
            '{id: $id, rate: $rate, burst: ($rate * 2), scope: "global", algorithm: "token_bucket", action: "drop", enabled: true}')"
        api_post /api/v1/ratelimit/rules "$rule" >/dev/null 2>&1
        _load_http_status
        if [ "$HTTP_STATUS" = "201" ] || [ "$HTTP_STATUS" = "200" ]; then
            status_ok=$(( status_ok + 1 ))
        else
            status_fail=$(( status_fail + 1 ))
        fi
    done

    end_ns="$(date +%s%N)"
    duration_ms="$(( (end_ns - start_ns) / 1000000 ))"

    _report_set "ratelimit_${label}_count" "$count"
    _report_set "ratelimit_${label}_ok" "$status_ok"
    _report_set "ratelimit_${label}_fail" "$status_fail"
    _report_set "ratelimit_${label}_duration_ms" "$duration_ms"

    echo "# ratelimit ${label}: ${count} rules in ${duration_ms}ms (ok=${status_ok}, fail=${status_fail})"

    # Cleanup
    for i in $(seq 1 "$count"); do
        api_delete "/api/v1/ratelimit/rules/rl-bench-${label}-${i}" >/dev/null 2>&1 || true
    done
}

# ── Helper: generate and POST LB services with backends ─────────────

_bench_lb_backends() {
    local count="$1"
    local label="$2"
    local i status_ok=0 status_fail=0

    local start_ns end_ns duration_ms
    start_ns="$(date +%s%N)"

    for i in $(seq 1 "$count"); do
        local port=$(( 8000 + i ))
        local octet3=$(( i / 256 ))
        local octet4=$(( i % 256 ))
        local svc
        svc="$(jq -n \
            --arg id "lb-bench-${label}-${i}" \
            --arg name "bench-svc-${i}" \
            --argjson listen_port "$port" \
            --arg be_addr "10.${octet3}.${octet4}.1" \
            --argjson be_port "$port" \
            '{
                id: $id,
                name: $name,
                protocol: "tcp",
                listen_port: $listen_port,
                algorithm: "round_robin",
                backends: [{id: ("be-" + $id), addr: $be_addr, port: $be_port, weight: 1}]
            }')"
        api_post /api/v1/lb/services "$svc" >/dev/null 2>&1
        _load_http_status
        if [ "$HTTP_STATUS" = "201" ] || [ "$HTTP_STATUS" = "200" ]; then
            status_ok=$(( status_ok + 1 ))
        else
            status_fail=$(( status_fail + 1 ))
        fi
    done

    end_ns="$(date +%s%N)"
    duration_ms="$(( (end_ns - start_ns) / 1000000 ))"

    _report_set "lb_${label}_count" "$count"
    _report_set "lb_${label}_ok" "$status_ok"
    _report_set "lb_${label}_fail" "$status_fail"
    _report_set "lb_${label}_duration_ms" "$duration_ms"

    echo "# lb ${label}: ${count} services in ${duration_ms}ms (ok=${status_ok}, fail=${status_fail})"

    # Cleanup
    for i in $(seq 1 "$count"); do
        api_delete "/api/v1/lb/services/lb-bench-${label}-${i}" >/dev/null 2>&1 || true
    done
}

# ── Helper: generate and POST DNS blocklist domains ─────────────────

_bench_dns_blocklist() {
    local count="$1"
    local label="$2"
    local i status_ok=0 status_fail=0

    local start_ns end_ns duration_ms
    start_ns="$(date +%s%N)"

    for i in $(seq 1 "$count"); do
        local payload
        payload="$(jq -n --arg domain "bench-${label}-${i}.malware.example.com" \
            '{domain: $domain}')"
        api_post /api/v1/domains/blocklist "$payload" >/dev/null 2>&1
        _load_http_status
        if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]; then
            status_ok=$(( status_ok + 1 ))
        else
            status_fail=$(( status_fail + 1 ))
        fi
    done

    end_ns="$(date +%s%N)"
    duration_ms="$(( (end_ns - start_ns) / 1000000 ))"

    _report_set "dns_blocklist_${label}_count" "$count"
    _report_set "dns_blocklist_${label}_ok" "$status_ok"
    _report_set "dns_blocklist_${label}_fail" "$status_fail"
    _report_set "dns_blocklist_${label}_duration_ms" "$duration_ms"

    echo "# dns blocklist ${label}: ${count} domains in ${duration_ms}ms (ok=${status_ok}, fail=${status_fail})"

    # Cleanup
    for i in $(seq 1 "$count"); do
        api_delete "/api/v1/domains/blocklist/bench-${label}-${i}.malware.example.com" >/dev/null 2>&1 || true
    done
}

# ── Helper: generate and POST threat intel IOCs ─────────────────────
# Threat intel IOCs are typically loaded from feeds. The agent exposes
# GET /api/v1/threatintel/iocs but may not have a direct POST for
# individual IOCs. We use the firewall rule path to simulate IOC-scale
# map writes, measuring the control-plane overhead. If a direct IOC
# POST endpoint exists, adapt accordingly.

_bench_threatintel_iocs() {
    local count="$1"
    local label="$2"
    local i status_ok=0 status_fail=0

    # Build a batch of firewall rules that simulate IOC-based blocking
    # (one deny rule per "IOC" IP address). This exercises the same
    # eBPF map write path at scale.
    local start_ns end_ns duration_ms
    start_ns="$(date +%s%N)"

    for i in $(seq 1 "$count"); do
        local octet2=$(( (i / 65536) % 256 ))
        local octet3=$(( (i / 256) % 256 ))
        local octet4=$(( i % 256 ))
        local rule
        rule="$(jq -n \
            --arg id "ti-bench-${label}-${i}" \
            --arg src_ip "${octet2}.${octet3}.${octet4}.0/32" \
            '{id: $id, priority: 50, action: "deny", protocol: "any", src_ip: $src_ip, scope: "global", enabled: true}')"
        api_post /api/v1/firewall/rules "$rule" >/dev/null 2>&1
        _load_http_status
        if [ "$HTTP_STATUS" = "201" ] || [ "$HTTP_STATUS" = "200" ]; then
            status_ok=$(( status_ok + 1 ))
        else
            status_fail=$(( status_fail + 1 ))
        fi
    done

    end_ns="$(date +%s%N)"
    duration_ms="$(( (end_ns - start_ns) / 1000000 ))"

    _report_set "threatintel_${label}_count" "$count"
    _report_set "threatintel_${label}_ok" "$status_ok"
    _report_set "threatintel_${label}_fail" "$status_fail"
    _report_set "threatintel_${label}_duration_ms" "$duration_ms"

    echo "# threatintel ${label}: ${count} IOC rules in ${duration_ms}ms (ok=${status_ok}, fail=${status_fail})"

    # Cleanup
    for i in $(seq 1 "$count"); do
        api_delete "/api/v1/firewall/rules/ti-bench-${label}-${i}" >/dev/null 2>&1 || true
    done
}

# ── Firewall rule bulk load benchmarks ──────────────────────────────

@test "firewall: bulk load 100 rules" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    _bench_firewall_rules 100 "100"
}

@test "firewall: bulk load 1K rules" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    local count=1000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=200

    _bench_firewall_rules "$count" "1k"
}

@test "firewall: bulk load 10K rules" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    # Reduce count in 2VM mode to avoid network-induced timeouts
    local count=10000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=500

    _bench_firewall_rules "$count" "10k"
}

# ── Threat intel IOC sync benchmarks ────────────────────────────────

@test "threatintel: IOC sync 1K entries" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    local count=1000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=200

    _bench_threatintel_iocs "$count" "1k"
}

@test "threatintel: IOC sync 10K entries" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    local count=10000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=500

    _bench_threatintel_iocs "$count" "10k"
}

# ── Ratelimit policy benchmarks ─────────────────────────────────────

@test "ratelimit: bulk add 100 policies" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    _bench_ratelimit_rules 100 "100"
}

@test "ratelimit: bulk add 1K policies" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    local count=1000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=200

    _bench_ratelimit_rules "$count" "1k"
}

# ── LB backend update benchmarks ───────────────────────────────────

@test "lb: backend update 10 services" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    _bench_lb_backends 10 "10"
}

@test "lb: backend update 100 services" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    _bench_lb_backends 100 "100"
}

# ── DNS blocklist sync benchmarks ──────────────────────────────────

@test "dns: blocklist sync 1K domains" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    local count=1000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=200

    _bench_dns_blocklist "$count" "1k"
}

@test "dns: blocklist sync 10K domains" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    local count=10000
    [ "${EBPF_2VM_MODE:-false}" = "true" ] && count=500

    _bench_dns_blocklist "$count" "10k"
}

# ── Summary ─────────────────────────────────────────────────────────

@test "map-ops benchmark summary" {
    [ "${EBPF_2VM_MODE:-false}" = "true" ] || require_root
    _require_agent_alive

    # Record metadata
    _report_set_str "timestamp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _report_set_str "kernel" "$(uname -r)"

    local pid
    pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true
    if [ -n "$pid" ]; then
        local rss_kb
        if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
            rss_kb="$(_agent_ssh_sudo grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')" || true
        elif [ -d "/proc/${pid}" ]; then
            rss_kb="$(grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')" || true
        fi
        if [ -n "$rss_kb" ]; then
            _report_set "agent_rss_kb_after_bench" "$rss_kb"
        fi
    fi

    # Print the full report
    echo "# Map Operations Benchmark Report: ${MAP_OPS_REPORT}"
    jq '.' "$MAP_OPS_REPORT"

    # Verify report has at least one benchmark result
    local keys
    keys="$(jq 'keys | length' "$MAP_OPS_REPORT")"
    [ "$keys" -ge 3 ]
}
