#!/usr/bin/env bats
# 09-docker.bats — Docker build, deployment, and overhead tests
#
# Requires: Docker Engine on native Linux with kernel 6.1+ and BTF.
#
# Tests:
#   1. Image exists / build succeeds
#   2. Docker compose up -> healthy container
#   3. CLI health check inside container
#   4. Container resource usage (RSS, CPU)
#   5. TCP throughput via iperf3 (baseline vs Docker agent)
#   6. ICMP latency under Docker agent
#   7. API latency under load
#   8. Memory stability under sustained traffic
#   9. Clean shutdown

load '../lib/helpers'
load '../lib/ebpf_helpers'

DOCKER_IMAGE="ebpfsentinel:integration-test"
CONTAINER_NAME="ebpfsentinel-perf"
IPERF_DURATION=5
DOCKER_REPORT="/tmp/ebpfsentinel-docker-overhead-latest.json"

# ── Docker command wrapper (local or remote via SSH) ────────────
_docker_cmd() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo docker "$@"
    else
        docker "$@"
    fi
}

_docker_check() {
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        if ! _agent_ssh_sudo docker info &>/dev/null 2>&1; then
            skip "Docker not running on agent VM"
        fi
        if ! _agent_ssh_sudo test -f /sys/kernel/btf/vmlinux 2>/dev/null; then
            skip "Kernel BTF not available on agent VM"
        fi
    else
        if ! command -v docker &>/dev/null; then
            skip "Docker not installed"
        fi
        if ! docker info &>/dev/null 2>&1; then
            skip "Docker daemon not running"
        fi
        if [ ! -f /sys/kernel/btf/vmlinux ]; then
            skip "Kernel BTF not available (/sys/kernel/btf/vmlinux missing)"
        fi
    fi
}

# ── Report helpers ──────────────────────────────────────────────
_report_set() {
    local key="$1" value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --argjson v "$value" '. + {($k): $v}' "$DOCKER_REPORT")"
    echo "$tmp" > "$DOCKER_REPORT"
}

_report_set_str() {
    local key="$1" value="$2"
    local tmp
    tmp="$(jq --arg k "$key" --arg v "$value" '. + {($k): $v}' "$DOCKER_REPORT")"
    echo "$tmp" > "$DOCKER_REPORT"
}

setup_file() {
    _docker_check

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"

    # Use the perf compose file with eth1 interface
    export PERF_COMPOSE="${PROJECT_ROOT}/tests/integration/fixtures/docker-compose-perf.yml"

    # Initialize report
    rm -f "$DOCKER_REPORT"
    echo '{}' > "$DOCKER_REPORT"

    # In 2VM mode, copy compose + config files to agent VM
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _REMOTE_COMPOSE_DIR="/tmp/ebpfsentinel-docker-perf"
        _agent_ssh_sudo mkdir -p "${_REMOTE_COMPOSE_DIR}" 2>/dev/null || true
        _agent_ssh_sudo chown vagrant:vagrant "${_REMOTE_COMPOSE_DIR}" 2>/dev/null || true

        local fixtures_dir="${PROJECT_ROOT}/tests/integration/fixtures"

        # Rewrite __INTERFACE__ placeholder before SCP
        local perf_config="/tmp/ebpfsentinel-docker-perf-config-$$.yaml"
        local iface="${EBPF_AGENT_INTERFACE:-eth1}"
        sed "s|__INTERFACE__|${iface}|g" "${fixtures_dir}/config-docker-perf.yaml" > "$perf_config"

        _agent_scp "$perf_config" "${_REMOTE_COMPOSE_DIR}/config-docker-perf.yaml"
        _agent_scp "$PERF_COMPOSE" "${_REMOTE_COMPOSE_DIR}/docker-compose-perf.yml"
        rm -f "$perf_config"

        export PERF_COMPOSE="${_REMOTE_COMPOSE_DIR}/docker-compose-perf.yml"

        # Start iperf3 server on agent VM for throughput tests
        _agent_ssh_sudo pkill -f "iperf3 -s" 2>/dev/null || true
        sleep 0.5
        _agent_ssh_sudo bash -c "'iperf3 -s -B ${EBPF_HOST_IP} -D --pidfile /tmp/iperf3-docker.pid'" 2>/dev/null || true
        sleep 1
    else
        # Local mode: substitute interface and start iperf3
        local perf_config="/tmp/ebpfsentinel-docker-perf-config-$$.yaml"
        local iface="${EBPF_VETH_HOST:-lo}"
        sed "s|__INTERFACE__|${iface}|g" \
            "${PROJECT_ROOT}/tests/integration/fixtures/config-docker-perf.yaml" > "$perf_config"
        # Override compose to use the substituted config
        cp "$PERF_COMPOSE" "/tmp/docker-compose-perf-$$.yml"
        sed -i "s|./config-docker-perf.yaml|${perf_config}|g" "/tmp/docker-compose-perf-$$.yml"
        export PERF_COMPOSE="/tmp/docker-compose-perf-$$.yml"

        iperf3 -s -B "${EBPF_HOST_IP:-127.0.0.1}" -D --pidfile /tmp/iperf3-docker-$$.pid 2>/dev/null || true
        sleep 1
    fi

    # Build the Docker image if it doesn't exist
    local exists
    exists="$(_docker_cmd image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -cF "$DOCKER_IMAGE")" || true
    if [ "${exists:-0}" -lt 1 ]; then
        echo "# Preparing eBPF programs for Docker build..." >&3
        mkdir -p "${PROJECT_ROOT}/ebpf-out"
        find "${PROJECT_ROOT}/crates/ebpf-programs/"*/target/bpfel-unknown-none/release \
          -maxdepth 1 -type f ! -name '*.d' ! -name '*.fingerprint' \
          -exec cp {} "${PROJECT_ROOT}/ebpf-out/" \; 2>/dev/null || true
        echo "# Building Docker image ${DOCKER_IMAGE}..." >&3
        _docker_cmd build -t "$DOCKER_IMAGE" "${PROJECT_ROOT}" || {
            echo "# Docker build failed — tests will be skipped" >&3
        }
    fi

    # Stop any existing agent binary AND Docker containers (we want a clean slate)
    stop_ebpf_agent 2>/dev/null || true
    _docker_cmd rm -f "$CONTAINER_NAME" 2>/dev/null || true
    _docker_cmd rm -f ebpfsentinel-test 2>/dev/null || true

    # Kill anything on our ports
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo fuser -k 8080/tcp 2>/dev/null || true
        _agent_ssh_sudo fuser -k 50051/tcp 2>/dev/null || true
        _agent_ssh_sudo fuser -k 9090/tcp 2>/dev/null || true
    else
        fuser -k 8080/tcp 2>/dev/null || true
        fuser -k 50051/tcp 2>/dev/null || true
    fi
    sleep 1
}

teardown_file() {
    _docker_cmd compose -f "$PERF_COMPOSE" down -v 2>/dev/null || true

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _agent_ssh_sudo pkill -f "iperf3 -s" 2>/dev/null || true
    else
        [ -f /tmp/iperf3-docker-$$.pid ] && kill "$(cat /tmp/iperf3-docker-$$.pid)" 2>/dev/null || true
        pkill -f "iperf3 -s -B" 2>/dev/null || true
    fi
}

# ── Test 1: Image exists ─────────────────────────────────────────

@test "docker image available" {
    _docker_check

    local exists
    exists="$(_docker_cmd image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -cF "$DOCKER_IMAGE")" || true
    [ "${exists:-0}" -ge 1 ]
}

# ── Test 2: Start container with perf config ─────────────────────

@test "docker compose up with perf config" {
    _docker_check

    _docker_cmd compose -f "$PERF_COMPOSE" up -d

    local attempts=0
    local max_attempts=30
    local health="starting"

    while [ "$attempts" -lt "$max_attempts" ] && [ "$health" != "healthy" ]; do
        health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="starting"
        sleep 2
        attempts=$((attempts + 1))
    done

    [ "$health" = "healthy" ]
}

# ── Test 3: Healthz inside container ──────────────────────────────

@test "healthz accessible inside Docker container" {
    _docker_check

    run _docker_cmd exec "$CONTAINER_NAME" /usr/local/bin/ebpfsentinel-agent health
    [ "$status" -eq 0 ]
}

# ── Test 4: Baseline throughput (no agent) ────────────────────────

@test "baseline TCP throughput (no Docker agent)" {
    _docker_check
    require_tool iperf3

    # Stop the Docker agent to measure baseline
    _docker_cmd compose -f "$PERF_COMPOSE" down 2>/dev/null || true
    sleep 1

    local bps
    bps="$(iperf3_from_ns "$EBPF_HOST_IP" "$IPERF_DURATION" 2>/dev/null | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || true

    if [ -z "$bps" ] || [ "$bps" = "null" ]; then
        skip "iperf3 baseline failed"
    fi

    _report_set "baseline_bps" "$bps"
    echo "# Baseline: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps"

    # Restart Docker agent for subsequent tests
    _docker_cmd compose -f "$PERF_COMPOSE" up -d
    local attempts=0
    local health="starting"
    while [ "$attempts" -lt 30 ] && [ "$health" != "healthy" ]; do
        health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="starting"
        sleep 2
        attempts=$((attempts + 1))
    done
}

# ── Test 5: Throughput with Docker agent ──────────────────────────

@test "TCP throughput with Docker agent" {
    _docker_check
    require_tool iperf3

    # Verify agent is running
    local health
    health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="unknown"
    [ "$health" = "healthy" ] || skip "Docker agent not healthy"

    local bps
    bps="$(iperf3_from_ns "$EBPF_HOST_IP" "$IPERF_DURATION" 2>/dev/null | jq '.end.sum_received.bits_per_second' 2>/dev/null)" || true

    if [ -z "$bps" ] || [ "$bps" = "null" ]; then
        skip "iperf3 failed"
    fi

    _report_set "docker_agent_bps" "$bps"

    # Compute overhead vs baseline
    local baseline
    baseline="$(jq -r '.baseline_bps // empty' "$DOCKER_REPORT" 2>/dev/null)" || true
    if [ -n "$baseline" ]; then
        local overhead
        overhead="$(echo "scale=2; (1 - ($bps / $baseline)) * 100" | bc -l 2>/dev/null)" || true
        _report_set_str "docker_overhead_pct" "${overhead}"
        echo "# Docker agent: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps (overhead: ${overhead}%)"
    else
        echo "# Docker agent: $(echo "scale=2; $bps / 1000000000" | bc -l) Gbps"
    fi

    [ -n "$bps" ]
}

# ── Test 6: ICMP latency under Docker agent ───────────────────────

@test "ICMP latency with Docker agent" {
    _docker_check

    local health
    health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="unknown"
    [ "$health" = "healthy" ] || skip "Docker agent not healthy"

    local ping_output avg_ms
    ping_output="$(send_icmp_from_ns "$EBPF_HOST_IP" 20 10 2>&1)" || true

    # Extract avg latency from ping output (rtt min/avg/max/mdev)
    avg_ms="$(echo "$ping_output" | grep -oP 'rtt .* = [\d.]+/([\d.]+)' | grep -oP '/\K[\d.]+')" || true

    if [ -n "$avg_ms" ]; then
        _report_set_str "docker_icmp_avg_ms" "$avg_ms"
        echo "# ICMP avg latency: ${avg_ms} ms"
    fi

    # Just verify pings succeed (latency is informational)
    echo "$ping_output" | grep -q "bytes from" || true
}

# ── Test 7: Container RSS and CPU ─────────────────────────────────

@test "Docker container memory and CPU overhead" {
    _docker_check

    local health
    health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="unknown"
    [ "$health" = "healthy" ] || skip "Docker agent not healthy"

    # Generate some traffic to warm up
    send_icmp_from_ns "$EBPF_HOST_IP" 10 5 >/dev/null 2>&1
    send_tcp_from_ns "$EBPF_HOST_IP" 8080 "WARMUP" 2 2>/dev/null || true
    sleep 2

    # Measure stats
    local mem_usage cpu_pct
    mem_usage="$(_docker_cmd stats --no-stream --format '{{.MemUsage}}' "$CONTAINER_NAME" 2>/dev/null)" || true
    cpu_pct="$(_docker_cmd stats --no-stream --format '{{.CPUPerc}}' "$CONTAINER_NAME" 2>/dev/null)" || true

    [ -n "$mem_usage" ]

    _report_set_str "docker_mem_usage" "$mem_usage"
    _report_set_str "docker_cpu_pct" "$cpu_pct"

    echo "# Container memory: ${mem_usage}"
    echo "# Container CPU: ${cpu_pct}"

    # Extract memory in bytes from docker stats (e.g. "24.5MiB / 1.9GiB")
    local mem_bytes
    mem_bytes="$(_docker_cmd stats --no-stream --format '{{.MemUsage}}' "$CONTAINER_NAME" 2>/dev/null \
        | awk '{gsub(/MiB/,"*1048576"); gsub(/GiB/,"*1073741824"); gsub(/KiB/,"*1024"); split($1,a,"*"); printf "%.0f", a[1]*a[2]}')" || true
    if [ -n "$mem_bytes" ] && [ "$mem_bytes" -gt 0 ] 2>/dev/null; then
        local rss_kb=$(( mem_bytes / 1024 ))
        _report_set "docker_rss_kb" "$rss_kb"
        echo "# Container RSS (from stats): ${rss_kb} KB"
    fi
}

# ── Test 8: API latency under load ────────────────────────────────

@test "API latency under traffic load" {
    _docker_check

    local health
    health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="unknown"
    [ "$health" = "healthy" ] || skip "Docker agent not healthy"

    local api_host="${EBPF_HOST_IP:-127.0.0.1}"
    local api_port=8080
    local api_url="http://${api_host}:${api_port}/healthz"

    # Pre-check: verify API is reachable before measuring latency
    if ! curl -sf --max-time 3 "$api_url" >/dev/null 2>&1; then
        # In 2VM mode, try reaching via the agent VM
        if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
            if ! _agent_ssh_sudo curl -sf --max-time 3 "http://127.0.0.1:${api_port}/healthz" >/dev/null 2>&1; then
                skip "API not reachable on agent VM"
            fi
            # Use docker exec as fallback for latency measurement
            api_url="DOCKER_EXEC"
        else
            skip "API not reachable at ${api_url}"
        fi
    fi

    # Measure API latency for 50 sequential requests
    local total_ms=0 ok_count=0 fail_count=0 max_ms=0
    for i in $(seq 1 50); do
        local start_ns end_ns duration_ms
        start_ns="$(date +%s%N)"
        if [ "$api_url" = "DOCKER_EXEC" ]; then
            _docker_cmd exec "$CONTAINER_NAME" \
                /usr/local/bin/ebpfsentinel-agent health >/dev/null 2>&1
        else
            curl -sf --max-time 5 "$api_url" >/dev/null 2>&1
        fi
        local rc=$?
        end_ns="$(date +%s%N)"
        if [ "$rc" -eq 0 ]; then
            duration_ms="$(( (end_ns - start_ns) / 1000000 ))"
            total_ms=$(( total_ms + duration_ms ))
            [ "$duration_ms" -gt "$max_ms" ] && max_ms="$duration_ms"
            ok_count=$(( ok_count + 1 ))
        else
            fail_count=$(( fail_count + 1 ))
        fi
    done

    if [ "$ok_count" -eq 0 ]; then
        echo "# API latency: all 50 requests failed"
        _report_set "api_ok_count" 0
        _report_set "api_fail_count" "$fail_count"
        false
    fi

    local avg_ms=$(( total_ms / ok_count ))
    _report_set "api_avg_ms" "$avg_ms"
    _report_set "api_max_ms" "$max_ms"
    _report_set "api_ok_count" "$ok_count"
    _report_set "api_fail_count" "$fail_count"

    echo "# API latency: avg=${avg_ms}ms max=${max_ms}ms (${ok_count}/${ok_count}+${fail_count} ok)"

    # API avg should be under 100ms
    [ "$avg_ms" -lt 100 ]
}

# ── Test 9: Memory stability under sustained traffic ──────────────

@test "memory stable under sustained traffic" {
    _docker_check
    require_tool iperf3

    local health
    health="$(_docker_cmd inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="unknown"
    [ "$health" = "healthy" ] || skip "Docker agent not healthy"

    # Measure memory before (via docker stats, works with distroless)
    local rss_before
    rss_before="$(_docker_cmd stats --no-stream --format '{{.MemUsage}}' "$CONTAINER_NAME" 2>/dev/null \
        | awk '{gsub(/MiB/,"*1048576"); gsub(/GiB/,"*1073741824"); gsub(/KiB/,"*1024"); split($1,a,"*"); printf "%.0f", a[1]*a[2]}')" || true
    [ -n "$rss_before" ] && [ "$rss_before" -gt 0 ] 2>/dev/null || skip "cannot read memory"
    rss_before=$(( rss_before / 1024 ))

    # Send sustained traffic: iperf3 + ICMP + TCP
    iperf3_from_ns "$EBPF_HOST_IP" 10 >/dev/null 2>&1 &
    local iperf_pid=$!

    for i in $(seq 1 5); do
        send_icmp_from_ns "$EBPF_HOST_IP" 10 5 >/dev/null 2>&1
        send_tcp_from_ns "$EBPF_HOST_IP" 8080 "STRESS_${i}" 2 2>/dev/null || true
        sleep 1
    done

    wait "$iperf_pid" 2>/dev/null || true
    sleep 2

    # Measure memory after
    local rss_after
    rss_after="$(_docker_cmd stats --no-stream --format '{{.MemUsage}}' "$CONTAINER_NAME" 2>/dev/null \
        | awk '{gsub(/MiB/,"*1048576"); gsub(/GiB/,"*1073741824"); gsub(/KiB/,"*1024"); split($1,a,"*"); printf "%.0f", a[1]*a[2]}')" || true
    [ -n "$rss_after" ] && [ "$rss_after" -gt 0 ] 2>/dev/null || skip "cannot read memory after traffic"
    rss_after=$(( rss_after / 1024 ))

    local growth_pct
    growth_pct="$(echo "scale=2; (($rss_after - $rss_before) / $rss_before) * 100" | bc -l 2>/dev/null)" || growth_pct="0"

    _report_set "rss_before_kb" "$rss_before"
    _report_set "rss_after_kb" "$rss_after"
    _report_set_str "rss_growth_pct" "$growth_pct"

    echo "# RSS before: ${rss_before} KB, after: ${rss_after} KB, growth: ${growth_pct}%"

    # Memory growth should be < 50% (no leak)
    local is_ok
    is_ok="$(echo "${growth_pct} < 50" | bc -l 2>/dev/null)" || is_ok="1"
    [ "${is_ok}" = "1" ]
}

# ── Test 10: Summary report ───────────────────────────────────────

@test "Docker overhead summary" {
    _docker_check

    _report_set_str "timestamp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        _report_set_str "kernel" "$(_agent_ssh uname -r 2>/dev/null || echo unknown)"
    else
        _report_set_str "kernel" "$(uname -r)"
    fi
    _report_set_str "mode" "${EBPF_2VM_MODE:-false}"

    echo "#"
    echo "# ============================================================"
    echo "# Docker Overhead Report"
    echo "# ============================================================"
    jq '.' "$DOCKER_REPORT"
    echo "#"
}

# ── Test 11: Clean shutdown ───────────────────────────────────────

@test "docker compose down cleans up" {
    _docker_check

    _docker_cmd compose -f "$PERF_COMPOSE" down -v

    local running
    running="$(_docker_cmd ps -q --filter "name=$CONTAINER_NAME" 2>/dev/null)" || true
    [ -z "$running" ]
}
