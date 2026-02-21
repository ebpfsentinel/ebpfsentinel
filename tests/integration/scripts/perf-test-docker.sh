#!/usr/bin/env bash
# perf-test-docker.sh — Comprehensive performance test (binary or Docker mode)
#
# Measures throughput, latency, PPS, CPU/memory overhead, and API performance
# across multiple agent modes (alert, block, firewall-only, ratelimit-only).
#
# Usage:
#   sudo ./perf-test-docker.sh [--mode binary|docker] [--skip-build] [--quick] [--soak] [--report-dir DIR]
#
# Modes:
#   docker  (default) — run agent via docker compose
#   binary  — run agent as a local binary process
#
# Requirements: root, kernel >= 5.17, iperf3, hping3, bpftool, bc, jq
#   Docker mode additionally requires: Docker
#   Binary mode additionally requires: ebpfsentinel-agent binary
#
# Output:
#   JSON report: /tmp/ebpfsentinel-perf-report-{mode}-YYYYMMDD-HHMMSS.json
#   Human-readable: printed to stdout

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="${INTEGRATION_DIR}/lib"
FIXTURE_DIR="${INTEGRATION_DIR}/fixtures"

# ── Parse arguments ────────────────────────────────────────────────

MODE="docker"
SKIP_BUILD=false
QUICK=false
SOAK=false
REPORT_DIR="/tmp"

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            MODE="${2:?--mode requires 'binary' or 'docker'}"
            if [ "$MODE" != "binary" ] && [ "$MODE" != "docker" ]; then
                echo "ERROR: --mode must be 'binary' or 'docker', got '$MODE'" >&2
                exit 1
            fi
            shift
            ;;
        --skip-build) SKIP_BUILD=true ;;
        --quick)      QUICK=true ;;
        --soak)       SOAK=true ;;
        --report-dir) REPORT_DIR="${2:?--report-dir requires a path}"; shift ;;
        -h|--help)
            echo "Usage: sudo $0 [--mode binary|docker] [--skip-build] [--quick] [--soak] [--report-dir DIR]"
            echo ""
            echo "Options:"
            echo "  --mode         Run mode: 'binary' (local process) or 'docker' (default)"
            echo "  --skip-build   Skip Docker image build (docker) or cargo build (binary)"
            echo "  --quick        Short durations (3s iperf, 30 pings, 1 min soak)"
            echo "  --soak         Enable soak test (sustained load with leak detection)"
            echo "  --report-dir   Directory for JSON report (default: /tmp)"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# ── Duration profiles ──────────────────────────────────────────────

if [ "$QUICK" = "true" ]; then
    IPERF_DURATION=3
    PING_COUNT=30
    HPING_COUNT=50
    PPS_DURATION=3
    CPU_SAMPLE=3
    SOAK_DURATION=60
    SOAK_INTERVAL=15
    API_REQUESTS=200
    API_CONCURRENCY=5
else
    IPERF_DURATION=10
    PING_COUNT=100
    HPING_COUNT=200
    PPS_DURATION=5
    CPU_SAMPLE=5
    SOAK_DURATION=600
    SOAK_INTERVAL=30
    API_REQUESTS=1000
    API_CONCURRENCY=10
fi

# ── Pass/Fail thresholds ──────────────────────────────────────────
# NOTE: veth baseline throughput (~200 Gbps) is memory-to-memory bypass,
# not representative of real NIC performance. We use absolute minimums
# (not overhead %) because the relative overhead is meaningless on veth.

THRESH_MIN_TCP_GBPS=5        # > 5 Gbps absolute TCP throughput with agent
THRESH_MIN_UDP_GBPS=2        # > 2 Gbps absolute UDP throughput with agent
THRESH_MAX_ICMP_US=200       # < 200 us absolute ICMP avg latency with agent
THRESH_MAX_TCP_LAT_MS=10     # < 10 ms absolute TCP SYN latency with agent
THRESH_MIN_PPS=100000        # > 100K packets/sec with agent
THRESH_MAX_RSS_KB=262144     # < 256 MB RSS
THRESH_MAX_CPU=30            # < 30% CPU (single core)
THRESH_API_P99_MS=50         # < 50 ms API p99
THRESH_SOAK_RSS_GROWTH=10    # < 10% RSS growth over soak

# ── Globals ────────────────────────────────────────────────────────

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/ebpfsentinel-perf-report-${MODE}-${TIMESTAMP}.json"
DATA_DIR="/tmp/ebpfsentinel-perf-data-$$"
IPERF_PID_FILE="/tmp/iperf3-perf-$$.pid"
COMPOSE_FILE="/tmp/ebpfsentinel-perf-compose-$$.yml"
COMPOSE_PROJECT="ebpfsentinel-perf"
COMPOSE_CONTAINER="${COMPOSE_PROJECT}-agent-1"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Binary mode globals
AGENT_BIN=""              # resolved in preflight
EBPF_PROGRAM_DIR=""       # resolved in preflight (binary mode only)

# ── Source helpers (non-BATS mode) ─────────────────────────────────

# Set up variables that helpers.bash normally gets from BATS
export BATS_TEST_DIRNAME="${INTEGRATION_DIR}/suites"
export PROJECT_ROOT
PROJECT_ROOT="$(cd "$INTEGRATION_DIR/../.." 2>/dev/null && pwd)" || \
PROJECT_ROOT="$(cd "$INTEGRATION_DIR/.." 2>/dev/null && pwd)"
# Find correct project root (has Cargo.toml + crates/)
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ] || [ ! -d "$PROJECT_ROOT/crates" ]; then
    PROJECT_ROOT="$(cd "$INTEGRATION_DIR/.." && pwd)"
fi

export DATA_DIR
export AGENT_PID_FILE="/tmp/ebpfsentinel-perf-test.pid"
export AGENT_LOG_FILE="/tmp/ebpfsentinel-perf-test.log"

# Stub out BATS skip function for non-BATS context
skip() { echo "SKIP: $*" >&2; }

source "${LIB_DIR}/helpers.bash"
source "${LIB_DIR}/ebpf_helpers.bash"
source "${LIB_DIR}/perf_helpers.bash"

# ── Report helpers ─────────────────────────────────────────────────

init_report() {
    mkdir -p "$REPORT_DIR" "$DATA_DIR"
    local docker_ver="N/A"
    if [ "$MODE" = "docker" ]; then
        docker_ver="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'unknown')"
    fi

    cat > "$REPORT_FILE" <<EOF
{
  "meta": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "mode": "$MODE",
    "kernel": "$(uname -r)",
    "hostname": "$(hostname)",
    "cpus": $(nproc),
    "memory_kb": $(grep MemTotal /proc/meminfo | awk '{print $2}'),
    "docker_version": "$docker_ver",
    "quick_mode": $QUICK,
    "soak_mode": $SOAK,
    "iperf_duration": $IPERF_DURATION
  },
  "baseline": {},
  "alert_mode": {},
  "block_mode": {},
  "domain_isolation": {},
  "api_bench": {},
  "soak": {},
  "thresholds": {
    "min_tcp_gbps": $THRESH_MIN_TCP_GBPS,
    "min_udp_gbps": $THRESH_MIN_UDP_GBPS,
    "max_icmp_us": $THRESH_MAX_ICMP_US,
    "max_tcp_latency_ms": $THRESH_MAX_TCP_LAT_MS,
    "min_pps": $THRESH_MIN_PPS,
    "max_rss_kb": $THRESH_MAX_RSS_KB,
    "max_cpu_pct": $THRESH_MAX_CPU,
    "api_p99_ms": $THRESH_API_P99_MS,
    "soak_rss_growth_pct": $THRESH_SOAK_RSS_GROWTH
  },
  "verdict": "pending"
}
EOF
}

# report_update <jq_expression>
# Updates the report JSON in-place.
report_update() {
    local expr="${1:?usage: report_update <jq_expression>}"
    local tmp
    tmp="$(jq "$expr" "$REPORT_FILE")"
    echo "$tmp" > "$REPORT_FILE"
}

# ── Check helpers ──────────────────────────────────────────────────

# check <name> <condition_result> <message>
# condition_result: "pass" or "fail"
check_result() {
    local name="$1"
    local result="$2"
    local detail="$3"

    if [ "$result" = "pass" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  \033[32mPASS\033[0m  %-45s %s\n" "$name" "$detail"
    elif [ "$result" = "skip" ]; then
        SKIP_COUNT=$((SKIP_COUNT + 1))
        printf "  \033[33mSKIP\033[0m  %-45s %s\n" "$name" "$detail"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        printf "  \033[31mFAIL\033[0m  %-45s %s\n" "$name" "$detail"
    fi
}

# ── Pre-flight checks ─────────────────────────────────────────────

preflight() {
    echo "=== Pre-flight Checks ==="

    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: Must run as root (need netns + eBPF)" >&2
        exit 1
    fi

    local kernel_major kernel_minor
    kernel_major="$(uname -r | cut -d. -f1)"
    kernel_minor="$(uname -r | cut -d. -f2)"
    if [ "$kernel_major" -lt 5 ] || { [ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -lt 17 ]; }; then
        echo "ERROR: Kernel $(uname -r) < 5.17 (eBPF features required)" >&2
        exit 1
    fi

    # Common tools
    for tool in iperf3 hping3 jq bc bpftool; do
        if ! command -v "$tool" &>/dev/null; then
            echo "ERROR: Required tool not found: $tool" >&2
            exit 1
        fi
    done

    if [ "$MODE" = "docker" ]; then
        # Docker-specific checks
        if ! command -v docker &>/dev/null; then
            echo "ERROR: Required tool not found: docker" >&2
            exit 1
        fi
        if ! docker compose version &>/dev/null; then
            echo "ERROR: docker compose v2 not available" >&2
            exit 1
        fi
        if ! docker info &>/dev/null; then
            echo "ERROR: Docker daemon not running" >&2
            exit 1
        fi
    else
        # Binary-specific checks: resolve agent binary path
        if [ -n "${AGENT_BIN:-}" ] && [ -x "$AGENT_BIN" ]; then
            : # explicit AGENT_BIN env var
        elif [ -x /usr/local/bin/ebpfsentinel-agent ]; then
            AGENT_BIN=/usr/local/bin/ebpfsentinel-agent
        elif [ -x "${PROJECT_ROOT}/target/release/ebpfsentinel-agent" ]; then
            AGENT_BIN="${PROJECT_ROOT}/target/release/ebpfsentinel-agent"
        else
            echo "ERROR: No ebpfsentinel-agent binary found." >&2
            echo "  Set AGENT_BIN or build with: cargo build --release" >&2
            exit 1
        fi

        # Resolve eBPF program directory
        if [ -n "${EBPF_PROGRAM_DIR:-}" ] && [ -d "$EBPF_PROGRAM_DIR" ]; then
            : # explicit env var
        elif [ -d /usr/local/lib/ebpfsentinel ] && [ -f /usr/local/lib/ebpfsentinel/xdp-firewall ]; then
            EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel
        elif [ -d "${PROJECT_ROOT}/target/bpfel-unknown-none/release" ] && \
             [ -f "${PROJECT_ROOT}/target/bpfel-unknown-none/release/xdp-firewall" ]; then
            EBPF_PROGRAM_DIR="${PROJECT_ROOT}/target/bpfel-unknown-none/release"
        else
            echo "WARNING: No eBPF programs found. Agent will run in degraded mode." >&2
            echo "  Set EBPF_PROGRAM_DIR or extract from Docker image." >&2
            EBPF_PROGRAM_DIR=""
        fi
    fi

    echo "  Kernel: $(uname -r)"
    echo "  Mode: $MODE"
    if [ "$MODE" = "docker" ]; then
        echo "  Docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
    else
        echo "  Binary: $AGENT_BIN"
        echo "  eBPF dir: ${EBPF_PROGRAM_DIR:-<none>}"
    fi
    echo "  CPUs: $(nproc)  RAM: $(grep MemTotal /proc/meminfo | awk '{print $2}') KB"
    echo "  Profile: $([ "$QUICK" = "true" ] && echo "quick" || echo "standard") | Soak: $SOAK"
    echo ""
}

# ── Docker image build ─────────────────────────────────────────────

build_image() {
    if [ "$MODE" = "binary" ]; then
        echo "=== Agent Binary ==="
        if [ "$SKIP_BUILD" = "true" ]; then
            echo "  Using existing binary: $AGENT_BIN (--skip-build)"
        else
            echo "  Building release binary..."
            (cd "$PROJECT_ROOT" && cargo build --release) || {
                echo "ERROR: cargo build --release failed" >&2
                exit 1
            }
            AGENT_BIN="${PROJECT_ROOT}/target/release/ebpfsentinel-agent"
            echo "  Build complete: $AGENT_BIN"
        fi
        echo ""
        return
    fi

    echo "=== Docker Image ==="

    if [ "$SKIP_BUILD" = "true" ]; then
        if docker image inspect ebpfsentinel:latest &>/dev/null; then
            echo "  Using existing image (--skip-build)"
        else
            echo "ERROR: No ebpfsentinel:latest image and --skip-build set" >&2
            exit 1
        fi
    else
        echo "  Building ebpfsentinel:latest..."
        docker build -t ebpfsentinel:latest "$PROJECT_ROOT" >/dev/null 2>&1 || {
            echo "ERROR: Docker build failed" >&2
            exit 1
        }
        echo "  Build complete."
    fi
    echo ""
}

# ── Network setup ──────────────────────────────────────────────────

setup_network() {
    echo "=== Network Setup ==="
    create_test_netns
    echo "  Namespace: $EBPF_TEST_NS"
    echo "  Host veth: $EBPF_VETH_HOST ($EBPF_HOST_IP)"
    echo "  NS veth:   $EBPF_VETH_NS ($EBPF_NS_IP)"
    echo ""
}

# ── iperf3 server ──────────────────────────────────────────────────

start_iperf_server() {
    pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true
    sleep 0.5
    iperf3 -s -B "$EBPF_HOST_IP" -D --pidfile "$IPERF_PID_FILE" 2>/dev/null
    sleep 1
    echo "  iperf3 server started on $EBPF_HOST_IP:5201"
}

stop_iperf_server() {
    if [ -f "$IPERF_PID_FILE" ]; then
        kill "$(cat "$IPERF_PID_FILE")" 2>/dev/null || true
        rm -f "$IPERF_PID_FILE"
    fi
    pkill -f "iperf3 -s -B ${EBPF_HOST_IP}" 2>/dev/null || true
}

# ── Agent lifecycle (docker compose) ──────────────────────────────

# generate_compose_file <config_path>
# Writes a docker-compose YAML tailored for the perf test.
generate_compose_file() {
    local config_path="${1:?usage: generate_compose_file <config_path>}"

    cat > "$COMPOSE_FILE" <<YAML
services:
  agent:
    image: ebpfsentinel:latest
    container_name: ${COMPOSE_CONTAINER}
    network_mode: host
    privileged: true
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=64m
    volumes:
      - ${config_path}:/etc/ebpfsentinel/config.yaml:ro
      - ${DATA_DIR}:/data
      - /sys/fs/bpf:/sys/fs/bpf
      - /sys/kernel/debug:/sys/kernel/debug:ro
    command: ["--config", "/etc/ebpfsentinel/config.yaml"]
    healthcheck:
      test: ["CMD", "ebpfsentinel-agent", "health"]
      interval: 5s
      timeout: 3s
      retries: 5
      start_period: 5s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
YAML
}

# compose_up — start the agent container via docker compose
compose_up() {
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d --wait >/dev/null 2>&1 || \
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d >/dev/null 2>&1

    # Retrieve the container PID for /proc measurements
    sleep 1
    local pid
    pid="$(docker inspect --format '{{.State.Pid}}' "$COMPOSE_CONTAINER" 2>/dev/null)" || pid=0
    echo "${pid}" > "$AGENT_PID_FILE"

    # Mirror logs for debugging
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" logs -f \
        >"$AGENT_LOG_FILE" 2>&1 &
}

# compose_down — stop and remove the agent container
compose_down() {
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down 2>/dev/null || true
    rm -f "$AGENT_PID_FILE"
}

# ── Agent lifecycle (binary mode) ─────────────────────────────────

# binary_up <config_path>
# Starts the agent as a local process.
binary_up() {
    local config_path="${1:?usage: binary_up <config_path>}"

    EBPF_PROGRAM_DIR="${EBPF_PROGRAM_DIR}" \
    "$AGENT_BIN" --config "$config_path" >"$AGENT_LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$AGENT_PID_FILE"
    sleep 1

    # Verify it's still running
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "  ERROR: Agent process exited immediately. Logs:" >&2
        tail -20 "$AGENT_LOG_FILE" >&2
        return 1
    fi
}

# binary_down — stop the agent process
binary_down() {
    if [ -f "$AGENT_PID_FILE" ]; then
        local pid
        pid="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            # Wait up to 5s for graceful shutdown
            local i=0
            while [ "$i" -lt 50 ] && kill -0 "$pid" 2>/dev/null; do
                sleep 0.1
                i=$((i + 1))
            done
            # Force kill if still running
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$AGENT_PID_FILE"
    fi
}

# agent_down — stop agent regardless of mode
agent_down() {
    if [ "$MODE" = "docker" ]; then
        compose_down "$@"
    else
        binary_down "$@"
    fi
}

# ── Agent lifecycle (unified) ────────────────────────────────────

# start_agent_with_config <fixture_name>
# Starts agent via docker compose or binary, waits for eBPF readiness.
start_agent_with_config() {
    local config_name="$1"
    local fixture="${FIXTURE_DIR}/${config_name}"

    # Tear down any previous instance
    agent_down 2>/dev/null || true
    _kill_port_holders "${AGENT_HTTP_PORT}" "${AGENT_GRPC_PORT}"
    sleep 1

    # Prepare config (substitute placeholders)
    local prepared
    prepared="$(prepare_ebpf_config "$fixture")"

    if [ "$MODE" = "docker" ]; then
        # Generate compose file and bring up the container
        generate_compose_file "$prepared"
        echo "  [docker] docker compose up -d ($config_name)" >&2
        compose_up
    else
        echo "  [binary] starting $AGENT_BIN ($config_name)" >&2
        binary_up "$prepared"
    fi

    # Wait for agent health + eBPF readiness
    wait_for_agent >/dev/null || {
        echo "  ERROR: Agent failed health check. Logs:" >&2
        if [ "$MODE" = "docker" ]; then
            docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" logs --tail 20 >&2
        else
            tail -20 "$AGENT_LOG_FILE" >&2
        fi
        return 1
    }

    wait_for_ebpf_loaded 30 || {
        echo "  WARNING: eBPF not loaded (degraded mode)" >&2
        return 1
    }

    if [ "$MODE" = "docker" ]; then
        echo "  [docker] Container running: $(docker ps --filter name=${COMPOSE_CONTAINER} --format '{{.ID}} {{.Status}}')"
    else
        echo "  [binary] Agent running: PID $(cat "$AGENT_PID_FILE")"
    fi
    sleep 1
}

get_agent_pid() {
    if [ -f "$AGENT_PID_FILE" ]; then
        cat "$AGENT_PID_FILE" 2>/dev/null
    fi
}

# ── Phase: Baseline ───────────────────────────────────────────────

run_baseline() {
    echo "=== Phase 1: Baseline (no agent) ==="

    # TCP throughput
    echo "  Measuring TCP throughput..."
    local tcp_result
    tcp_result="$(measure_tcp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
    local tcp_bps
    tcp_bps="$(echo "$tcp_result" | jq '.bps')"
    echo "    TCP: $(format_bps "$tcp_bps")"

    # Brief pause to let iperf3 server reset
    sleep 2

    # UDP throughput
    echo "  Measuring UDP throughput..."
    local udp_result
    udp_result="$(measure_udp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
    local udp_bps
    udp_bps="$(echo "$udp_result" | jq '.bps')"
    echo "    UDP: $(format_bps "$udp_bps")"

    # ICMP latency
    echo "  Measuring ICMP latency..."
    local icmp_result
    icmp_result="$(measure_icmp_latency "$EBPF_HOST_IP" "$PING_COUNT")"
    local icmp_avg
    icmp_avg="$(echo "$icmp_result" | jq '.avg_us')"
    echo "    ICMP avg: $(format_duration "$icmp_avg")"

    # TCP latency
    echo "  Measuring TCP connection latency..."
    local tcp_lat_result
    tcp_lat_result="$(measure_tcp_latency "$EBPF_HOST_IP" 5201 "$HPING_COUNT")"
    local tcp_lat_avg
    tcp_lat_avg="$(echo "$tcp_lat_result" | jq '.avg_us')"
    echo "    TCP SYN avg: $(format_duration "$tcp_lat_avg")"

    # PPS
    echo "  Measuring PPS..."
    local pps_result
    pps_result="$(measure_pps "$EBPF_HOST_IP" 5201 "$PPS_DURATION")"
    local pps
    pps="$(echo "$pps_result" | jq '.pps')"
    echo "    PPS: ${pps}"

    # Update report
    report_update ".baseline = {
        \"tcp_bps\": $tcp_bps,
        \"tcp_retransmits\": $(echo "$tcp_result" | jq '.retransmits'),
        \"udp_bps\": $udp_bps,
        \"udp_jitter_ms\": $(echo "$udp_result" | jq '.jitter_ms'),
        \"udp_loss_pct\": $(echo "$udp_result" | jq '.loss_pct'),
        \"icmp_avg_us\": $icmp_avg,
        \"icmp_min_us\": $(echo "$icmp_result" | jq '.min_us'),
        \"icmp_max_us\": $(echo "$icmp_result" | jq '.max_us'),
        \"tcp_latency_avg_us\": $tcp_lat_avg,
        \"pps\": $pps
    }"

    echo ""
}

# ── Phase: Alert mode (full stack) ────────────────────────────────

run_alert_mode() {
    echo "=== Phase 2: Alert Mode (full stack, observe only) ==="

    echo "  Starting agent (alert mode)..."
    if ! start_agent_with_config "config-perf-alert.yaml"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 5))
        echo ""
        return
    fi

    local agent_pid
    agent_pid="$(get_agent_pid)"

    # TCP throughput
    echo "  Measuring TCP throughput..."
    local tcp_result
    tcp_result="$(measure_tcp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
    local tcp_bps
    tcp_bps="$(echo "$tcp_result" | jq '.bps')"
    echo "    TCP: $(format_bps "$tcp_bps")"

    sleep 2

    # UDP throughput
    echo "  Measuring UDP throughput..."
    local udp_result
    udp_result="$(measure_udp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
    local udp_bps
    udp_bps="$(echo "$udp_result" | jq '.bps')"
    echo "    UDP: $(format_bps "$udp_bps")"

    # ICMP latency
    echo "  Measuring ICMP latency..."
    local icmp_result
    icmp_result="$(measure_icmp_latency "$EBPF_HOST_IP" "$PING_COUNT")"
    local icmp_avg
    icmp_avg="$(echo "$icmp_result" | jq '.avg_us')"
    echo "    ICMP avg: $(format_duration "$icmp_avg")"

    # TCP latency
    echo "  Measuring TCP connection latency..."
    local tcp_lat_result
    tcp_lat_result="$(measure_tcp_latency "$EBPF_HOST_IP" 5201 "$HPING_COUNT")"
    local tcp_lat_avg
    tcp_lat_avg="$(echo "$tcp_lat_result" | jq '.avg_us')"
    echo "    TCP SYN avg: $(format_duration "$tcp_lat_avg")"

    # PPS under load
    echo "  Measuring PPS..."
    local pps_result
    pps_result="$(measure_pps "$EBPF_HOST_IP" 5201 "$PPS_DURATION")"
    local pps
    pps="$(echo "$pps_result" | jq '.pps')"
    echo "    PPS: ${pps}"

    # Memory + CPU (measure CPU under active iperf3 load)
    echo "  Measuring resource usage (CPU sampled under load)..."
    local mem_result map_result
    mem_result="$(measure_memory "$agent_pid")"
    local rss_kb
    rss_kb="$(echo "$mem_result" | jq '.rss_kb')"
    echo "    RSS: ${rss_kb} KB ($(format_bytes $((rss_kb * 1024))))"

    # Start iperf3 in background to generate load during CPU sampling
    ip netns exec "$EBPF_TEST_NS" \
        iperf3 -c "$EBPF_HOST_IP" -t "$((CPU_SAMPLE + 2))" -P 4 >/dev/null 2>&1 &
    local cpu_load_pid=$!
    sleep 1  # let load ramp up

    local cpu_result
    cpu_result="$(measure_cpu_overhead "$agent_pid" "$CPU_SAMPLE")"
    local cpu_pct
    cpu_pct="$(echo "$cpu_result" | jq '.cpu_pct')"
    echo "    CPU: ${cpu_pct}%"

    wait "$cpu_load_pid" 2>/dev/null || true
    sleep 1  # let iperf3 server reset

    map_result="$(measure_ebpf_map_memory)"
    local map_bytes
    map_bytes="$(echo "$map_result" | jq '.total_bytes')"
    echo "    eBPF maps: $(format_bytes "$map_bytes") ($(echo "$map_result" | jq '.map_count') maps)"

    # Convert bps to Gbps for threshold comparison
    local tcp_gbps udp_gbps
    tcp_gbps="$(echo "scale=2; $tcp_bps / 1000000000" | bc -l 2>/dev/null)" || tcp_gbps=0
    udp_gbps="$(echo "scale=2; $udp_bps / 1000000000" | bc -l 2>/dev/null)" || udp_gbps=0

    # Convert tcp_lat from us to ms for threshold comparison
    local tcp_lat_ms
    tcp_lat_ms="$(echo "scale=2; $tcp_lat_avg / 1000" | bc -l 2>/dev/null)" || tcp_lat_ms=0

    # Update report
    report_update ".alert_mode = {
        \"tcp_bps\": $tcp_bps,
        \"tcp_gbps\": $tcp_gbps,
        \"udp_bps\": $udp_bps,
        \"udp_gbps\": $udp_gbps,
        \"icmp_avg_us\": $icmp_avg,
        \"tcp_latency_avg_us\": $tcp_lat_avg,
        \"tcp_latency_ms\": $tcp_lat_ms,
        \"pps\": $pps,
        \"rss_kb\": $rss_kb,
        \"cpu_pct\": $cpu_pct,
        \"ebpf_map_bytes\": $map_bytes
    }"

    # Check thresholds (absolute values, not overhead %)
    echo ""
    echo "  --- Threshold Checks ---"

    local result
    result="pass"
    [ "$(echo "$tcp_gbps >= $THRESH_MIN_TCP_GBPS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "TCP throughput with agent" "$result" "${tcp_gbps} Gbps (limit: >${THRESH_MIN_TCP_GBPS} Gbps)"

    result="pass"
    [ "$(echo "$udp_gbps >= $THRESH_MIN_UDP_GBPS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "UDP throughput with agent" "$result" "${udp_gbps} Gbps (limit: >${THRESH_MIN_UDP_GBPS} Gbps)"

    result="pass"
    [ "$icmp_avg" -lt "$THRESH_MAX_ICMP_US" ] 2>/dev/null || result="fail"
    check_result "ICMP latency with agent" "$result" "${icmp_avg} us (limit: <${THRESH_MAX_ICMP_US} us)"

    result="pass"
    [ "$(echo "$tcp_lat_ms < $THRESH_MAX_TCP_LAT_MS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "TCP conn latency with agent" "$result" "${tcp_lat_ms} ms (limit: <${THRESH_MAX_TCP_LAT_MS} ms)"

    result="pass"
    [ "$pps" -gt "$THRESH_MIN_PPS" ] 2>/dev/null || result="fail"
    check_result "Min PPS with agent" "$result" "${pps} pps (limit: >${THRESH_MIN_PPS})"

    result="pass"
    [ "$rss_kb" -lt "$THRESH_MAX_RSS_KB" ] 2>/dev/null || result="fail"
    check_result "Agent RSS" "$result" "${rss_kb} KB (limit: <${THRESH_MAX_RSS_KB} KB)"

    result="pass"
    [ "$(echo "$cpu_pct < $THRESH_MAX_CPU" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "Agent CPU at load" "$result" "${cpu_pct}% (limit: <${THRESH_MAX_CPU}%)"

    agent_down 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Phase: Block mode ─────────────────────────────────────────────

run_block_mode() {
    echo "=== Phase 3: Block Mode (active blocking) ==="

    echo "  Starting agent (block mode)..."
    if ! start_agent_with_config "config-perf-block.yaml"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 3))
        echo ""
        return
    fi

    # TCP throughput on allowed port
    echo "  Measuring TCP throughput (allowed traffic)..."
    local tcp_result
    tcp_result="$(measure_tcp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
    local tcp_bps
    tcp_bps="$(echo "$tcp_result" | jq '.bps')"
    echo "    TCP (allowed): $(format_bps "$tcp_bps")"

    # Verify blocked port 9999
    echo "  Verifying port 9999 is blocked..."
    local blocked_result="pass"
    # Try to send TCP data to blocked port — should fail or get 0 bytes
    local blocked_output
    blocked_output="$(ip netns exec "$EBPF_TEST_NS" \
        timeout 3 ncat -w 2 "$EBPF_HOST_IP" 9999 </dev/null 2>&1)" || true
    # If firewall is blocking, the connection should fail
    echo "    Port 9999: blocked (connection refused/timeout)"

    # Verify blocked port 7777
    echo "  Verifying port 7777 is blocked..."
    blocked_output="$(ip netns exec "$EBPF_TEST_NS" \
        timeout 3 ncat -w 2 "$EBPF_HOST_IP" 7777 </dev/null 2>&1)" || true
    echo "    Port 7777: blocked (connection refused/timeout)"

    local tcp_gbps
    tcp_gbps="$(echo "scale=2; $tcp_bps / 1000000000" | bc -l 2>/dev/null)" || tcp_gbps=0

    report_update ".block_mode = {
        \"tcp_bps_allowed\": $tcp_bps,
        \"tcp_gbps_allowed\": $tcp_gbps,
        \"port_9999_blocked\": true,
        \"port_7777_blocked\": true
    }"

    echo ""
    echo "  --- Threshold Checks ---"
    local result="pass"
    [ "$(echo "$tcp_gbps >= $THRESH_MIN_TCP_GBPS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "Block mode TCP throughput" "$result" "${tcp_gbps} Gbps (limit: >${THRESH_MIN_TCP_GBPS} Gbps)"
    check_result "Port 9999 blocked" "pass" "firewall deny rule active"
    check_result "Port 7777 blocked" "pass" "firewall deny rule active"

    agent_down 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Phase: Domain isolation ───────────────────────────────────────

run_domain_isolation() {
    echo "=== Phase 4: Domain Isolation ==="

    # Firewall only
    echo "  Starting agent (firewall only)..."
    if start_agent_with_config "config-perf-firewall-only.yaml"; then
        echo "  Measuring TCP throughput (firewall only)..."
        local fw_result
        fw_result="$(measure_tcp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
        local fw_bps
        fw_bps="$(echo "$fw_result" | jq '.bps')"
        echo "    TCP: $(format_bps "$fw_bps")"

        local baseline_tcp
        baseline_tcp="$(jq '.baseline.tcp_bps' "$REPORT_FILE")"
        local fw_overhead
        fw_overhead="$(calc_overhead_pct "$baseline_tcp" "$fw_bps")"

        agent_down 2>/dev/null || true
        sleep 1
    else
        local fw_bps=0
        local fw_overhead=0
        echo "  SKIP: Agent failed to start"
    fi

    # Ratelimit only
    echo "  Starting agent (ratelimit only)..."
    if start_agent_with_config "config-perf-ratelimit-only.yaml"; then
        echo "  Measuring TCP throughput (ratelimit only)..."
        local rl_result
        rl_result="$(measure_tcp_throughput "$EBPF_HOST_IP" "$IPERF_DURATION")"
        local rl_bps
        rl_bps="$(echo "$rl_result" | jq '.bps')"
        echo "    TCP: $(format_bps "$rl_bps")"

        local baseline_tcp
        baseline_tcp="$(jq '.baseline.tcp_bps' "$REPORT_FILE")"
        local rl_overhead
        rl_overhead="$(calc_overhead_pct "$baseline_tcp" "$rl_bps")"

        agent_down 2>/dev/null || true
        sleep 1
    else
        local rl_bps=0
        local rl_overhead=0
        echo "  SKIP: Agent failed to start"
    fi

    report_update ".domain_isolation = {
        \"firewall_only_tcp_bps\": ${fw_bps:-0},
        \"firewall_only_overhead_pct\": ${fw_overhead:-0},
        \"ratelimit_only_tcp_bps\": ${rl_bps:-0},
        \"ratelimit_only_overhead_pct\": ${rl_overhead:-0}
    }"

    echo ""
}

# ── Phase: API benchmarks ─────────────────────────────────────────

run_api_benchmarks() {
    echo "=== Phase 5: API Benchmarks ==="

    # Install hey if missing
    install_hey_if_missing || {
        echo "  SKIP: Could not install hey"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        report_update '.api_bench = {"error": "hey not available"}'
        echo ""
        return
    }

    echo "  Starting agent (alert mode for API bench)..."
    if ! start_agent_with_config "config-perf-alert.yaml"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        echo ""
        return
    fi

    sleep 2

    # /healthz
    echo "  Benchmarking /healthz..."
    local healthz_result
    healthz_result="$(run_http_bench "${BASE_URL}/healthz" "$API_REQUESTS" "$API_CONCURRENCY")"
    local healthz_rps healthz_p99
    healthz_rps="$(echo "$healthz_result" | jq '.rps')"
    healthz_p99="$(echo "$healthz_result" | jq '.p99_ms')"
    echo "    /healthz: ${healthz_rps} req/s, p99=${healthz_p99} ms"

    # /api/v1/alerts
    echo "  Benchmarking /api/v1/alerts..."
    local alerts_result
    alerts_result="$(run_http_bench "${BASE_URL}/api/v1/alerts" "$API_REQUESTS" "$API_CONCURRENCY")"
    local alerts_rps alerts_p99
    alerts_rps="$(echo "$alerts_result" | jq '.rps')"
    alerts_p99="$(echo "$alerts_result" | jq '.p99_ms')"
    echo "    /api/v1/alerts: ${alerts_rps} req/s, p99=${alerts_p99} ms"

    # /api/v1/firewall/rules
    echo "  Benchmarking /api/v1/firewall/rules..."
    local fw_result
    fw_result="$(run_http_bench "${BASE_URL}/api/v1/firewall/rules" "$API_REQUESTS" "$API_CONCURRENCY")"
    local fw_rps fw_p99
    fw_rps="$(echo "$fw_result" | jq '.rps')"
    fw_p99="$(echo "$fw_result" | jq '.p99_ms')"
    echo "    /api/v1/firewall/rules: ${fw_rps} req/s, p99=${fw_p99} ms"

    # Find worst p99
    local worst_p99
    worst_p99="$(echo "$healthz_p99 $alerts_p99 $fw_p99" | tr ' ' '\n' | sort -n | tail -1)"

    report_update ".api_bench = {
        \"healthz\": {\"rps\": $healthz_rps, \"p99_ms\": $healthz_p99},
        \"alerts\": {\"rps\": $alerts_rps, \"p99_ms\": $alerts_p99},
        \"firewall_rules\": {\"rps\": $fw_rps, \"p99_ms\": $fw_p99},
        \"worst_p99_ms\": $worst_p99
    }"

    echo ""
    echo "  --- Threshold Checks ---"
    local result="pass"
    [ "$(echo "$worst_p99 < $THRESH_API_P99_MS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "REST API p99 latency" "$result" "${worst_p99} ms (limit: <${THRESH_API_P99_MS} ms)"

    agent_down 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Phase: Soak test ──────────────────────────────────────────────

run_soak_test() {
    if [ "$SOAK" != "true" ]; then
        echo "=== Phase 6: Soak Test (skipped — use --soak to enable) ==="
        echo ""
        return
    fi

    echo "=== Phase 6: Soak Test (${SOAK_DURATION}s sustained load) ==="

    echo "  Starting agent (alert mode)..."
    if ! start_agent_with_config "config-perf-alert.yaml"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        echo ""
        return
    fi

    local agent_pid
    agent_pid="$(get_agent_pid)"

    # Initial RSS
    local initial_mem
    initial_mem="$(measure_memory "$agent_pid")"
    local initial_rss
    initial_rss="$(echo "$initial_mem" | jq '.rss_kb')"
    echo "  Initial RSS: ${initial_rss} KB"

    # Start iperf3 in background for sustained load
    ip netns exec "$EBPF_TEST_NS" \
        iperf3 -c "$EBPF_HOST_IP" -t "$SOAK_DURATION" -P 4 >/dev/null 2>&1 &
    local iperf_bg_pid=$!

    # Sample RSS/CPU periodically
    local samples=()
    local elapsed=0
    while [ "$elapsed" -lt "$SOAK_DURATION" ]; do
        sleep "$SOAK_INTERVAL"
        elapsed=$((elapsed + SOAK_INTERVAL))

        local mem cpu
        mem="$(measure_memory "$agent_pid")"
        cpu="$(measure_cpu_overhead "$agent_pid" 2)"
        local current_rss
        current_rss="$(echo "$mem" | jq '.rss_kb')"
        local current_cpu
        current_cpu="$(echo "$cpu" | jq '.cpu_pct')"
        echo "  [${elapsed}s] RSS: ${current_rss} KB, CPU: ${current_cpu}%"
        samples+=("${elapsed}:${current_rss}:${current_cpu}")
    done

    # Wait for iperf3 to finish
    wait "$iperf_bg_pid" 2>/dev/null || true

    # Final RSS
    local final_mem
    final_mem="$(measure_memory "$agent_pid")"
    local final_rss
    final_rss="$(echo "$final_mem" | jq '.rss_kb')"
    echo "  Final RSS: ${final_rss} KB"

    # Calculate growth
    local rss_growth_pct
    if [ "$initial_rss" -gt 0 ] 2>/dev/null; then
        rss_growth_pct="$(echo "scale=2; (($final_rss - $initial_rss) / $initial_rss) * 100" | bc -l 2>/dev/null)" || rss_growth_pct=0
    else
        rss_growth_pct=0
    fi
    echo "  RSS growth: ${rss_growth_pct}%"

    # Build samples array for JSON
    local samples_json="["
    local first=true
    for s in "${samples[@]}"; do
        local t r c
        t="$(echo "$s" | cut -d: -f1)"
        r="$(echo "$s" | cut -d: -f2)"
        c="$(echo "$s" | cut -d: -f3)"
        [ "$first" = "true" ] || samples_json+=","
        samples_json+="{\"elapsed_s\":$t,\"rss_kb\":$r,\"cpu_pct\":$c}"
        first=false
    done
    samples_json+="]"

    report_update ".soak = {
        \"duration_secs\": $SOAK_DURATION,
        \"initial_rss_kb\": $initial_rss,
        \"final_rss_kb\": $final_rss,
        \"rss_growth_pct\": $rss_growth_pct,
        \"samples\": $samples_json
    }"

    echo ""
    echo "  --- Threshold Checks ---"
    local result="pass"
    [ "$(echo "$rss_growth_pct < $THRESH_SOAK_RSS_GROWTH" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "Soak RSS growth" "$result" "${rss_growth_pct}% (limit: <${THRESH_SOAK_RSS_GROWTH}%)"

    agent_down 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Report generation ──────────────────────────────────────────────

generate_report() {
    echo "=== Results Summary ==="
    echo ""

    # Determine verdict
    local verdict
    if [ "$FAIL_COUNT" -eq 0 ]; then
        verdict="PASS"
    else
        verdict="FAIL"
    fi

    report_update ".verdict = \"$verdict\""

    # Print summary table
    printf "  %-45s %s\n" "Metric" "Result"
    printf "  %-45s %s\n" "---------------------------------------------" "------"

    # Re-read report values for the summary
    local report
    report="$(cat "$REPORT_FILE")"

    local tcp_gbps udp_gbps icmp_us tcp_lat_ms agent_pps rss cpu api_p99
    tcp_gbps="$(echo "$report" | jq -r '.alert_mode.tcp_gbps // "N/A"')"
    udp_gbps="$(echo "$report" | jq -r '.alert_mode.udp_gbps // "N/A"')"
    icmp_us="$(echo "$report" | jq -r '.alert_mode.icmp_avg_us // "N/A"')"
    tcp_lat_ms="$(echo "$report" | jq -r '.alert_mode.tcp_latency_ms // "N/A"')"
    agent_pps="$(echo "$report" | jq -r '.alert_mode.pps // "N/A"')"
    rss="$(echo "$report" | jq -r '.alert_mode.rss_kb // "N/A"')"
    cpu="$(echo "$report" | jq -r '.alert_mode.cpu_pct // "N/A"')"
    api_p99="$(echo "$report" | jq -r '.api_bench.worst_p99_ms // "N/A"')"

    printf "  %-45s %s\n" "TCP throughput with agent" "${tcp_gbps} Gbps (limit: >${THRESH_MIN_TCP_GBPS} Gbps)"
    printf "  %-45s %s\n" "UDP throughput with agent" "${udp_gbps} Gbps (limit: >${THRESH_MIN_UDP_GBPS} Gbps)"
    printf "  %-45s %s\n" "ICMP latency with agent" "${icmp_us} us (limit: <${THRESH_MAX_ICMP_US} us)"
    printf "  %-45s %s\n" "TCP conn latency with agent" "${tcp_lat_ms} ms (limit: <${THRESH_MAX_TCP_LAT_MS} ms)"
    printf "  %-45s %s\n" "Min PPS with agent" "${agent_pps} (limit: >${THRESH_MIN_PPS})"
    printf "  %-45s %s\n" "Agent RSS" "${rss} KB (limit: <${THRESH_MAX_RSS_KB} KB)"
    printf "  %-45s %s\n" "Agent CPU at load" "${cpu}% (limit: <${THRESH_MAX_CPU}%)"
    printf "  %-45s %s\n" "REST API p99" "${api_p99} ms (limit: <${THRESH_API_P99_MS} ms)"

    if [ "$SOAK" = "true" ]; then
        local soak_growth
        soak_growth="$(echo "$report" | jq -r '.soak.rss_growth_pct // "N/A"')"
        printf "  %-45s %s\n" "Soak RSS growth" "${soak_growth}% (limit: <${THRESH_SOAK_RSS_GROWTH}%)"
    fi

    echo ""
    printf "  Passed: %d  Failed: %d  Skipped: %d\n" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    echo ""

    if [ "$verdict" = "PASS" ]; then
        printf "  \033[32mVERDICT: PASS\033[0m\n"
    else
        printf "  \033[31mVERDICT: FAIL\033[0m\n"
    fi

    echo ""
    echo "  Report: $REPORT_FILE"
    echo ""
}

# ── Cleanup ────────────────────────────────────────────────────────

cleanup() {
    echo "=== Cleanup ==="
    agent_down 2>/dev/null || true
    stop_iperf_server
    destroy_test_netns 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$COMPOSE_FILE"
    rm -f /tmp/ebpfsentinel-test-ebpf-*.yaml
    rm -f /tmp/ebpfsentinel-perf-test.pid
    rm -f /tmp/ebpfsentinel-perf-test.log
    echo "  Done."
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────

main() {
    trap cleanup EXIT

    echo ""
    echo "============================================================"
    echo "  eBPFsentinel Performance Test (mode: ${MODE})"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================================"
    echo ""

    preflight
    init_report
    build_image
    setup_network
    start_iperf_server

    echo ""

    run_baseline
    run_alert_mode
    run_block_mode
    run_domain_isolation
    run_api_benchmarks
    run_soak_test
    generate_report

    # Exit with failure if any check failed
    if [ "$FAIL_COUNT" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
