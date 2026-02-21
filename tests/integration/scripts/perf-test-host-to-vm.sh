#!/usr/bin/env bash
# perf-test-host-to-vm.sh — Host-to-VM performance test over VirtualBox private network
#
# Topology:
#   Host (192.168.56.1) ──> Vagrant VM (192.168.56.10)
#   Traffic crosses a real VirtualBox host-only adapter (not veth memory bypass).
#
# Measures throughput, latency, PPS, CPU/RSS, API perf, and blocking verification
# with the agent running inside the VM (binary and/or Docker mode).
#
# Usage:
#   ./perf-test-host-to-vm.sh [--mode binary|docker|both] [--quick] [--soak]
#                              [--skip-provision] [--report-dir DIR]
#
# Requirements (host):  vagrant, iperf3, hping3 (sudo), ping, curl, jq
# Optional (host):      hey (API benchmarks skipped if missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VAGRANT_DIR="${INTEGRATION_DIR}/vagrant"
FIXTURE_DIR="${INTEGRATION_DIR}/fixtures"

# ── Parse arguments ────────────────────────────────────────────────

MODE="both"
QUICK=false
SOAK=false
SKIP_PROVISION=false
REPORT_DIR="/tmp"

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            MODE="${2:?--mode requires 'binary', 'docker', or 'both'}"
            if [ "$MODE" != "binary" ] && [ "$MODE" != "docker" ] && [ "$MODE" != "both" ]; then
                echo "ERROR: --mode must be 'binary', 'docker', or 'both', got '$MODE'" >&2
                exit 1
            fi
            shift
            ;;
        --quick)          QUICK=true ;;
        --soak)           SOAK=true ;;
        --skip-provision) SKIP_PROVISION=true ;;
        --report-dir)     REPORT_DIR="${2:?--report-dir requires a path}"; shift ;;
        -h|--help)
            echo "Usage: $0 [--mode binary|docker|both] [--quick] [--soak]"
            echo "                                 [--skip-provision] [--report-dir DIR]"
            echo ""
            echo "Options:"
            echo "  --mode             Run mode: 'binary', 'docker', or 'both' (default)"
            echo "  --quick            Short durations (3s iperf, 30 pings)"
            echo "  --soak             Enable soak test (sustained load with leak detection)"
            echo "  --skip-provision   Skip vagrant up / provisioning"
            echo "  --report-dir       Directory for JSON reports (default: /tmp)"
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

# ── Network constants ──────────────────────────────────────────────

VM_IP="192.168.56.10"
HOST_IP="192.168.56.1"
WHITELIST_SUBNET="192.168.56.0/24"
AGENT_HTTP_PORT=18080

# ── Pass/Fail thresholds ──────────────────────────────────────────
# VirtualBox host-only network: ~1-5 Gbps (much lower than veth ~200 Gbps)

THRESH_MIN_TCP_MBPS=500        # > 500 Mbps
THRESH_MIN_UDP_MBPS=200        # > 200 Mbps
THRESH_MAX_ICMP_MS=5           # < 5 ms avg
THRESH_MAX_TCP_LAT_MS=50       # < 50 ms
THRESH_MIN_PPS=10000           # > 10K pps
THRESH_MAX_RSS_KB=262144       # < 256 MB
THRESH_MAX_CPU=30              # < 30%
THRESH_API_P99_MS=100          # < 100 ms
THRESH_SOAK_RSS_GROWTH=10      # < 10% RSS growth over soak

# ── Globals ────────────────────────────────────────────────────────

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
VM_INTERFACE=""                # detected dynamically (enp0s8)
CURRENT_REPORT_FILE=""         # set per mode

# ── Helpers ────────────────────────────────────────────────────────

# check_result <name> <pass|fail|skip> <detail>
check_result() {
    local name="$1" result="$2" detail="$3"
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

# report_update <jq_expression>
report_update() {
    local expr="${1:?usage: report_update <jq_expression>}"
    local tmp
    tmp="$(jq "$expr" "$CURRENT_REPORT_FILE")"
    echo "$tmp" > "$CURRENT_REPORT_FILE"
}

# safe_jq <file> <expr> [default]
safe_jq() {
    local file="$1" expr="$2" default="${3:-N/A}"
    jq -r "$expr // empty" "$file" 2>/dev/null || echo "$default"
}

# format_overhead <val1> <val2> <higher_is_worse>
format_overhead() {
    local bval="$1" dval="$2" higher_is_worse="${3:-true}"
    if [ "$bval" = "N/A" ] || [ "$dval" = "N/A" ] || [ "$bval" = "0" ]; then
        echo "N/A"; return
    fi
    local raw_pct
    if [ "$higher_is_worse" = "true" ]; then
        raw_pct="$(echo "scale=4; (($dval - $bval) / $bval) * 100" | bc -l 2>/dev/null)" || { echo "N/A"; return; }
    else
        raw_pct="$(echo "scale=4; (($bval - $dval) / $bval) * 100" | bc -l 2>/dev/null)" || { echo "N/A"; return; }
    fi
    local pct
    pct="$(LC_NUMERIC=C printf '%.1f' "$raw_pct" 2>/dev/null)" || { echo "N/A"; return; }
    if [[ "$pct" == -* ]]; then echo "${pct}%"; else echo "+${pct}%"; fi
}

format_value() {
    local val="$1" unit="$2"
    if [ "$val" = "N/A" ] || [ -z "$val" ]; then echo "N/A"; else echo "${val} ${unit}"; fi
}

# ── VM helpers (run commands via vagrant ssh) ──────────────────────

# vm_ssh <command>
# Runs a command inside the VM. Uses -- -q for quiet SSH.
vm_ssh() {
    cd "$VAGRANT_DIR" && vagrant ssh -c "$1" -- -q
}

# ── Pre-flight (host) ─────────────────────────────────────────────

preflight_host() {
    echo "=== Pre-flight Checks (host) ==="

    if ! command -v vagrant &>/dev/null; then
        echo "ERROR: vagrant not found in PATH" >&2; exit 1
    fi

    for tool in iperf3 ping curl jq; do
        if ! command -v "$tool" &>/dev/null; then
            echo "ERROR: Required tool not found: $tool" >&2; exit 1
        fi
    done

    # hping3 requires sudo for raw sockets
    if ! command -v hping3 &>/dev/null; then
        echo "WARNING: hping3 not found — PPS and TCP latency tests will be skipped" >&2
    elif ! sudo -n true 2>/dev/null; then
        echo "WARNING: hping3 requires passwordless sudo — PPS and TCP latency tests will be skipped" >&2
    fi

    if ! command -v hey &>/dev/null; then
        echo "WARNING: hey not found — API benchmarks will be skipped" >&2
    fi

    if [ ! -f "${VAGRANT_DIR}/Vagrantfile" ]; then
        echo "ERROR: No Vagrantfile at ${VAGRANT_DIR}/Vagrantfile" >&2; exit 1
    fi

    mkdir -p "$REPORT_DIR"

    echo "  Vagrant: $(vagrant --version)"
    echo "  VM IP: $VM_IP  Host IP: $HOST_IP"
    echo "  Mode: $MODE"
    echo "  Profile: $([ "$QUICK" = "true" ] && echo "quick" || echo "standard") | Soak: $SOAK"
    echo "  Reports: $REPORT_DIR"
    echo ""
}

# ── VM lifecycle ───────────────────────────────────────────────────

vm_up() {
    if [ "$SKIP_PROVISION" = "true" ]; then
        echo "=== VM — skip provision (--skip-provision) ==="
        cd "$VAGRANT_DIR" && vagrant status | grep -q running || {
            echo "  VM not running — starting without provision..."
            cd "$VAGRANT_DIR" && vagrant up --no-provision
        }
    else
        echo "=== VM — vagrant up ==="
        cd "$VAGRANT_DIR" && vagrant up
    fi
    echo ""
}

vm_sync() {
    echo "=== VM — rsync latest code ==="
    cd "$VAGRANT_DIR" && vagrant rsync
    echo ""
}

vm_detect_interface() {
    echo "=== VM — Detect private network interface ==="
    VM_INTERFACE="$(vm_ssh "ip -o addr show | grep '${VM_IP}/' | awk '{print \$2}'" | tr -d '\r\n')"
    if [ -z "$VM_INTERFACE" ]; then
        echo "ERROR: Could not find interface with IP $VM_IP in VM" >&2
        echo "  Run 'vagrant ssh -c \"ip addr\"' to debug" >&2
        exit 1
    fi
    echo "  Interface: $VM_INTERFACE (IP: $VM_IP)"
    echo ""
}

# ── Build steps inside VM ─────────────────────────────────────────

vm_build_binary() {
    echo "=== VM — Build agent binary (cargo build --release) ==="
    cd "$VAGRANT_DIR" && vagrant ssh -c \
        'source "$HOME/.cargo/env" && cd ~/ebpfsentinel && cargo build --release 2>&1' \
        -- -q
    echo "  Binary build complete."
    echo ""
}

vm_build_docker() {
    echo "=== VM — Build Docker image ==="
    cd "$VAGRANT_DIR" && vagrant ssh -c \
        'cd ~/ebpfsentinel && docker build -t ebpfsentinel:latest . 2>&1' \
        -- -q
    echo "  Docker image build complete."
    echo ""
}

vm_extract_ebpf_programs() {
    echo "=== VM — Extract eBPF programs from Docker image ==="
    cd "$VAGRANT_DIR" && vagrant ssh -c '
        set -e
        EBPF_DIR=/usr/local/lib/ebpfsentinel
        CID=$(docker create ebpfsentinel:latest true)
        sudo mkdir -p "$EBPF_DIR"
        for prog in xdp-firewall xdp-ratelimit tc-ids tc-threatintel uprobe-dlp; do
            sudo docker cp "${CID}:${EBPF_DIR}/${prog}" "${EBPF_DIR}/${prog}" 2>/dev/null && \
                echo "  Extracted: ${prog}" || \
                echo "  Skipped:  ${prog} (not in image)"
        done
        docker rm "$CID" >/dev/null
    ' -- -q
    echo ""
}

# ── Config preparation (in VM) ────────────────────────────────────

# vm_prepare_config <fixture_name>
# Substitutes placeholders and writes prepared config in VM. Returns VM path.
vm_prepare_config() {
    local fixture_name="${1:?usage: vm_prepare_config <fixture_name>}"
    local vm_fixture="~/ebpfsentinel/tests/integration/fixtures/${fixture_name}"
    local vm_output="/tmp/ebpfsentinel-host-perf-config-$$.yaml"

    vm_ssh "sed \
        -e 's|__INTERFACE__|${VM_INTERFACE}|g' \
        -e 's|__DATA_DIR__|/tmp/ebpfsentinel-host-perf-data|g' \
        -e 's|__WHITELIST_SUBNET__|${WHITELIST_SUBNET}|g' \
        ${vm_fixture} > ${vm_output} && \
        mkdir -p /tmp/ebpfsentinel-host-perf-data && \
        echo ${vm_output}" | tr -d '\r\n'
}

# ── Agent lifecycle (in VM) ───────────────────────────────────────

# vm_start_agent <binary|docker> <config_path_in_vm>
vm_start_agent() {
    local agent_mode="${1:?usage: vm_start_agent <binary|docker> <config>}"
    local config_path="${2:?usage: vm_start_agent <binary|docker> <config>}"

    echo "  Starting agent (${agent_mode} mode)..."

    # Stop any previous agent
    vm_stop_agent "$agent_mode" 2>/dev/null || true
    sleep 1

    if [ "$agent_mode" = "binary" ]; then
        # No nested single-quote issues: inner script has no single quotes
        cd "$VAGRANT_DIR" && vagrant ssh -c "sudo bash -c 'EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel /home/vagrant/ebpfsentinel/target/release/ebpfsentinel-agent --config ${config_path} >/tmp/ebpfsentinel-host-perf-agent.log 2>&1 & echo \$! > /tmp/ebpfsentinel-host-perf-agent.pid'" -- -q
    else
        vm_ssh "docker rm -f ebpfsentinel-host-perf 2>/dev/null || true" >/dev/null 2>&1
        vm_ssh "docker run -d --name ebpfsentinel-host-perf --network host --privileged -v ${config_path}:/etc/ebpfsentinel/config.yaml:ro -v /tmp/ebpfsentinel-host-perf-data:/data -v /sys/fs/bpf:/sys/fs/bpf -v /sys/kernel/debug:/sys/kernel/debug:ro ebpfsentinel:latest --config /etc/ebpfsentinel/config.yaml" >/dev/null
    fi

    # Wait for agent health from host
    echo "  Waiting for agent health..."
    local attempt=0
    while [ "$attempt" -lt 30 ]; do
        if curl -sf --max-time 2 "http://${VM_IP}:${AGENT_HTTP_PORT}/healthz" >/dev/null 2>&1; then
            echo "  Agent healthy."
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done

    echo "  ERROR: Agent failed health check after 30s" >&2
    if [ "$agent_mode" = "binary" ]; then
        vm_ssh "sudo tail -20 /tmp/ebpfsentinel-host-perf-agent.log 2>/dev/null" >&2 || true
    else
        vm_ssh "docker logs --tail 20 ebpfsentinel-host-perf 2>&1" >&2 || true
    fi
    return 1
}

# vm_stop_agent <binary|docker>
vm_stop_agent() {
    local agent_mode="${1:?usage: vm_stop_agent <binary|docker>}"

    if [ "$agent_mode" = "binary" ]; then
        # Use the measurement script dir for the stop helper; simple pkill fallback
        vm_ssh "sudo pkill -f ebpfsentinel-agent 2>/dev/null; sudo rm -f /tmp/ebpfsentinel-host-perf-agent.pid" || true
    else
        vm_ssh "docker rm -f ebpfsentinel-host-perf 2>/dev/null" >/dev/null || true
    fi
}

# ── iperf3 server lifecycle (in VM) ───────────────────────────────

vm_start_iperf_server() {
    vm_ssh "sudo pkill iperf3 2>/dev/null; true" || true
    sleep 0.5
    vm_ssh "sudo iperf3 -s -B ${VM_IP} -D --pidfile /tmp/iperf3-host-perf.pid"
    sleep 1
    echo "  iperf3 server started on ${VM_IP}:5201"
}

vm_stop_iperf_server() {
    vm_ssh "sudo pkill iperf3 2>/dev/null; sudo rm -f /tmp/iperf3-host-perf.pid" || true
}

# ── Host measurement functions ────────────────────────────────────

# host_measure_tcp_throughput [duration] [streams]
host_measure_tcp_throughput() {
    local duration="${1:-$IPERF_DURATION}"
    local streams="${2:-4}"

    local result
    result="$(iperf3 -c "$VM_IP" -t "$duration" -P "$streams" --json 2>/dev/null)" || {
        echo '{"mbps": 0, "retransmits": 0, "error": "iperf3 failed"}'
        return 1
    }

    local bps retransmits mbps
    bps="$(echo "$result" | jq '.end.sum_received.bits_per_second // 0' 2>/dev/null)" || bps=0
    retransmits="$(echo "$result" | jq '.end.sum_sent.retransmits // 0' 2>/dev/null)" || retransmits=0
    mbps="$(echo "scale=2; $bps / 1000000" | bc -l 2>/dev/null)" || mbps=0

    echo "{\"mbps\": ${mbps}, \"bps\": ${bps}, \"retransmits\": ${retransmits}}"
}

# host_measure_udp_throughput [duration]
host_measure_udp_throughput() {
    local duration="${1:-$IPERF_DURATION}"

    local result
    result="$(iperf3 -c "$VM_IP" -t "$duration" -u -b 0 --json 2>/dev/null)" || {
        echo '{"mbps": 0, "jitter_ms": 0, "loss_pct": 100, "error": "iperf3 failed"}'
        return 1
    }

    local bps jitter loss mbps
    bps="$(echo "$result" | jq '.end.sum.bits_per_second // 0' 2>/dev/null)" || bps=0
    jitter="$(echo "$result" | jq '.end.sum.jitter_ms // 0' 2>/dev/null)" || jitter=0
    loss="$(echo "$result" | jq '.end.sum.lost_percent // 0' 2>/dev/null)" || loss=0
    mbps="$(echo "scale=2; $bps / 1000000" | bc -l 2>/dev/null)" || mbps=0

    echo "{\"mbps\": ${mbps}, \"bps\": ${bps}, \"jitter_ms\": ${jitter}, \"loss_pct\": ${loss}}"
}

# host_measure_icmp_latency [count]
host_measure_icmp_latency() {
    local count="${1:-$PING_COUNT}"

    local result
    result="$(ping -c "$count" -W 1 -i 0.05 "$VM_IP" 2>/dev/null)" || {
        echo '{"avg_ms": 0, "min_ms": 0, "max_ms": 0, "error": "ping failed"}'
        return 1
    }

    local rtt_line
    rtt_line="$(echo "$result" | grep 'rtt min/avg/max' || true)"
    if [ -z "$rtt_line" ]; then
        echo '{"avg_ms": 0, "min_ms": 0, "max_ms": 0, "error": "no rtt line"}'
        return 1
    fi

    local values min_ms avg_ms max_ms
    values="$(echo "$rtt_line" | sed 's|.* = ||; s|/| |g; s| ms||')"
    min_ms="$(echo "$values" | awk '{print $1}')"
    avg_ms="$(echo "$values" | awk '{print $2}')"
    max_ms="$(echo "$values" | awk '{print $3}')"

    echo "{\"avg_ms\": ${avg_ms:-0}, \"min_ms\": ${min_ms:-0}, \"max_ms\": ${max_ms:-0}}"
}

# _has_sudo — check if passwordless sudo is available
_has_sudo() {
    sudo -n true 2>/dev/null
}

# host_measure_tcp_latency [port] [count]
host_measure_tcp_latency() {
    local port="${1:-5201}"
    local count="${2:-$HPING_COUNT}"

    if ! command -v hping3 &>/dev/null; then
        echo '{"avg_ms": 0, "error": "hping3 not found"}'
        return 1
    fi

    if ! _has_sudo; then
        echo '{"avg_ms": 0, "error": "hping3 requires sudo (no passwordless sudo)"}'
        return 1
    fi

    local result
    result="$(sudo hping3 -S -p "$port" -c "$count" -i u10000 "$VM_IP" 2>&1)" || true

    local rtt_line
    rtt_line="$(echo "$result" | grep 'round-trip' || true)"
    if [ -z "$rtt_line" ]; then
        echo '{"avg_ms": 0, "error": "no rtt line from hping3"}'
        return 1
    fi

    local avg_ms
    avg_ms="$(echo "$rtt_line" | sed 's|.*= ||; s| ms.*||' | awk -F'/' '{print $2}')" || avg_ms=0

    echo "{\"avg_ms\": ${avg_ms:-0}}"
}

# host_measure_pps [port] [duration]
host_measure_pps() {
    local port="${1:-5201}"
    local duration="${2:-$PPS_DURATION}"

    if ! command -v hping3 &>/dev/null; then
        echo '{"pps": 0, "error": "hping3 not found"}'
        return 1
    fi

    if ! _has_sudo; then
        echo '{"pps": 0, "error": "hping3 requires sudo (no passwordless sudo)"}'
        return 1
    fi

    local tmpfile
    tmpfile="$(mktemp /tmp/ebpfsentinel-host-pps-XXXXXX)"

    sudo hping3 -S -p "$port" --flood -q "$VM_IP" >"$tmpfile" 2>&1 &
    local hping_pid=$!

    sleep "$duration"
    sudo kill "$hping_pid" 2>/dev/null
    wait "$hping_pid" 2>/dev/null || true

    local result packets_sent pps
    result="$(cat "$tmpfile" 2>/dev/null)"
    rm -f "$tmpfile"

    packets_sent="$(echo "$result" | grep 'packets transmitted' | awk '{print $1}')" || packets_sent=0

    if [ -n "$packets_sent" ] && [ "$packets_sent" -gt 0 ] 2>/dev/null; then
        pps="$(echo "$packets_sent / $duration" | bc 2>/dev/null)" || pps=0
    else
        pps=0
    fi

    echo "{\"pps\": ${pps}, \"total_packets\": ${packets_sent:-0}, \"duration_secs\": ${duration}}"
}

# host_verify_blocked_port <port>
# Returns 0 if port is blocked (connection fails), 1 if it succeeds.
host_verify_blocked_port() {
    local port="${1:?usage: host_verify_blocked_port <port>}"

    if timeout 3 bash -c "echo '' | ncat -w 2 $VM_IP $port" >/dev/null 2>&1; then
        return 1  # Connection succeeded — not blocked
    else
        return 0  # Connection failed — blocked
    fi
}

# ── VM resource measurement ───────────────────────────────────────

# vm_measure_resources <binary|docker>
# Returns JSON with rss_kb and cpu_pct from inside the VM.
# Uses the standalone vm-measure-resources.sh script to avoid SSH escaping issues.
vm_measure_resources() {
    local agent_mode="${1:?usage: vm_measure_resources <binary|docker>}"
    local sample_secs="${2:-$CPU_SAMPLE}"
    local measure_script="~/ebpfsentinel/tests/integration/scripts/vm-measure-resources.sh"

    # Get PID based on mode
    local pid
    if [ "$agent_mode" = "binary" ]; then
        pid="$(vm_ssh "sudo cat /tmp/ebpfsentinel-host-perf-agent.pid 2>/dev/null" | tr -d '\r\n')"
    else
        pid="$(vm_ssh "docker inspect --format '{{.State.Pid}}' ebpfsentinel-host-perf 2>/dev/null" | tr -d '\r\n')"
    fi

    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        echo '{"rss_kb": 0, "cpu_pct": 0, "error": "pid not found"}'
        return
    fi

    local result
    result="$(vm_ssh "sudo bash ${measure_script} ${pid} ${sample_secs}")" || {
        echo '{"rss_kb": 0, "cpu_pct": 0, "error": "measurement failed"}'
        return
    }

    # Clean up any trailing whitespace/CR from vagrant ssh
    echo "$result" | tr -d '\r' | grep -o '{.*}' | head -1
}

# ── Report initialization ─────────────────────────────────────────

init_report() {
    local mode="$1"
    CURRENT_REPORT_FILE="${REPORT_DIR}/ebpfsentinel-host-perf-${mode}-${TIMESTAMP}.json"

    cat > "$CURRENT_REPORT_FILE" <<EOF
{
  "meta": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "topology": "host-to-vm",
    "mode": "$mode",
    "host_ip": "$HOST_IP",
    "vm_ip": "$VM_IP",
    "vm_interface": "$VM_INTERFACE",
    "kernel": "$(vm_ssh 'uname -r' | tr -d '\r\n')",
    "hostname": "$(vm_ssh 'hostname' | tr -d '\r\n')",
    "cpus": $(vm_ssh 'nproc' | tr -d '\r\n'),
    "memory_kb": $(vm_ssh "grep MemTotal /proc/meminfo | awk '{print \$2}'" | tr -d '\r\n'),
    "quick_mode": $QUICK,
    "soak_mode": $SOAK,
    "iperf_duration": $IPERF_DURATION
  },
  "baseline": {},
  "alert_mode": {},
  "block_mode": {},
  "api_bench": {},
  "soak": {},
  "thresholds": {
    "min_tcp_mbps": $THRESH_MIN_TCP_MBPS,
    "min_udp_mbps": $THRESH_MIN_UDP_MBPS,
    "max_icmp_ms": $THRESH_MAX_ICMP_MS,
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

# ── Phase 1: Baseline (no agent) ──────────────────────────────────

run_baseline() {
    echo "=== Phase 1: Baseline (no agent, host-to-VM) ==="

    # TCP throughput
    echo "  Measuring TCP throughput..."
    local tcp_result tcp_mbps
    tcp_result="$(host_measure_tcp_throughput)"
    tcp_mbps="$(echo "$tcp_result" | jq '.mbps')"
    echo "    TCP: ${tcp_mbps} Mbps"

    sleep 2

    # UDP throughput
    echo "  Measuring UDP throughput..."
    local udp_result udp_mbps
    udp_result="$(host_measure_udp_throughput)"
    udp_mbps="$(echo "$udp_result" | jq '.mbps')"
    echo "    UDP: ${udp_mbps} Mbps"

    # ICMP latency
    echo "  Measuring ICMP latency..."
    local icmp_result icmp_avg
    icmp_result="$(host_measure_icmp_latency)"
    icmp_avg="$(echo "$icmp_result" | jq '.avg_ms')"
    echo "    ICMP avg: ${icmp_avg} ms"

    # TCP latency
    echo "  Measuring TCP connection latency..."
    local tcp_lat_result tcp_lat_avg
    tcp_lat_result="$(host_measure_tcp_latency)"
    tcp_lat_avg="$(echo "$tcp_lat_result" | jq '.avg_ms')"
    echo "    TCP SYN avg: ${tcp_lat_avg} ms"

    # PPS
    echo "  Measuring PPS..."
    local pps_result pps
    pps_result="$(host_measure_pps)"
    pps="$(echo "$pps_result" | jq '.pps')"
    echo "    PPS: ${pps}"

    report_update ".baseline = {
        \"tcp_mbps\": $tcp_mbps,
        \"tcp_retransmits\": $(echo "$tcp_result" | jq '.retransmits'),
        \"udp_mbps\": $udp_mbps,
        \"udp_jitter_ms\": $(echo "$udp_result" | jq '.jitter_ms'),
        \"udp_loss_pct\": $(echo "$udp_result" | jq '.loss_pct'),
        \"icmp_avg_ms\": $icmp_avg,
        \"icmp_min_ms\": $(echo "$icmp_result" | jq '.min_ms'),
        \"icmp_max_ms\": $(echo "$icmp_result" | jq '.max_ms'),
        \"tcp_latency_avg_ms\": $tcp_lat_avg,
        \"pps\": $pps
    }"

    echo ""
}

# ── Phase 2: Alert mode ───────────────────────────────────────────

run_alert_mode() {
    local agent_mode="$1"
    echo "=== Phase 2: Alert Mode (${agent_mode}, full stack, observe only) ==="

    local config_path
    config_path="$(vm_prepare_config "config-perf-alert.yaml")"

    if ! vm_start_agent "$agent_mode" "$config_path"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 7))
        echo ""
        return
    fi

    # TCP throughput
    echo "  Measuring TCP throughput..."
    local tcp_result tcp_mbps
    tcp_result="$(host_measure_tcp_throughput)"
    tcp_mbps="$(echo "$tcp_result" | jq '.mbps')"
    echo "    TCP: ${tcp_mbps} Mbps"

    sleep 2

    # UDP throughput
    echo "  Measuring UDP throughput..."
    local udp_result udp_mbps
    udp_result="$(host_measure_udp_throughput)"
    udp_mbps="$(echo "$udp_result" | jq '.mbps')"
    echo "    UDP: ${udp_mbps} Mbps"

    # ICMP latency
    echo "  Measuring ICMP latency..."
    local icmp_result icmp_avg
    icmp_result="$(host_measure_icmp_latency)"
    icmp_avg="$(echo "$icmp_result" | jq '.avg_ms')"
    echo "    ICMP avg: ${icmp_avg} ms"

    # TCP latency
    echo "  Measuring TCP connection latency..."
    local tcp_lat_result tcp_lat_avg
    tcp_lat_result="$(host_measure_tcp_latency)"
    tcp_lat_avg="$(echo "$tcp_lat_result" | jq '.avg_ms')"
    echo "    TCP SYN avg: ${tcp_lat_avg} ms"

    # PPS
    echo "  Measuring PPS..."
    local pps_result pps
    pps_result="$(host_measure_pps)"
    pps="$(echo "$pps_result" | jq '.pps')"
    echo "    PPS: ${pps}"

    # Resource measurement (CPU sampled under load from VM)
    echo "  Measuring resource usage..."

    # Start iperf3 in background to generate load during resource sampling
    iperf3 -c "$VM_IP" -t "$((CPU_SAMPLE + 2))" -P 4 >/dev/null 2>&1 &
    local cpu_load_pid=$!
    sleep 1

    local resource_result rss_kb cpu_pct
    resource_result="$(vm_measure_resources "$agent_mode" "$CPU_SAMPLE")"
    rss_kb="$(echo "$resource_result" | jq '.rss_kb // 0')"
    cpu_pct="$(echo "$resource_result" | jq '.cpu_pct // 0')"
    echo "    RSS: ${rss_kb} KB"
    echo "    CPU: ${cpu_pct}%"

    wait "$cpu_load_pid" 2>/dev/null || true
    sleep 1

    report_update ".alert_mode = {
        \"tcp_mbps\": $tcp_mbps,
        \"udp_mbps\": $udp_mbps,
        \"icmp_avg_ms\": $icmp_avg,
        \"tcp_latency_avg_ms\": $tcp_lat_avg,
        \"pps\": $pps,
        \"rss_kb\": $rss_kb,
        \"cpu_pct\": $cpu_pct
    }"

    # Threshold checks
    echo ""
    echo "  --- Threshold Checks ---"

    local result
    result="pass"
    [ "$(echo "$tcp_mbps >= $THRESH_MIN_TCP_MBPS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "TCP throughput with agent" "$result" "${tcp_mbps} Mbps (limit: >${THRESH_MIN_TCP_MBPS} Mbps)"

    result="pass"
    [ "$(echo "$udp_mbps >= $THRESH_MIN_UDP_MBPS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "UDP throughput with agent" "$result" "${udp_mbps} Mbps (limit: >${THRESH_MIN_UDP_MBPS} Mbps)"

    result="pass"
    [ "$(echo "$icmp_avg < $THRESH_MAX_ICMP_MS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "ICMP latency with agent" "$result" "${icmp_avg} ms (limit: <${THRESH_MAX_ICMP_MS} ms)"

    if [ "$tcp_lat_avg" = "0" ] && ! _has_sudo; then
        check_result "TCP conn latency with agent" "skip" "hping3 requires sudo"
    else
        result="pass"
        [ "$(echo "$tcp_lat_avg < $THRESH_MAX_TCP_LAT_MS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
        check_result "TCP conn latency with agent" "$result" "${tcp_lat_avg} ms (limit: <${THRESH_MAX_TCP_LAT_MS} ms)"
    fi

    if [ "$pps" = "0" ] && ! _has_sudo; then
        check_result "Min PPS with agent" "skip" "hping3 requires sudo"
    else
        result="pass"
        [ "$pps" -gt "$THRESH_MIN_PPS" ] 2>/dev/null || result="fail"
        check_result "Min PPS with agent" "$result" "${pps} pps (limit: >${THRESH_MIN_PPS})"
    fi

    result="pass"
    [ "$rss_kb" -lt "$THRESH_MAX_RSS_KB" ] 2>/dev/null || result="fail"
    check_result "Agent RSS" "$result" "${rss_kb} KB (limit: <${THRESH_MAX_RSS_KB} KB)"

    result="pass"
    [ "$(echo "$cpu_pct < $THRESH_MAX_CPU" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "Agent CPU at load" "$result" "${cpu_pct}% (limit: <${THRESH_MAX_CPU}%)"

    vm_stop_agent "$agent_mode" 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Phase 3: Block mode ───────────────────────────────────────────

run_block_mode() {
    local agent_mode="$1"
    echo "=== Phase 3: Block Mode (${agent_mode}, active blocking) ==="

    local config_path
    config_path="$(vm_prepare_config "config-perf-block.yaml")"

    if ! vm_start_agent "$agent_mode" "$config_path"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 3))
        echo ""
        return
    fi

    # TCP throughput on allowed port
    echo "  Measuring TCP throughput (allowed traffic)..."
    local tcp_result tcp_mbps
    tcp_result="$(host_measure_tcp_throughput)"
    tcp_mbps="$(echo "$tcp_result" | jq '.mbps')"
    echo "    TCP (allowed): ${tcp_mbps} Mbps"

    # Verify blocked port 9999
    echo "  Verifying port 9999 is blocked..."
    local port_9999_blocked=true
    if host_verify_blocked_port 9999; then
        echo "    Port 9999: blocked"
    else
        echo "    Port 9999: NOT blocked (unexpected)"
        port_9999_blocked=false
    fi

    # Verify blocked port 7777
    echo "  Verifying port 7777 is blocked..."
    local port_7777_blocked=true
    if host_verify_blocked_port 7777; then
        echo "    Port 7777: blocked"
    else
        echo "    Port 7777: NOT blocked (unexpected)"
        port_7777_blocked=false
    fi

    report_update ".block_mode = {
        \"tcp_mbps_allowed\": $tcp_mbps,
        \"port_9999_blocked\": $port_9999_blocked,
        \"port_7777_blocked\": $port_7777_blocked
    }"

    echo ""
    echo "  --- Threshold Checks ---"
    local result="pass"
    [ "$(echo "$tcp_mbps >= $THRESH_MIN_TCP_MBPS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "Block mode TCP throughput" "$result" "${tcp_mbps} Mbps (limit: >${THRESH_MIN_TCP_MBPS} Mbps)"

    result="pass"
    [ "$port_9999_blocked" = "true" ] || result="fail"
    check_result "Port 9999 blocked" "$result" "firewall deny rule active"

    result="pass"
    [ "$port_7777_blocked" = "true" ] || result="fail"
    check_result "Port 7777 blocked" "$result" "firewall deny rule active"

    vm_stop_agent "$agent_mode" 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Phase 4: API benchmarks ───────────────────────────────────────

run_api_benchmarks() {
    local agent_mode="$1"
    echo "=== Phase 4: API Benchmarks (${agent_mode}) ==="

    if ! command -v hey &>/dev/null; then
        echo "  SKIP: hey not installed on host"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        report_update '.api_bench = {"error": "hey not available"}'
        echo ""
        return
    fi

    local config_path
    config_path="$(vm_prepare_config "config-perf-alert.yaml")"

    if ! vm_start_agent "$agent_mode" "$config_path"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        echo ""
        return
    fi

    sleep 2

    local base_url="http://${VM_IP}:${AGENT_HTTP_PORT}"

    # /healthz
    echo "  Benchmarking /healthz..."
    local healthz_result healthz_rps healthz_p99
    healthz_result="$(hey -n "$API_REQUESTS" -c "$API_CONCURRENCY" -q 0 "${base_url}/healthz" 2>/dev/null)" || true
    healthz_rps="$(echo "$healthz_result" | grep 'Requests/sec:' | awk '{print $2}')" || healthz_rps=0
    local healthz_p99_secs
    healthz_p99_secs="$(echo "$healthz_result" | grep '99%' | awk '{print $3}')" || healthz_p99_secs=0
    healthz_p99="$(echo "${healthz_p99_secs:-0} * 1000" | bc -l 2>/dev/null | xargs printf '%.2f' 2>/dev/null)" || healthz_p99=0
    echo "    /healthz: ${healthz_rps:-0} req/s, p99=${healthz_p99:-0} ms"

    # /api/v1/alerts
    echo "  Benchmarking /api/v1/alerts..."
    local alerts_result alerts_rps alerts_p99
    alerts_result="$(hey -n "$API_REQUESTS" -c "$API_CONCURRENCY" -q 0 "${base_url}/api/v1/alerts" 2>/dev/null)" || true
    alerts_rps="$(echo "$alerts_result" | grep 'Requests/sec:' | awk '{print $2}')" || alerts_rps=0
    local alerts_p99_secs
    alerts_p99_secs="$(echo "$alerts_result" | grep '99%' | awk '{print $3}')" || alerts_p99_secs=0
    alerts_p99="$(echo "${alerts_p99_secs:-0} * 1000" | bc -l 2>/dev/null | xargs printf '%.2f' 2>/dev/null)" || alerts_p99=0
    echo "    /api/v1/alerts: ${alerts_rps:-0} req/s, p99=${alerts_p99:-0} ms"

    # /api/v1/firewall/rules
    echo "  Benchmarking /api/v1/firewall/rules..."
    local fw_result fw_rps fw_p99
    fw_result="$(hey -n "$API_REQUESTS" -c "$API_CONCURRENCY" -q 0 "${base_url}/api/v1/firewall/rules" 2>/dev/null)" || true
    fw_rps="$(echo "$fw_result" | grep 'Requests/sec:' | awk '{print $2}')" || fw_rps=0
    local fw_p99_secs
    fw_p99_secs="$(echo "$fw_result" | grep '99%' | awk '{print $3}')" || fw_p99_secs=0
    fw_p99="$(echo "${fw_p99_secs:-0} * 1000" | bc -l 2>/dev/null | xargs printf '%.2f' 2>/dev/null)" || fw_p99=0
    echo "    /api/v1/firewall/rules: ${fw_rps:-0} req/s, p99=${fw_p99:-0} ms"

    # Worst p99
    local worst_p99
    worst_p99="$(echo "${healthz_p99:-0} ${alerts_p99:-0} ${fw_p99:-0}" | tr ' ' '\n' | sort -n | tail -1)"

    report_update ".api_bench = {
        \"healthz\": {\"rps\": ${healthz_rps:-0}, \"p99_ms\": ${healthz_p99:-0}},
        \"alerts\": {\"rps\": ${alerts_rps:-0}, \"p99_ms\": ${alerts_p99:-0}},
        \"firewall_rules\": {\"rps\": ${fw_rps:-0}, \"p99_ms\": ${fw_p99:-0}},
        \"worst_p99_ms\": ${worst_p99:-0}
    }"

    echo ""
    echo "  --- Threshold Checks ---"
    local result="pass"
    [ "$(echo "${worst_p99:-0} < $THRESH_API_P99_MS" | bc -l 2>/dev/null)" = "1" ] || result="fail"
    check_result "REST API p99 latency" "$result" "${worst_p99:-0} ms (limit: <${THRESH_API_P99_MS} ms)"

    vm_stop_agent "$agent_mode" 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Phase 5: Soak test ────────────────────────────────────────────

run_soak_test() {
    local agent_mode="$1"

    if [ "$SOAK" != "true" ]; then
        echo "=== Phase 5: Soak Test (skipped -- use --soak to enable) ==="
        echo ""
        return
    fi

    echo "=== Phase 5: Soak Test (${agent_mode}, ${SOAK_DURATION}s sustained load) ==="

    local config_path
    config_path="$(vm_prepare_config "config-perf-alert.yaml")"

    if ! vm_start_agent "$agent_mode" "$config_path"; then
        echo "  SKIP: Agent failed to start"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        echo ""
        return
    fi

    # Initial RSS
    local initial_result initial_rss
    initial_result="$(vm_measure_resources "$agent_mode" 1)"
    initial_rss="$(echo "$initial_result" | jq '.rss_kb // 0')"
    echo "  Initial RSS: ${initial_rss} KB"

    # Start iperf3 in background for sustained load
    iperf3 -c "$VM_IP" -t "$SOAK_DURATION" -P 4 >/dev/null 2>&1 &
    local iperf_bg_pid=$!

    # Sample RSS/CPU periodically
    local samples_json="["
    local elapsed=0
    local first=true
    while [ "$elapsed" -lt "$SOAK_DURATION" ]; do
        sleep "$SOAK_INTERVAL"
        elapsed=$((elapsed + SOAK_INTERVAL))

        local sample_result current_rss current_cpu
        sample_result="$(vm_measure_resources "$agent_mode" 2)"
        current_rss="$(echo "$sample_result" | jq '.rss_kb // 0')"
        current_cpu="$(echo "$sample_result" | jq '.cpu_pct // 0')"
        echo "  [${elapsed}s] RSS: ${current_rss} KB, CPU: ${current_cpu}%"

        [ "$first" = "true" ] || samples_json+=","
        samples_json+="{\"elapsed_s\":$elapsed,\"rss_kb\":$current_rss,\"cpu_pct\":$current_cpu}"
        first=false
    done
    samples_json+="]"

    wait "$iperf_bg_pid" 2>/dev/null || true

    # Final RSS
    local final_result final_rss
    final_result="$(vm_measure_resources "$agent_mode" 1)"
    final_rss="$(echo "$final_result" | jq '.rss_kb // 0')"
    echo "  Final RSS: ${final_rss} KB"

    # Calculate growth
    local rss_growth_pct=0
    if [ "$initial_rss" -gt 0 ] 2>/dev/null; then
        rss_growth_pct="$(echo "scale=2; (($final_rss - $initial_rss) / $initial_rss) * 100" | bc -l 2>/dev/null)" || rss_growth_pct=0
    fi
    echo "  RSS growth: ${rss_growth_pct}%"

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

    vm_stop_agent "$agent_mode" 2>/dev/null || true
    sleep 1
    echo ""
}

# ── Report generation ─────────────────────────────────────────────

generate_report() {
    local agent_mode="$1"

    echo "=== Results Summary (${agent_mode}) ==="
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

    local report
    report="$(cat "$CURRENT_REPORT_FILE")"

    local tcp_mbps udp_mbps icmp_ms tcp_lat_ms agent_pps rss cpu api_p99
    tcp_mbps="$(echo "$report" | jq -r '.alert_mode.tcp_mbps // "N/A"')"
    udp_mbps="$(echo "$report" | jq -r '.alert_mode.udp_mbps // "N/A"')"
    icmp_ms="$(echo "$report" | jq -r '.alert_mode.icmp_avg_ms // "N/A"')"
    tcp_lat_ms="$(echo "$report" | jq -r '.alert_mode.tcp_latency_avg_ms // "N/A"')"
    agent_pps="$(echo "$report" | jq -r '.alert_mode.pps // "N/A"')"
    rss="$(echo "$report" | jq -r '.alert_mode.rss_kb // "N/A"')"
    cpu="$(echo "$report" | jq -r '.alert_mode.cpu_pct // "N/A"')"
    api_p99="$(echo "$report" | jq -r '.api_bench.worst_p99_ms // "N/A"')"

    printf "  %-45s %s\n" "TCP throughput with agent" "${tcp_mbps} Mbps (limit: >${THRESH_MIN_TCP_MBPS} Mbps)"
    printf "  %-45s %s\n" "UDP throughput with agent" "${udp_mbps} Mbps (limit: >${THRESH_MIN_UDP_MBPS} Mbps)"
    printf "  %-45s %s\n" "ICMP latency with agent" "${icmp_ms} ms (limit: <${THRESH_MAX_ICMP_MS} ms)"
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
    echo "  Report: $CURRENT_REPORT_FILE"
    echo ""
}

# ── Run single mode ───────────────────────────────────────────────

# run_single_mode <binary|docker>
# Runs all phases for a single agent mode.
run_single_mode() {
    local agent_mode="$1"

    # Reset counters per mode
    PASS_COUNT=0
    FAIL_COUNT=0
    SKIP_COUNT=0

    echo ""
    echo "============================================================"
    echo "  Host-to-VM Performance Test (mode: ${agent_mode})"
    echo "============================================================"
    echo ""

    init_report "$agent_mode"

    vm_start_iperf_server

    run_baseline
    run_alert_mode "$agent_mode"

    vm_stop_iperf_server
    sleep 1
    vm_start_iperf_server

    run_block_mode "$agent_mode"

    vm_stop_iperf_server

    run_api_benchmarks "$agent_mode"
    run_soak_test "$agent_mode"
    generate_report "$agent_mode"
}

# ── Comparison ─────────────────────────────────────────────────────

compare_reports() {
    local binary_report="$1"
    local docker_report="$2"

    echo ""
    echo "============================================================"
    echo "  Docker vs Binary Comparison (host-to-VM)"
    echo "============================================================"
    echo ""

    local b_tcp d_tcp b_udp d_udp b_icmp d_icmp b_tcp_lat d_tcp_lat
    local b_pps d_pps b_rss d_rss b_cpu d_cpu b_api d_api

    b_tcp="$(safe_jq "$binary_report" '.alert_mode.tcp_mbps')"
    d_tcp="$(safe_jq "$docker_report" '.alert_mode.tcp_mbps')"
    b_udp="$(safe_jq "$binary_report" '.alert_mode.udp_mbps')"
    d_udp="$(safe_jq "$docker_report" '.alert_mode.udp_mbps')"
    b_icmp="$(safe_jq "$binary_report" '.alert_mode.icmp_avg_ms')"
    d_icmp="$(safe_jq "$docker_report" '.alert_mode.icmp_avg_ms')"
    b_tcp_lat="$(safe_jq "$binary_report" '.alert_mode.tcp_latency_avg_ms')"
    d_tcp_lat="$(safe_jq "$docker_report" '.alert_mode.tcp_latency_avg_ms')"
    b_pps="$(safe_jq "$binary_report" '.alert_mode.pps')"
    d_pps="$(safe_jq "$docker_report" '.alert_mode.pps')"
    b_rss="$(safe_jq "$binary_report" '.alert_mode.rss_kb')"
    d_rss="$(safe_jq "$docker_report" '.alert_mode.rss_kb')"
    b_cpu="$(safe_jq "$binary_report" '.alert_mode.cpu_pct')"
    d_cpu="$(safe_jq "$docker_report" '.alert_mode.cpu_pct')"
    b_api="$(safe_jq "$binary_report" '.api_bench.worst_p99_ms')"
    d_api="$(safe_jq "$docker_report" '.api_bench.worst_p99_ms')"

    printf "  %-30s  %-14s  %-14s  %s\n" "Metric" "Binary" "Docker" "Overhead"
    printf "  %-30s  %-14s  %-14s  %s\n" \
        "$(printf '%0.s-' {1..30})" \
        "$(printf '%0.s-' {1..14})" \
        "$(printf '%0.s-' {1..14})" \
        "$(printf '%0.s-' {1..10})"

    printf "  %-30s  %-14s  %-14s  %s\n" "TCP throughput" \
        "$(format_value "$b_tcp" "Mbps")" "$(format_value "$d_tcp" "Mbps")" \
        "$(format_overhead "$b_tcp" "$d_tcp" false)"

    printf "  %-30s  %-14s  %-14s  %s\n" "UDP throughput" \
        "$(format_value "$b_udp" "Mbps")" "$(format_value "$d_udp" "Mbps")" \
        "$(format_overhead "$b_udp" "$d_udp" false)"

    printf "  %-30s  %-14s  %-14s  %s\n" "ICMP latency" \
        "$(format_value "$b_icmp" "ms")" "$(format_value "$d_icmp" "ms")" \
        "$(format_overhead "$b_icmp" "$d_icmp" true)"

    printf "  %-30s  %-14s  %-14s  %s\n" "TCP conn latency" \
        "$(format_value "$b_tcp_lat" "ms")" "$(format_value "$d_tcp_lat" "ms")" \
        "$(format_overhead "$b_tcp_lat" "$d_tcp_lat" true)"

    printf "  %-30s  %-14s  %-14s  %s\n" "PPS" \
        "$(format_value "$b_pps" "")" "$(format_value "$d_pps" "")" \
        "$(format_overhead "$b_pps" "$d_pps" false)"

    printf "  %-30s  %-14s  %-14s  %s\n" "RSS" \
        "$(format_value "$b_rss" "KB")" "$(format_value "$d_rss" "KB")" \
        "$(format_overhead "$b_rss" "$d_rss" true)"

    printf "  %-30s  %-14s  %-14s  %s\n" "CPU under load" \
        "$(format_value "$b_cpu" "%")" "$(format_value "$d_cpu" "%")" \
        "$(format_overhead "$b_cpu" "$d_cpu" true)"

    printf "  %-30s  %-14s  %-14s  %s\n" "API p99" \
        "$(format_value "$b_api" "ms")" "$(format_value "$d_api" "ms")" \
        "$(format_overhead "$b_api" "$d_api" true)"

    echo ""

    local b_verdict d_verdict
    b_verdict="$(safe_jq "$binary_report" '.verdict' 'UNKNOWN')"
    d_verdict="$(safe_jq "$docker_report" '.verdict' 'UNKNOWN')"

    local b_color="\033[32m" d_color="\033[32m"
    [ "$b_verdict" = "PASS" ] || b_color="\033[31m"
    [ "$d_verdict" = "PASS" ] || d_color="\033[31m"

    printf "  Binary verdict: ${b_color}%s\033[0m   Docker verdict: ${d_color}%s\033[0m\n" \
        "$b_verdict" "$d_verdict"
    echo ""
}

# ── Cleanup ────────────────────────────────────────────────────────

cleanup() {
    echo "=== Cleanup ==="
    vm_stop_agent "binary" 2>/dev/null || true
    vm_stop_agent "docker" 2>/dev/null || true
    vm_stop_iperf_server 2>/dev/null || true
    vm_ssh "rm -f /tmp/ebpfsentinel-host-perf-config-*.yaml" 2>/dev/null || true
    vm_ssh "rm -rf /tmp/ebpfsentinel-host-perf-data" 2>/dev/null || true
    echo "  Done."
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────

main() {
    trap cleanup EXIT

    echo ""
    echo "============================================================"
    echo "  eBPFsentinel Host-to-VM Performance Test"
    echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================================"
    echo ""

    preflight_host
    vm_up
    vm_sync
    vm_detect_interface

    # Build artifacts based on mode
    local needs_binary=false needs_docker=false
    case "$MODE" in
        binary) needs_binary=true ;;
        docker) needs_docker=true ;;
        both)   needs_binary=true; needs_docker=true ;;
    esac

    if [ "$needs_docker" = "true" ]; then
        vm_build_docker
    fi

    if [ "$needs_binary" = "true" ]; then
        if [ "$needs_docker" = "true" ]; then
            vm_extract_ebpf_programs
        fi
        vm_build_binary
    fi

    # Run tests
    local binary_report="" docker_report=""
    local exit_code=0

    if [ "$needs_binary" = "true" ]; then
        run_single_mode "binary" || exit_code=$?
        binary_report="$CURRENT_REPORT_FILE"
    fi

    if [ "$needs_docker" = "true" ]; then
        run_single_mode "docker" || exit_code=$?
        docker_report="$CURRENT_REPORT_FILE"
    fi

    # Compare if both modes ran
    if [ "$MODE" = "both" ] && [ -n "$binary_report" ] && [ -n "$docker_report" ]; then
        compare_reports "$binary_report" "$docker_report"
    fi

    echo "  Reports:"
    [ -z "$binary_report" ] || echo "    Binary: $binary_report"
    [ -z "$docker_report" ] || echo "    Docker: $docker_report"
    echo ""

    exit "$exit_code"
}

main "$@"
