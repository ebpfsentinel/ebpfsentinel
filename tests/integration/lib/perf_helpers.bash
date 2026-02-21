#!/usr/bin/env bash
# perf_helpers.bash — Measurement functions for Docker performance tests
#
# Provides:
#   - TCP/UDP throughput measurement (iperf3)
#   - ICMP and TCP latency measurement (ping, hping3)
#   - PPS measurement (hping3 flood)
#   - CPU/memory overhead measurement (/proc sampling)
#   - eBPF map memory measurement (bpftool)
#   - HTTP benchmark helpers (hey)
#   - Human-readable formatting utilities

PERF_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source ebpf_helpers (which sources helpers.bash + constants.bash)
if [ -z "${EBPF_HOST_IP:-}" ]; then
    source "${PERF_HELPERS_DIR}/ebpf_helpers.bash"
fi

# ── Throughput measurement ──────────────────────────────────────────

# measure_tcp_throughput <dst_ip> <duration_secs> [streams]
# Runs iperf3 TCP with JSON output. Returns JSON with bps + retransmits.
measure_tcp_throughput() {
    local dst="${1:?usage: measure_tcp_throughput <dst_ip> <duration> [streams]}"
    local duration="${2:-10}"
    local streams="${3:-4}"

    local result
    result="$(ip netns exec "$EBPF_TEST_NS" \
        iperf3 -c "$dst" -t "$duration" -P "$streams" --json 2>/dev/null)" || {
        echo '{"bps": 0, "retransmits": 0, "error": "iperf3 failed"}'
        return 1
    }

    local bps retransmits
    bps="$(echo "$result" | jq '.end.sum_received.bits_per_second // 0' 2>/dev/null)" || bps=0
    retransmits="$(echo "$result" | jq '.end.sum_sent.retransmits // 0' 2>/dev/null)" || retransmits=0

    echo "{\"bps\": ${bps}, \"retransmits\": ${retransmits}}"
}

# measure_udp_throughput <dst_ip> <duration_secs>
# Runs iperf3 UDP with unlimited bandwidth. Returns JSON with bps + jitter + loss%.
measure_udp_throughput() {
    local dst="${1:?usage: measure_udp_throughput <dst_ip> <duration>}"
    local duration="${2:-10}"

    local result
    result="$(ip netns exec "$EBPF_TEST_NS" \
        iperf3 -c "$dst" -t "$duration" -u -b 0 --json 2>/dev/null)" || {
        echo '{"bps": 0, "jitter_ms": 0, "loss_pct": 100, "error": "iperf3 failed"}'
        return 1
    }

    local bps jitter loss
    bps="$(echo "$result" | jq '.end.sum.bits_per_second // 0' 2>/dev/null)" || bps=0
    jitter="$(echo "$result" | jq '.end.sum.jitter_ms // 0' 2>/dev/null)" || jitter=0
    loss="$(echo "$result" | jq '.end.sum.lost_percent // 0' 2>/dev/null)" || loss=0

    echo "{\"bps\": ${bps}, \"jitter_ms\": ${jitter}, \"loss_pct\": ${loss}}"
}

# ── Latency measurement ────────────────────────────────────────────

# measure_icmp_latency <dst_ip> <count>
# Pings from netns. Returns JSON with min/avg/max RTT in microseconds.
measure_icmp_latency() {
    local dst="${1:?usage: measure_icmp_latency <dst_ip> <count>}"
    local count="${2:-100}"

    local result
    result="$(ip netns exec "$EBPF_TEST_NS" \
        ping -c "$count" -W 1 -i 0.01 "$dst" 2>/dev/null)" || {
        echo '{"min_us": 0, "avg_us": 0, "max_us": 0, "error": "ping failed"}'
        return 1
    }

    # Parse "rtt min/avg/max/mdev = 0.035/0.042/0.060/0.005 ms"
    local rtt_line
    rtt_line="$(echo "$result" | grep 'rtt min/avg/max' || true)"
    if [ -z "$rtt_line" ]; then
        echo '{"min_us": 0, "avg_us": 0, "max_us": 0, "error": "no rtt line"}'
        return 1
    fi

    local values
    values="$(echo "$rtt_line" | sed 's|.* = ||; s|/| |g; s| ms||')"
    local min_ms avg_ms max_ms
    min_ms="$(echo "$values" | awk '{print $1}')"
    avg_ms="$(echo "$values" | awk '{print $2}')"
    max_ms="$(echo "$values" | awk '{print $3}')"

    # Convert ms to us
    local min_us avg_us max_us
    min_us="$(echo "$min_ms * 1000" | bc -l 2>/dev/null | cut -d. -f1)" || min_us=0
    avg_us="$(echo "$avg_ms * 1000" | bc -l 2>/dev/null | cut -d. -f1)" || avg_us=0
    max_us="$(echo "$max_ms * 1000" | bc -l 2>/dev/null | cut -d. -f1)" || max_us=0

    echo "{\"min_us\": ${min_us:-0}, \"avg_us\": ${avg_us:-0}, \"max_us\": ${max_us:-0}}"
}

# measure_tcp_latency <dst_ip> <dst_port> <count>
# Uses hping3 SYN from netns. Returns JSON with avg RTT in microseconds.
measure_tcp_latency() {
    local dst="${1:?usage: measure_tcp_latency <dst_ip> <dst_port> <count>}"
    local port="${2:?usage: measure_tcp_latency <dst_ip> <dst_port> <count>}"
    local count="${3:-100}"

    local result
    result="$(ip netns exec "$EBPF_TEST_NS" \
        hping3 -S -p "$port" -c "$count" -i u10000 "$dst" 2>&1)" || true

    # Parse "round-trip min/avg/max = 0.1/0.2/0.3 ms"
    local rtt_line
    rtt_line="$(echo "$result" | grep 'round-trip' || true)"
    if [ -z "$rtt_line" ]; then
        echo '{"avg_us": 0, "error": "no rtt line from hping3"}'
        return 1
    fi

    # Extract "0.1/0.2/0.3" after "= ", then pick avg (second field)
    local avg_ms
    avg_ms="$(echo "$rtt_line" | sed 's|.*= ||; s| ms.*||' | awk -F'/' '{print $2}')" || avg_ms=0

    local avg_us
    avg_us="$(echo "${avg_ms:-0} * 1000" | bc -l 2>/dev/null | cut -d. -f1)" || avg_us=0

    echo "{\"avg_us\": ${avg_us:-0}}"
}

# ── PPS measurement ────────────────────────────────────────────────

# measure_pps <dst_ip> <dst_port> <duration_secs>
# Uses hping3 flood (64B SYN packets) from netns. Returns packets/sec.
measure_pps() {
    local dst="${1:?usage: measure_pps <dst_ip> <dst_port> <duration>}"
    local port="${2:?usage: measure_pps <dst_ip> <dst_port> <duration>}"
    local duration="${3:-5}"

    local tmpfile
    tmpfile="$(mktemp /tmp/ebpfsentinel-pps-XXXXXX)"

    # hping3 --flood sends as fast as possible; run in background, kill after duration
    ip netns exec "$EBPF_TEST_NS" \
        hping3 -S -p "$port" --flood -q "$dst" >"$tmpfile" 2>&1 &
    local hping_pid=$!

    sleep "$duration"
    kill "$hping_pid" 2>/dev/null
    wait "$hping_pid" 2>/dev/null || true

    local result
    result="$(cat "$tmpfile" 2>/dev/null)"
    rm -f "$tmpfile"

    # Parse "N packets transmitted, 0 packets received"
    local packets_sent
    packets_sent="$(echo "$result" | grep 'packets transmitted' | awk '{print $1}')" || packets_sent=0

    local pps
    if [ -n "$packets_sent" ] && [ "$packets_sent" -gt 0 ] 2>/dev/null; then
        pps="$(echo "$packets_sent / $duration" | bc 2>/dev/null)" || pps=0
    else
        pps=0
    fi

    echo "{\"pps\": ${pps}, \"total_packets\": ${packets_sent:-0}, \"duration_secs\": ${duration}}"
}

# ── Resource measurement ───────────────────────────────────────────

# measure_cpu_overhead <pid> <sample_secs>
# Samples /proc/<pid>/stat at start and end. Returns CPU %.
measure_cpu_overhead() {
    local pid="${1:?usage: measure_cpu_overhead <pid> <sample_secs>}"
    local sample="${2:-5}"

    if [ ! -f "/proc/${pid}/stat" ]; then
        echo '{"cpu_pct": 0, "error": "process not found"}'
        return 1
    fi

    # Read initial CPU ticks (utime + stime, fields 14+15 in /proc/pid/stat)
    local stat1 utime1 stime1 total1 clock1
    stat1="$(cat "/proc/${pid}/stat" 2>/dev/null)"
    utime1="$(echo "$stat1" | awk '{print $14}')"
    stime1="$(echo "$stat1" | awk '{print $15}')"
    total1=$((utime1 + stime1))
    clock1="$(cat /proc/uptime | awk '{print $1}')"

    sleep "$sample"

    # Read final CPU ticks
    local stat2 utime2 stime2 total2 clock2
    stat2="$(cat "/proc/${pid}/stat" 2>/dev/null)" || {
        echo '{"cpu_pct": 0, "error": "process exited during sampling"}'
        return 1
    }
    utime2="$(echo "$stat2" | awk '{print $14}')"
    stime2="$(echo "$stat2" | awk '{print $15}')"
    total2=$((utime2 + stime2))
    clock2="$(cat /proc/uptime | awk '{print $1}')"

    # CPU % = (delta_ticks / CLK_TCK) / delta_wall * 100
    local clk_tck
    clk_tck="$(getconf CLK_TCK)"
    local delta_ticks=$((total2 - total1))
    local cpu_pct
    cpu_pct="$(echo "scale=2; ($delta_ticks / $clk_tck) / ($clock2 - $clock1) * 100" | bc -l 2>/dev/null)" || cpu_pct=0

    echo "{\"cpu_pct\": ${cpu_pct:-0}}"
}

# measure_memory <pid>
# Returns RSS in KB from /proc/<pid>/status.
measure_memory() {
    local pid="${1:?usage: measure_memory <pid>}"

    if [ ! -f "/proc/${pid}/status" ]; then
        echo '{"rss_kb": 0, "error": "process not found"}'
        return 1
    fi

    local rss_kb
    rss_kb="$(grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')" || rss_kb=0

    echo "{\"rss_kb\": ${rss_kb:-0}}"
}

# measure_ebpf_map_memory
# Uses bpftool to sum eBPF map memory. Returns total bytes.
measure_ebpf_map_memory() {
    if ! command -v bpftool &>/dev/null; then
        echo '{"total_bytes": 0, "map_count": 0, "error": "bpftool not found"}'
        return 1
    fi

    local maps_json
    maps_json="$(bpftool map list -j 2>/dev/null)" || {
        echo '{"total_bytes": 0, "map_count": 0, "error": "bpftool failed"}'
        return 1
    }

    local total_bytes map_count
    total_bytes="$(echo "$maps_json" | jq '[.[] | .bytes_memlock // 0] | add // 0' 2>/dev/null)" || total_bytes=0
    map_count="$(echo "$maps_json" | jq 'length' 2>/dev/null)" || map_count=0

    echo "{\"total_bytes\": ${total_bytes}, \"map_count\": ${map_count}}"
}

# ── HTTP benchmark helpers ─────────────────────────────────────────

# install_hey_if_missing
# Installs hey HTTP benchmark tool if not in PATH.
install_hey_if_missing() {
    if command -v hey &>/dev/null; then
        return 0
    fi

    echo "Installing hey HTTP benchmark tool..." >&2
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac

    curl -sSL "https://hey-release.s3.us-east-2.amazonaws.com/hey_linux_${arch}" \
        -o /usr/local/bin/hey 2>/dev/null && \
    chmod +x /usr/local/bin/hey

    if ! command -v hey &>/dev/null; then
        echo "Failed to install hey" >&2
        return 1
    fi
}

# run_http_bench <url> [requests] [concurrency]
# Runs hey and returns JSON with req/s + p99 latency.
run_http_bench() {
    local url="${1:?usage: run_http_bench <url> [requests] [concurrency]}"
    local requests="${2:-1000}"
    local concurrency="${3:-10}"

    if ! command -v hey &>/dev/null; then
        echo '{"rps": 0, "p99_ms": 0, "error": "hey not installed"}'
        return 1
    fi

    local result
    result="$(hey -n "$requests" -c "$concurrency" -q 0 "$url" 2>/dev/null)" || {
        echo '{"rps": 0, "p99_ms": 0, "error": "hey failed"}'
        return 1
    }

    # Parse "Requests/sec: 12345.67"
    local rps
    rps="$(echo "$result" | grep 'Requests/sec:' | awk '{print $2}')" || rps=0

    # Parse "99% in X.XXXX secs"
    local p99_secs p99_ms
    p99_secs="$(echo "$result" | grep '99%' | awk '{print $3}')" || p99_secs=0
    p99_ms="$(echo "${p99_secs:-0} * 1000" | bc -l 2>/dev/null | xargs printf '%.2f' 2>/dev/null)" || p99_ms=0

    echo "{\"rps\": ${rps:-0}, \"p99_ms\": ${p99_ms:-0}}"
}

# ── Formatting utilities ───────────────────────────────────────────

# format_bps <bits_per_second>
# Returns human-readable string (e.g., "9.41 Gbps").
format_bps() {
    local bps="${1:-0}"

    if [ "$(echo "$bps >= 1000000000" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $bps / 1000000000" | bc -l) Gbps"
    elif [ "$(echo "$bps >= 1000000" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $bps / 1000000" | bc -l) Mbps"
    elif [ "$(echo "$bps >= 1000" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $bps / 1000" | bc -l) Kbps"
    else
        echo "${bps} bps"
    fi
}

# format_duration <microseconds>
# Returns human-readable string (e.g., "42 us", "1.5 ms").
format_duration() {
    local us="${1:-0}"

    if [ "$(echo "$us >= 1000000" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $us / 1000000" | bc -l) s"
    elif [ "$(echo "$us >= 1000" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $us / 1000" | bc -l) ms"
    else
        echo "${us} us"
    fi
}

# format_bytes <bytes>
# Returns human-readable string (e.g., "1.5 MB").
format_bytes() {
    local bytes="${1:-0}"

    if [ "$(echo "$bytes >= 1073741824" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc -l) GB"
    elif [ "$(echo "$bytes >= 1048576" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc -l) MB"
    elif [ "$(echo "$bytes >= 1024" | bc -l 2>/dev/null)" = "1" ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc -l) KB"
    else
        echo "${bytes} B"
    fi
}

# ── Overhead calculation ───────────────────────────────────────────

# calc_overhead_pct <baseline> <with_agent>
# Returns overhead percentage (positive = slower).
calc_overhead_pct() {
    local baseline="${1:?usage: calc_overhead_pct <baseline> <with_agent>}"
    local with_agent="${2:?usage: calc_overhead_pct <baseline> <with_agent>}"

    if [ "$baseline" = "0" ] || [ -z "$baseline" ]; then
        echo "0"
        return
    fi

    echo "scale=2; (1 - ($with_agent / $baseline)) * 100" | bc -l 2>/dev/null || echo "0"
}

# calc_latency_increase_us <baseline_us> <with_agent_us>
# Returns absolute latency increase in microseconds.
calc_latency_increase_us() {
    local baseline="${1:?usage: calc_latency_increase_us <baseline> <with_agent>}"
    local with_agent="${2:?usage: calc_latency_increase_us <baseline> <with_agent>}"

    echo "$((with_agent - baseline))"
}
