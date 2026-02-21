#!/usr/bin/env bash
# perf-test-vagrant.sh — Binary vs Docker performance comparison in Vagrant VM
#
# Boots a Vagrant VM, runs perf-test-docker.sh twice (once as a local binary,
# once via Docker), then prints a side-by-side comparison with overhead %.
#
# Usage:
#   ./perf-test-vagrant.sh [--quick] [--soak] [--skip-provision] [--report-dir DIR]
#
# Requirements: vagrant, VagrantFile in ../vagrant/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VAGRANT_DIR="${INTEGRATION_DIR}/vagrant"

# ── Parse arguments ────────────────────────────────────────────────

QUICK=false
SOAK=false
SKIP_PROVISION=false
REPORT_DIR="/tmp"
EXTRA_FLAGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --quick)          QUICK=true; EXTRA_FLAGS+=("--quick") ;;
        --soak)           SOAK=true; EXTRA_FLAGS+=("--soak") ;;
        --skip-provision) SKIP_PROVISION=true ;;
        --report-dir)     REPORT_DIR="${2:?--report-dir requires a path}"; shift ;;
        -h|--help)
            echo "Usage: $0 [--quick] [--soak] [--skip-provision] [--report-dir DIR]"
            echo ""
            echo "Options:"
            echo "  --quick            Short durations (~6 min total)"
            echo "  --soak             Enable soak test in both modes"
            echo "  --skip-provision   Skip vagrant up / provisioning"
            echo "  --report-dir       Local directory for JSON reports (default: /tmp)"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# ── Pre-flight ─────────────────────────────────────────────────────

preflight() {
    echo "=== Vagrant Perf Test — Pre-flight ==="

    if ! command -v vagrant &>/dev/null; then
        echo "ERROR: vagrant not found in PATH" >&2
        exit 1
    fi

    if [ ! -f "${VAGRANT_DIR}/Vagrantfile" ]; then
        echo "ERROR: No Vagrantfile at ${VAGRANT_DIR}/Vagrantfile" >&2
        exit 1
    fi

    if ! command -v jq &>/dev/null; then
        echo "ERROR: jq is required on the host for report comparison" >&2
        exit 1
    fi

    mkdir -p "$REPORT_DIR"

    echo "  Vagrant: $(vagrant --version)"
    echo "  Profile: $([ "$QUICK" = "true" ] && echo "quick" || echo "standard") | Soak: $SOAK"
    echo "  Reports: $REPORT_DIR"
    echo ""
}

# ── VM lifecycle ───────────────────────────────────────────────────

vm_up() {
    if [ "$SKIP_PROVISION" = "true" ]; then
        echo "=== VM — skip provision (--skip-provision) ==="
        # Just make sure it's running
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

# ── Run perf tests in VM ──────────────────────────────────────────

# vm_run_perf <mode>
# Runs perf-test-docker.sh inside the VM with the given mode.
# Returns the remote path to the JSON report.
vm_run_perf() {
    local mode="${1:?usage: vm_run_perf <binary|docker>}"

    echo "=== VM — Performance test (mode: ${mode}) ==="
    cd "$VAGRANT_DIR" && vagrant ssh -c \
        "sudo bash ~/ebpfsentinel/tests/integration/scripts/perf-test-docker.sh \
            --mode ${mode} --skip-build ${EXTRA_FLAGS[*]:-}" \
        -- -q
    echo ""
}

# vm_find_report <mode>
# Finds the most recent report file for the given mode inside the VM.
vm_find_report() {
    local mode="${1:?usage: vm_find_report <mode>}"
    cd "$VAGRANT_DIR" && vagrant ssh -c \
        "ls -1t /tmp/ebpfsentinel-perf-report-${mode}-*.json 2>/dev/null | head -1" \
        -- -q | tr -d '\r'
}

# vm_copy_report <remote_path> <local_path>
# Copies a file from the VM to the host.
vm_copy_report() {
    local remote="${1:?}"
    local local_path="${2:?}"
    cd "$VAGRANT_DIR" && vagrant ssh -c "cat '${remote}'" -- -q > "$local_path"
}

# ── Comparison ─────────────────────────────────────────────────────

# safe_jq <file> <expr> [default]
# Extracts a value from JSON, returning default on failure.
safe_jq() {
    local file="$1" expr="$2" default="${3:-N/A}"
    jq -r "$expr // empty" "$file" 2>/dev/null || echo "$default"
}

# format_overhead <binary_val> <docker_val> <higher_is_worse>
# Prints overhead % with sign. higher_is_worse=true means docker > binary is bad.
format_overhead() {
    local bval="$1" dval="$2" higher_is_worse="${3:-true}"

    if [ "$bval" = "N/A" ] || [ "$dval" = "N/A" ] || [ "$bval" = "0" ]; then
        echo "N/A"
        return
    fi

    local raw_pct
    if [ "$higher_is_worse" = "true" ]; then
        # For latency/RSS/CPU: overhead = (docker - binary) / binary * 100
        raw_pct="$(echo "scale=4; (($dval - $bval) / $bval) * 100" | bc -l 2>/dev/null)" || { echo "N/A"; return; }
    else
        # For throughput/PPS: overhead = (binary - docker) / binary * 100 (positive = docker is slower)
        raw_pct="$(echo "scale=4; (($bval - $dval) / $bval) * 100" | bc -l 2>/dev/null)" || { echo "N/A"; return; }
    fi

    # Round to 1 decimal place (LC_NUMERIC=C ensures dot decimal separator)
    local pct
    pct="$(LC_NUMERIC=C printf '%.1f' "$raw_pct" 2>/dev/null)" || { echo "N/A"; return; }

    if [[ "$pct" == -* ]]; then
        echo "${pct}%"
    else
        echo "+${pct}%"
    fi
}

# format_value <value> <unit>
format_value() {
    local val="$1" unit="$2"
    if [ "$val" = "N/A" ] || [ -z "$val" ]; then
        echo "N/A"
    else
        echo "${val} ${unit}"
    fi
}

compare_reports() {
    local binary_report="$1"
    local docker_report="$2"

    echo ""
    echo "============================================================"
    echo "  Docker vs Binary Comparison"
    echo "============================================================"
    echo ""

    # Extract metrics
    local b_tcp_gbps d_tcp_gbps b_udp_gbps d_udp_gbps
    local b_icmp d_icmp b_tcp_lat d_tcp_lat
    local b_pps d_pps b_rss d_rss b_cpu d_cpu b_api d_api

    b_tcp_gbps="$(safe_jq "$binary_report" '.alert_mode.tcp_gbps')"
    d_tcp_gbps="$(safe_jq "$docker_report" '.alert_mode.tcp_gbps')"

    b_udp_gbps="$(safe_jq "$binary_report" '.alert_mode.udp_gbps')"
    d_udp_gbps="$(safe_jq "$docker_report" '.alert_mode.udp_gbps')"

    b_icmp="$(safe_jq "$binary_report" '.alert_mode.icmp_avg_us')"
    d_icmp="$(safe_jq "$docker_report" '.alert_mode.icmp_avg_us')"

    b_tcp_lat="$(safe_jq "$binary_report" '.alert_mode.tcp_latency_ms')"
    d_tcp_lat="$(safe_jq "$docker_report" '.alert_mode.tcp_latency_ms')"

    b_pps="$(safe_jq "$binary_report" '.alert_mode.pps')"
    d_pps="$(safe_jq "$docker_report" '.alert_mode.pps')"

    b_rss="$(safe_jq "$binary_report" '.alert_mode.rss_kb')"
    d_rss="$(safe_jq "$docker_report" '.alert_mode.rss_kb')"

    b_cpu="$(safe_jq "$binary_report" '.alert_mode.cpu_pct')"
    d_cpu="$(safe_jq "$docker_report" '.alert_mode.cpu_pct')"

    b_api="$(safe_jq "$binary_report" '.api_bench.worst_p99_ms')"
    d_api="$(safe_jq "$docker_report" '.api_bench.worst_p99_ms')"

    # Print table
    printf "  %-30s  %-12s  %-12s  %s\n" "Metric" "Binary" "Docker" "Overhead"
    printf "  %-30s  %-12s  %-12s  %s\n" \
        "$(printf '%0.s─' {1..30})" \
        "$(printf '%0.s─' {1..12})" \
        "$(printf '%0.s─' {1..12})" \
        "$(printf '%0.s─' {1..10})"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "TCP throughput" \
        "$(format_value "$b_tcp_gbps" "Gbps")" \
        "$(format_value "$d_tcp_gbps" "Gbps")" \
        "$(format_overhead "$b_tcp_gbps" "$d_tcp_gbps" false)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "UDP throughput" \
        "$(format_value "$b_udp_gbps" "Gbps")" \
        "$(format_value "$d_udp_gbps" "Gbps")" \
        "$(format_overhead "$b_udp_gbps" "$d_udp_gbps" false)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "ICMP latency" \
        "$(format_value "$b_icmp" "us")" \
        "$(format_value "$d_icmp" "us")" \
        "$(format_overhead "$b_icmp" "$d_icmp" true)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "TCP conn latency" \
        "$(format_value "$b_tcp_lat" "ms")" \
        "$(format_value "$d_tcp_lat" "ms")" \
        "$(format_overhead "$b_tcp_lat" "$d_tcp_lat" true)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "PPS" \
        "$(format_value "$b_pps" "")" \
        "$(format_value "$d_pps" "")" \
        "$(format_overhead "$b_pps" "$d_pps" false)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "RSS" \
        "$(format_value "$b_rss" "KB")" \
        "$(format_value "$d_rss" "KB")" \
        "$(format_overhead "$b_rss" "$d_rss" true)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "CPU under load" \
        "$(format_value "$b_cpu" "%")" \
        "$(format_value "$d_cpu" "%")" \
        "$(format_overhead "$b_cpu" "$d_cpu" true)"

    printf "  %-30s  %-12s  %-12s  %s\n" \
        "API p99" \
        "$(format_value "$b_api" "ms")" \
        "$(format_value "$d_api" "ms")" \
        "$(format_overhead "$b_api" "$d_api" true)"

    echo ""

    # Verdicts
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

# ── Main ───────────────────────────────────────────────────────────

main() {
    echo ""
    echo "============================================================"
    echo "  eBPFsentinel Vagrant Performance Comparison"
    echo "  Binary vs Docker — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================================"
    echo ""

    preflight
    vm_up
    vm_sync

    # Build both artifacts inside VM
    vm_build_binary
    vm_build_docker
    vm_extract_ebpf_programs

    # Run binary mode
    local binary_exit=0
    vm_run_perf binary || binary_exit=$?

    # Run docker mode
    local docker_exit=0
    vm_run_perf docker || docker_exit=$?

    # Retrieve reports
    echo "=== Retrieving reports from VM ==="
    local binary_remote docker_remote
    binary_remote="$(vm_find_report binary)"
    docker_remote="$(vm_find_report docker)"

    if [ -z "$binary_remote" ]; then
        echo "ERROR: No binary mode report found in VM" >&2
        exit 1
    fi
    if [ -z "$docker_remote" ]; then
        echo "ERROR: No docker mode report found in VM" >&2
        exit 1
    fi

    local binary_local="${REPORT_DIR}/$(basename "$binary_remote")"
    local docker_local="${REPORT_DIR}/$(basename "$docker_remote")"

    vm_copy_report "$binary_remote" "$binary_local"
    echo "  Binary report: $binary_local"

    vm_copy_report "$docker_remote" "$docker_local"
    echo "  Docker report: $docker_local"
    echo ""

    # Compare
    compare_reports "$binary_local" "$docker_local"

    echo "  Reports:"
    echo "    Binary: $binary_local"
    echo "    Docker: $docker_local"
    echo ""

    # Exit with failure if either mode failed
    local exit_code=0
    if [ "$binary_exit" -ne 0 ]; then
        echo "WARNING: Binary mode exited with code $binary_exit" >&2
        exit_code=1
    fi
    if [ "$docker_exit" -ne 0 ]; then
        echo "WARNING: Docker mode exited with code $docker_exit" >&2
        exit_code=1
    fi

    exit "$exit_code"
}

main "$@"
