#!/usr/bin/env bash
# benchmark-resource-matrix.sh — Feature × Volume resource consumption matrix
#
# Measures CPU% and RSS for each eBPF feature combination under different
# traffic volumes. Produces a JSON report and a markdown table suitable
# for the README.
#
# Usage:
#   ./benchmark-resource-matrix.sh [OPTIONS]
#
# Options:
#   --profile NAME      Override auto-detected VM profile name (e.g. "4vCPU-4GB")
#   --duration SECS     Traffic duration per measurement (default: 15)
#   --output FILE       JSON report path (default: /tmp/ebpfsentinel-resource-matrix-{profile}.json)
#   --merge FILE1 FILE2 Merge two profile reports into a combined markdown table
#   --2vm               Enable 2-VM mode (agent on remote VM via SSH)
#
# Environment (2VM mode):
#   EBPF_AGENT_VM       Agent VM IP (default: 192.168.56.10)
#   AGENT_SSH_KEY        SSH key for agent VM
#
# Examples:
#   # Run on current VM (auto-detects 4vCPU-4GB or 8vCPU-8GB)
#   ./benchmark-resource-matrix.sh
#
#   # Run in 2VM mode
#   ./benchmark-resource-matrix.sh --2vm
#
#   # Merge two reports for README
#   ./benchmark-resource-matrix.sh --merge report-4vcpu.json report-8vcpu.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────
DURATION=15
PROFILE=""
OUTPUT=""
MODE_2VM=false
MERGE_MODE=false
MERGE_FILE1=""
MERGE_FILE2=""

AGENT_VM_IP="${EBPF_AGENT_VM:-192.168.56.10}"
SSH_KEY="${AGENT_SSH_KEY:-}"
AGENT_HTTP_PORT=8080

# Feature configurations to benchmark (label → features to enable)
# Individual features, then combinations, then all
declare -a FEATURE_LABELS=(
    "no-agent"
    # ── Individual features ──
    "firewall"
    "ids"
    "ips"
    "ratelimit"
    "threatintel"
    "conntrack"
    "ddos"
    "dns"
    # ── Feature combinations ──
    "firewall+ids"
    "ids+ips"
    "firewall+ratelimit"
    "ids+threatintel"
    "conntrack+ddos"
    "firewall+ids+ips+ratelimit"
    # ── All features ──
    "all-features"
)

declare -a FEATURE_FLAGS=(
    ""
    # ── Individual features ──
    "firewall"
    "ids"
    "ips"
    "ratelimit"
    "threatintel"
    "conntrack"
    "ddos"
    "dns"
    # ── Feature combinations ──
    "firewall ids"
    "ids ips"
    "firewall ratelimit"
    "ids threatintel"
    "conntrack ddos"
    "firewall ids ips ratelimit"
    # ── All features ──
    "firewall ids ips ratelimit threatintel conntrack ddos dns"
)

# Traffic volumes (label → iperf3 args)
# max-bandwidth: no rate cap, iperf3 sends as fast as the link allows
declare -a VOLUME_LABELS=("idle" "100mbps" "1gbps" "max-bandwidth")
declare -a VOLUME_IPERF_ARGS=("" "-b 100M" "-b 1G" "")

# ── Parse arguments ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)   PROFILE="$2"; shift 2 ;;
        --duration)  DURATION="$2"; shift 2 ;;
        --output)    OUTPUT="$2"; shift 2 ;;
        --2vm)       MODE_2VM=true; shift ;;
        --merge)     MERGE_MODE=true; MERGE_FILE1="$2"; MERGE_FILE2="$3"; shift 3 ;;
        -h|--help)   head -30 "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── SSH helpers ────────────────────────────────────────────────────
_ssh_cmd() {
    if [ -z "$SSH_KEY" ]; then
        # Try Vagrant key
        local vagrant_key="${INTEGRATION_DIR}/vagrant/.vagrant/machines/agent/virtualbox/private_key"
        [ -f "$vagrant_key" ] && SSH_KEY="$vagrant_key"
    fi
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "vagrant@${AGENT_VM_IP}" "$@"
}

_ssh_sudo() {
    _ssh_cmd sudo "$@"
}

_scp_to() {
    local src="$1" dst="$2"
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$src" "vagrant@${AGENT_VM_IP}:${dst}"
}

# ── Merge mode ─────────────────────────────────────────────────────
if [ "$MERGE_MODE" = true ]; then
    if [ ! -f "$MERGE_FILE1" ] || [ ! -f "$MERGE_FILE2" ]; then
        echo "Error: both report files must exist" >&2
        exit 1
    fi

    profile1="$(jq -r '.profile' "$MERGE_FILE1")"
    profile2="$(jq -r '.profile' "$MERGE_FILE2")"

    echo ""
    echo "## Resource Consumption Matrix"
    echo ""
    echo "> CPU% = system-wide busy / total — compare against 'no-agent' baseline for true eBPF cost."
    echo ""
    echo "| Feature | Traffic | CPU % ($profile1) | RSS MB ($profile1) | CPU % ($profile2) | RSS MB ($profile2) |"
    echo "|---------|---------|-------------------|--------------------|-------------------|--------------------|"

    jq -r '.measurements[] | "\(.feature)|\(.volume)"' "$MERGE_FILE1" | while IFS='|' read -r feat vol; do
        cpu1=$(jq -r --arg f "$feat" --arg v "$vol" '.measurements[] | select(.feature == $f and .volume == $v) | .cpu_pct' "$MERGE_FILE1")
        rss1=$(jq -r --arg f "$feat" --arg v "$vol" '.measurements[] | select(.feature == $f and .volume == $v) | .rss_mb' "$MERGE_FILE1")
        cpu2=$(jq -r --arg f "$feat" --arg v "$vol" '.measurements[] | select(.feature == $f and .volume == $v) | .cpu_pct // "—"' "$MERGE_FILE2")
        rss2=$(jq -r --arg f "$feat" --arg v "$vol" '.measurements[] | select(.feature == $f and .volume == $v) | .rss_mb // "—"' "$MERGE_FILE2")
        printf "| %-20s | %-7s | %17s | %18s | %17s | %18s |\n" "$feat" "$vol" "${cpu1}%" "${rss1}" "${cpu2}%" "${rss2}"
    done

    exit 0
fi

# ── Detect VM profile ──────────────────────────────────────────────
_detect_profile() {
    local vcpus mem_gb

    if [ "$MODE_2VM" = true ]; then
        vcpus="$(_ssh_cmd nproc 2>/dev/null)" || vcpus="?"
        mem_gb="$(_ssh_cmd "awk '/MemTotal/{printf \"%.0f\", \$2/1048576}' /proc/meminfo" 2>/dev/null)" || mem_gb="?"
    else
        vcpus="$(nproc)"
        mem_gb="$(awk '/MemTotal/{printf "%.0f", $2/1048576}' /proc/meminfo)"
    fi

    echo "${vcpus}vCPU-${mem_gb}GB"
}

if [ -z "$PROFILE" ]; then
    PROFILE="$(_detect_profile)"
fi

if [ -z "$OUTPUT" ]; then
    OUTPUT="/tmp/ebpfsentinel-resource-matrix-${PROFILE}.json"
fi

echo "=== eBPFsentinel Resource Matrix Benchmark ==="
echo "Profile:  ${PROFILE}"
echo "Duration: ${DURATION}s per measurement"
echo "Mode:     $([ "$MODE_2VM" = true ] && echo "2VM (agent: ${AGENT_VM_IP})" || echo "local")"
echo "Output:   ${OUTPUT}"
echo ""

# ── Config generation ──────────────────────────────────────────────
_make_config() {
    local features="$1"
    local enable_firewall=false enable_ids=false enable_ips=false
    local enable_ratelimit=false enable_threatintel=false
    local enable_conntrack=false enable_ddos=false enable_dns=false

    for feat in $features; do
        case "$feat" in
            firewall)    enable_firewall=true ;;
            ids)         enable_ids=true ;;
            ips)         enable_ips=true ;;
            ratelimit)   enable_ratelimit=true ;;
            threatintel) enable_threatintel=true ;;
            conntrack)   enable_conntrack=true ;;
            ddos)        enable_ddos=true ;;
            dns)         enable_dns=true ;;
        esac
    done

    local iface="eth1"
    [ "$MODE_2VM" != true ] && iface="${EBPF_VETH_HOST:-lo}"

    local config_file="/tmp/ebpfsentinel-bench-config-$$.yaml"
    cat > "$config_file" <<EOF
agent:
  interfaces:
    - ${iface}
  bind_address: "0.0.0.0"
  log_level: warn
  http_port: 8080
  grpc_port: 50051
  metrics_port: 9090

firewall:
  enabled: ${enable_firewall}
  default_policy: pass
  rules:
    - id: fw-bench-deny
      priority: 10
      action: deny
      protocol: tcp
      dst_port: 9999
      scope: global
      enabled: true

ids:
  enabled: ${enable_ids}
  mode: alert
  rules:
    - id: ids-bench-1
      description: "Benchmark IDS rule"
      severity: medium
      protocol: tcp
      dst_port: 4444
      enabled: true

ips:
  enabled: ${enable_ips}
  mode: enforce
  rules:
    - id: ips-bench-1
      description: "Benchmark IPS rule"
      severity: high
      protocol: tcp
      dst_port: 4445
      action: drop
      enabled: true

ratelimit:
  enabled: ${enable_ratelimit}
  default_rate: 100000
  default_burst: 200000
  default_algorithm: token_bucket
  rules:
    - id: rl-bench-1
      rate: 100000
      burst: 200000
      scope: global
      algorithm: token_bucket
      action: drop
      enabled: true

threatintel:
  enabled: ${enable_threatintel}
  mode: alert
  feeds: []

conntrack:
  enabled: ${enable_conntrack}
  half_open_threshold: 100
  rst_threshold: 50
  fin_threshold: 50
  ack_threshold: 200

ddos:
  enabled: ${enable_ddos}
  policies: []

dns:
  enabled: ${enable_dns}

alerting:
  enabled: false

audit:
  enabled: false
EOF

    echo "$config_file"
}

# ── Agent lifecycle ────────────────────────────────────────────────
REMOTE_CONFIG="/tmp/ebpfsentinel-bench-config.yaml"
REMOTE_LOG="/tmp/ebpfsentinel-bench.log"
REMOTE_PID_FILE="/tmp/ebpfsentinel-bench.pid"
AGENT_PID=""

_start_agent() {
    local config_file="$1"

    if [ "$MODE_2VM" = true ]; then
        _ssh_sudo pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
        sleep 1

        _scp_to "$config_file" "$REMOTE_CONFIG"
        _ssh_sudo bash -c "'nohup /usr/local/bin/ebpfsentinel-agent --config ${REMOTE_CONFIG} >${REMOTE_LOG} 2>&1 & echo \$! > ${REMOTE_PID_FILE}'"
        sleep 2

        AGENT_PID="$(_ssh_cmd cat "$REMOTE_PID_FILE" 2>/dev/null)" || true
        if [ -z "$AGENT_PID" ]; then
            echo "  ERROR: Failed to start agent" >&2
            return 1
        fi

        # Wait for healthz
        local attempts=0
        while [ "$attempts" -lt 30 ]; do
            if curl -sf --max-time 2 "http://${AGENT_VM_IP}:${AGENT_HTTP_PORT}/healthz" >/dev/null 2>&1; then
                return 0
            fi
            sleep 1
            attempts=$((attempts + 1))
        done
        echo "  ERROR: Agent not healthy after 30s" >&2
        return 1
    else
        # Local mode
        sudo pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
        sleep 1

        sudo nohup /usr/local/bin/ebpfsentinel-agent --config "$config_file" > "$REMOTE_LOG" 2>&1 &
        AGENT_PID=$!
        echo "$AGENT_PID" > "$REMOTE_PID_FILE"

        local attempts=0
        while [ "$attempts" -lt 30 ]; do
            if curl -sf --max-time 2 "http://127.0.0.1:${AGENT_HTTP_PORT}/healthz" >/dev/null 2>&1; then
                return 0
            fi
            sleep 1
            attempts=$((attempts + 1))
        done
        echo "  ERROR: Agent not healthy after 30s" >&2
        return 1
    fi
}

_stop_agent() {
    if [ "$MODE_2VM" = true ]; then
        _ssh_sudo pkill -f ebpfsentinel-agent 2>/dev/null || true
        sleep 1
        _ssh_sudo pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
    else
        sudo pkill -f ebpfsentinel-agent 2>/dev/null || true
        sleep 1
        sudo pkill -9 -f ebpfsentinel-agent 2>/dev/null || true
    fi
    AGENT_PID=""
    sleep 1
}

# ── CPU + RSS measurement ──────────────────────────────────────────
# CPU: system-wide /proc/stat delta (captures kernel softirq from eBPF)
#   CPU% = delta(user+nice+system+irq+softirq) / delta(total) * 100
# RSS: per-process /proc/PID/status VmRSS

_read_system_cpu() {
    # Returns: user nice system idle iowait irq softirq steal (8 fields)
    if [ "$MODE_2VM" = true ]; then
        _ssh_cmd "head -1 /proc/stat" 2>/dev/null | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}'
    else
        head -1 /proc/stat | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}'
    fi
}

_read_rss_kb() {
    local pid="$1"
    if [ "$MODE_2VM" = true ]; then
        _ssh_sudo grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}'
    else
        sudo grep VmRSS "/proc/${pid}/status" 2>/dev/null | awk '{print $2}'
    fi
}

_measure_resources() {
    # $1 = agent PID, $2 = traffic volume index
    local pid="$1"
    local vol_idx="$2"
    local vol_args="${VOLUME_IPERF_ARGS[$vol_idx]}"

    local target_ip="$AGENT_VM_IP"
    [ "$MODE_2VM" != true ] && target_ip="${EBPF_HOST_IP:-10.200.0.1}"

    # Read system-wide CPU counters before
    local cpu_before
    cpu_before="$(_read_system_cpu)"
    read -r b_user b_nice b_sys b_idle b_iowait b_irq b_softirq b_steal <<< "$cpu_before"

    # Generate traffic (or idle)
    local vol_label="${VOLUME_LABELS[$vol_idx]}"
    if [ "$vol_label" = "idle" ]; then
        sleep "$DURATION"
    elif [ -n "$vol_args" ]; then
        iperf3 -c "$target_ip" -t "$DURATION" $vol_args --json >/dev/null 2>&1 || true
    else
        # max-bandwidth: no rate cap
        iperf3 -c "$target_ip" -t "$DURATION" --json >/dev/null 2>&1 || true
    fi

    # Read system-wide CPU counters after
    local cpu_after
    cpu_after="$(_read_system_cpu)"
    read -r a_user a_nice a_sys a_idle a_iowait a_irq a_softirq a_steal <<< "$cpu_after"

    # Compute CPU% = delta_busy / delta_total * 100
    # busy = user + nice + system + irq + softirq (captures eBPF softirq work)
    local d_user=$(( a_user - b_user ))
    local d_nice=$(( a_nice - b_nice ))
    local d_sys=$(( a_sys - b_sys ))
    local d_idle=$(( a_idle - b_idle ))
    local d_iowait=$(( a_iowait - b_iowait ))
    local d_irq=$(( a_irq - b_irq ))
    local d_softirq=$(( a_softirq - b_softirq ))
    local d_steal=$(( a_steal - b_steal ))

    local d_busy=$(( d_user + d_nice + d_sys + d_irq + d_softirq ))
    local d_total=$(( d_busy + d_idle + d_iowait + d_steal ))
    [ "$d_total" -eq 0 ] && d_total=1

    local cpu_pct
    cpu_pct="$(LC_ALL=C awk "BEGIN {printf \"%.1f\", ${d_busy} * 100.0 / ${d_total}}")" || cpu_pct="0.0"

    # Read RSS
    local rss_kb
    rss_kb="$(_read_rss_kb "$pid")" || rss_kb=0
    local rss_mb
    rss_mb="$(LC_ALL=C awk "BEGIN {printf \"%.1f\", ${rss_kb:-0} / 1024.0}")" || rss_mb="0.0"

    echo "${cpu_pct}|${rss_mb}|${rss_kb}"
}

# ── iperf3 server management ──────────────────────────────────────
_start_iperf_server() {
    if [ "$MODE_2VM" = true ]; then
        _ssh_sudo pkill -f "iperf3 -s" 2>/dev/null || true
        sleep 0.5
        _ssh_sudo bash -c "'iperf3 -s -D --pidfile /tmp/iperf3-bench-matrix.pid'" 2>/dev/null || true
    else
        pkill -f "iperf3 -s" 2>/dev/null || true
        sleep 0.5
        iperf3 -s -B "${EBPF_HOST_IP:-10.200.0.1}" -D --pidfile /tmp/iperf3-bench-matrix.pid 2>/dev/null || true
    fi
    sleep 1
}

_stop_iperf_server() {
    if [ "$MODE_2VM" = true ]; then
        _ssh_sudo pkill -f "iperf3 -s" 2>/dev/null || true
    else
        pkill -f "iperf3 -s" 2>/dev/null || true
    fi
}

# ── Main benchmark loop ───────────────────────────────────────────
_start_iperf_server

# Initialize report
rm -f "$OUTPUT"
echo '{"profile":"'"$PROFILE"'","duration_s":'"$DURATION"',"measurements":[]}' > "$OUTPUT"

# Measure system baseline (no agent, idle)
echo "--- Measuring system baseline ---"
if [ "$MODE_2VM" = true ]; then
    baseline_cpu="$(_ssh_cmd "awk '/^cpu /{u=\$2;n=\$3;s=\$4;idle=\$5; printf \"%.1f\", (u+n+s)/(u+n+s+idle)*100}' /proc/stat" 2>/dev/null)" || baseline_cpu="0"
    baseline_mem="$(_ssh_cmd "awk '/MemAvailable/{printf \"%.0f\", \$2/1024}' /proc/meminfo" 2>/dev/null)" || baseline_mem="0"
else
    baseline_cpu="$(awk '/^cpu /{u=$2;n=$3;s=$4;idle=$5; printf "%.1f", (u+n+s)/(u+n+s+idle)*100}' /proc/stat)" || baseline_cpu="0"
    baseline_mem="$(awk '/MemAvailable/{printf "%.0f", $2/1024}' /proc/meminfo)" || baseline_mem="0"
fi
echo "  System CPU: ${baseline_cpu}%, Available RAM: ${baseline_mem} MB"

# Calibrate max bandwidth (3s burst, no agent)
echo "--- Calibrating max bandwidth ---"
MAX_BW_GBPS=""
cal_target="$AGENT_VM_IP"
[ "$MODE_2VM" != true ] && cal_target="${EBPF_HOST_IP:-10.200.0.1}"
max_bps="$(iperf3 -c "$cal_target" -t 3 --json 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['end']['sum_sent']['bits_per_second'])" 2>/dev/null)" || max_bps=""
if [ -n "$max_bps" ]; then
    MAX_BW_GBPS="$(LC_ALL=C awk "BEGIN {printf \"%.1f\", ${max_bps} / 1000000000}")"
    echo "  Max link bandwidth: ~${MAX_BW_GBPS} Gbps"
else
    MAX_BW_GBPS="unknown"
    echo "  Max link bandwidth: could not measure"
fi

total_features=${#FEATURE_LABELS[@]}
total_volumes=${#VOLUME_LABELS[@]}
measurement_idx=0

for feat_idx in $(seq 0 $(( total_features - 1 ))); do
    feat_label="${FEATURE_LABELS[$feat_idx]}"
    feat_flags="${FEATURE_FLAGS[$feat_idx]}"

    echo ""
    echo "=== Feature: ${feat_label} ==="

    if [ "$feat_label" = "no-agent" ]; then
        # Measure system without agent at each volume
        _stop_agent 2>/dev/null || true

        for vol_idx in $(seq 0 $(( total_volumes - 1 ))); do
            vol_label="${VOLUME_LABELS[$vol_idx]}"
            vol_args="${VOLUME_IPERF_ARGS[$vol_idx]}"
            echo "  Volume: ${vol_label}..."

            local_target="$AGENT_VM_IP"
            [ "$MODE_2VM" != true ] && local_target="${EBPF_HOST_IP:-10.200.0.1}"

            if [ "$vol_label" = "idle" ]; then
                sleep "$DURATION"
            elif [ -n "$vol_args" ]; then
                iperf3 -c "$local_target" -t "$DURATION" $vol_args --json >/dev/null 2>&1 || true
            else
                iperf3 -c "$local_target" -t "$DURATION" --json >/dev/null 2>&1 || true
            fi

            # Record as 0% CPU, 0 RSS (no agent)
            tmp="$(jq --arg f "$feat_label" --arg v "$vol_label" \
                '.measurements += [{"feature":$f,"volume":$v,"cpu_pct":"0.0","rss_mb":"0.0","rss_kb":0}]' "$OUTPUT")"
            echo "$tmp" > "$OUTPUT"
            echo "    CPU: 0.0% (no agent), RSS: 0.0 MB"
        done
        continue
    fi

    # Generate config and start agent
    config_file="$(_make_config "$feat_flags")"

    if ! _start_agent "$config_file"; then
        echo "  SKIP: agent failed to start"
        for vol_idx in $(seq 0 $(( total_volumes - 1 ))); do
            vol_label="${VOLUME_LABELS[$vol_idx]}"
            tmp="$(jq --arg f "$feat_label" --arg v "$vol_label" \
                '.measurements += [{"feature":$f,"volume":$v,"cpu_pct":"—","rss_mb":"—","rss_kb":0}]' "$OUTPUT")"
            echo "$tmp" > "$OUTPUT"
        done
        _stop_agent 2>/dev/null || true
        rm -f "$config_file"
        continue
    fi

    echo "  Agent PID: ${AGENT_PID}"

    # Warm up: let agent settle
    sleep 3

    for vol_idx in $(seq 0 $(( total_volumes - 1 ))); do
        vol_label="${VOLUME_LABELS[$vol_idx]}"
        echo "  Volume: ${vol_label}..."

        result="$(_measure_resources "$AGENT_PID" "$vol_idx")"
        IFS='|' read -r cpu_pct rss_mb rss_kb <<< "$result"

        tmp="$(jq --arg f "$feat_label" --arg v "$vol_label" \
            --arg cpu "$cpu_pct" --arg rss "$rss_mb" --argjson rsskb "${rss_kb:-0}" \
            '.measurements += [{"feature":$f,"volume":$v,"cpu_pct":$cpu,"rss_mb":$rss,"rss_kb":$rsskb}]' "$OUTPUT")"
        echo "$tmp" > "$OUTPUT"

        echo "    CPU: ${cpu_pct}%, RSS: ${rss_mb} MB"

        # Brief pause between measurements
        sleep 2
    done

    _stop_agent
    rm -f "$config_file"
done

# ── Add metadata to report ─────────────────────────────────────────
tmp="$(jq --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg p "$PROFILE" \
    '. + {timestamp: $ts, profile: $p}' "$OUTPUT")"
echo "$tmp" > "$OUTPUT"

if [ "$MODE_2VM" = true ]; then
    kernel="$(_ssh_cmd uname -r 2>/dev/null)" || kernel="unknown"
else
    kernel="$(uname -r)"
fi
tmp="$(jq --arg k "$kernel" --arg bw "$MAX_BW_GBPS" '. + {kernel: $k, max_bandwidth_gbps: $bw}' "$OUTPUT")"
echo "$tmp" > "$OUTPUT"

_stop_iperf_server

# ── Print markdown table ───────────────────────────────────────────
echo ""
echo ""
echo "## Resource Consumption — ${PROFILE}"
echo ""
echo "> CPU% = system-wide busy (user+sys+irq+softirq) / total — includes eBPF softirq overhead."
echo "> Compare each feature row against 'no-agent' at the same traffic volume for true eBPF cost."
echo "> max-bandwidth = ~${MAX_BW_GBPS} Gbps (measured link maximum, no rate cap)."
echo ""
echo "| Feature | Traffic | CPU % | RSS (MB) |"
echo "|---------|---------|------:|---------:|"

jq -r '.measurements[] | "| \(.feature) | \(.volume) | \(.cpu_pct)% | \(.rss_mb) |"' "$OUTPUT"

echo ""
echo "Report saved to: ${OUTPUT}"
echo ""
echo "To merge two profiles into a comparison table:"
echo "  $0 --merge ${OUTPUT} /tmp/ebpfsentinel-resource-matrix-OTHER.json"
