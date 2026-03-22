#!/bin/bash
# Full 2-VM benchmark: measures eBPF + agent overhead for all features.
# Run from ATTACKER VM. Agent VM must be reachable at 192.168.56.10.
#
# Method: (system CPU% on agent VM with agent) - (baseline system CPU% without agent)
# Each measurement averaged over 3 runs to reduce variance.
# RSS from /proc/PID/status VmRSS on agent VM.

AGENT=192.168.56.10
DUR=10
RUNS=3

SSH_KEY="${HOME}/.ssh/agent_key"
sa() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 vagrant@$AGENT "$@"; }

measure_once() {
    local bw="$1"
    local before=$(sa 'head -1 /proc/stat' | awk '{b=$2+$3+$4+$7+$8; t=$2+$3+$4+$5+$6+$7+$8+$9; print b,t}')
    if [ "$bw" = "0" ]; then sleep $DUR
    else iperf3 -c $AGENT -t $DUR -b ${bw}M --json >/dev/null 2>&1 || true; fi
    local after=$(sa 'head -1 /proc/stat' | awk '{b=$2+$3+$4+$7+$8; t=$2+$3+$4+$5+$6+$7+$8+$9; print b,t}')
    local bb bt ab at; read bb bt <<< "$before"; read ab at <<< "$after"
    awk "BEGIN{d=$((ab-bb));t=$((at-bt));if(t==0)t=1;printf \"%.1f\",d*100.0/t}"
}

measure_avg() {
    local bw="$1" total=0 i=0
    while [ "$i" -lt "$RUNS" ]; do
        local p=$(measure_once "$bw")
        total=$(awk "BEGIN{printf \"%.1f\",$total+$p}")
        i=$((i+1))
    done
    awk "BEGIN{printf \"%.1f\",$total/$RUNS}"
}

cleanup_agent() {
    sa "sudo pkill -9 -f ebpfsentinel-agent" || true
    sleep 1
    sa "sudo ip link set dev eth1 xdp off" || true
    sa "sudo rm -rf /sys/fs/bpf/ebpfsentinel" || true
}

start_agent() {
    local config="$1"
    cleanup_agent
    echo "$config" | sa "sudo tee /tmp/b.yaml >/dev/null"
    sa "sudo EBPF_PROGRAM_DIR=/home/vagrant/ebpfsentinel/target/bpfel-unknown-none/release nohup /home/vagrant/ebpfsentinel/target/release/ebpfsentinel-agent --config /tmp/b.yaml >/dev/null 2>&1 &"
    sleep 5
}

get_rss() {
    local pid=$(sa "pgrep -f ebpfsentinel-agent" | head -1)
    [ -z "$pid" ] && echo "0.0" && return
    local rss=$(sa "sudo grep VmRSS /proc/$pid/status" | awk '{print $2}')
    awk "BEGIN{printf \"%.1f\",${rss:-0}/1024.0}"
}

VOLUMES="0 100 500 1000 5000"
vol_label() { [ "$1" = "0" ] && echo "idle" || echo "${1}M"; }

C="alerting:
  enabled: false
audit:
  enabled: false"

IFACE="eth1"

# ── Calibrate ──
echo "=== Calibrating ==="
sa "pkill -f 'iperf3 -s' || true; nohup iperf3 -s -D 2>/dev/null &" || true
sleep 1
MAX=$(iperf3 -c $AGENT -t 3 --json 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print(f'{d[\"end\"][\"sum_received\"][\"bits_per_second\"]/1e9:.1f}')" 2>/dev/null) || MAX="?"
echo "  Max BW: ~${MAX} Gbps"
echo "  Duration: ${DUR}s × ${RUNS} runs per measurement"
echo ""

# ── Baseline ──
echo "=== BASELINE (no agent, avg of $RUNS runs) ==="
cleanup_agent
declare -A BL
for v in $VOLUMES; do
    p=$(measure_avg $v); BL[$v]="$p"
    printf "  %-6s %5s%%\n" "$(vol_label $v)" "$p"
done

# ── Run feature ──
run() {
    local name="$1" config="$2"
    echo ""; echo "=== $name ==="
    start_agent "$config"
    local rss=$(get_rss)
    for v in $VOLUMES; do
        sys=$(measure_avg $v); bl="${BL[$v]}"
        cost=$(awk "BEGIN{c=$sys-$bl;if(c<0)c=0;printf \"%.1f\",c}")
        printf "  %-6s sys=%5s%% bl=%5s%% -> cost=%5s%%  RSS=%sMB\n" "$(vol_label $v)" "$sys" "$bl" "$cost" "$rss"
    done
    cleanup_agent
}

mk_config() {
    local features="$1"
    local fw=false ids=false ips=false rl=false ti=false ct=false ddos=false dns=false
    for f in $features; do
        case $f in firewall) fw=true;; ids) ids=true;; ips) ips=true;; ratelimit) rl=true;;
                   threatintel) ti=true;; conntrack) ct=true;; ddos) ddos=true;; dns) dns=true;; esac
    done
    cat <<EOF
agent:
  interfaces: [$IFACE]
  bind_address: 0.0.0.0
  log_level: warn
  http_port: 8080
firewall:
  enabled: $fw
  default_policy: pass
  rules:
    - id: fw-1
      priority: 10
      action: deny
      protocol: tcp
      dst_port: 9999
      scope: global
      enabled: true
ids:
  enabled: $ids
ips:
  enabled: $ips
ratelimit:
  enabled: $rl
  default_rate: 100000
  default_burst: 200000
  default_algorithm: token_bucket
threatintel:
  enabled: $ti
  mode: alert
conntrack:
  enabled: $ct
ddos:
  enabled: $ddos
dns:
  enabled: $dns
$C
EOF
}

# ── Individual features ──
for feat in firewall ids ips ratelimit threatintel conntrack ddos dns; do
    run "$feat" "$(mk_config "$feat")"
done

# ── Combinations ──
for combo in "firewall ids" "ids ips" "firewall ratelimit" "ids threatintel" "conntrack ddos" "firewall ids ips ratelimit"; do
    label=$(echo $combo | tr ' ' '+')
    run "$label" "$(mk_config "$combo")"
done

# ── All features ──
run "all-features" "$(mk_config "firewall ids ips ratelimit threatintel conntrack ddos dns")"

sa "pkill -f 'iperf3 -s'" || true
echo ""; echo "=== DONE ==="
