#!/bin/bash
# Benchmark v2: rule-count impact on CPU.
# Rules loaded via config YAML (not API) to guarantee all N rules are present.
# Traffic on port 5201 traverses ALL rules (no early match) before default-pass.
#
# Run from ATTACKER VM.

AGENT=192.168.56.10
SSH_KEY="${HOME}/.ssh/agent_key"
DUR=10
RUNS=3

sa() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 vagrant@$AGENT "$@"; }

measure_avg() {
    local bw="$1" total=0 i=0
    while [ "$i" -lt "$RUNS" ]; do
        local before=$(sa 'head -1 /proc/stat' | awk '{b=$2+$3+$4+$7+$8; t=$2+$3+$4+$5+$6+$7+$8+$9; print b,t}')
        if [ "$bw" = "0" ]; then sleep $DUR
        else iperf3 -c $AGENT -t $DUR -b ${bw}M -p 5201 --json >/dev/null 2>&1 || true; fi
        local after=$(sa 'head -1 /proc/stat' | awk '{b=$2+$3+$4+$7+$8; t=$2+$3+$4+$5+$6+$7+$8+$9; print b,t}')
        local bb bt ab at; read bb bt <<< "$before"; read ab at <<< "$after"
        local p=$(awk "BEGIN{d=$((ab-bb));t=$((at-bt));if(t==0)t=1;printf \"%.1f\",d*100.0/t}")
        total=$(awk "BEGIN{printf \"%.1f\",$total+$p}")
        i=$((i+1))
    done
    awk "BEGIN{printf \"%.1f\",$total/$RUNS}"
}

get_rss() {
    local pid=$(sa "pgrep -f ebpfsentinel-agent" | head -1)
    [ -z "$pid" ] && echo "0.0" && return
    local rss=$(sa "sudo grep VmRSS /proc/$pid/status" | awk '{print $2}')
    awk "BEGIN{printf \"%.1f\",${rss:-0}/1024.0}"
}

cleanup() {
    sa "sudo pkill -9 -f ebpfsentinel-agent" || true; sleep 1
    sa "sudo ip link set dev eth1 xdp off 2>/dev/null" || true
    sa "sudo rm -rf /sys/fs/bpf/ebpfsentinel 2>/dev/null" || true
}

# Generate YAML config with N rules. Each rule denies a unique port != 5201.
# Traffic to port 5201 must traverse ALL N rules before hitting default-pass.
gen_config() {
    local nrules="$1" features="$2"
    local fw=true ids=false ct=false rl=false ti=false ddos=false dns=false
    for f in $features; do
        case $f in ids) ids=true;; conntrack) ct=true;; ratelimit) rl=true;;
                   threatintel) ti=true;; ddos) ddos=true;; dns) dns=true;; esac
    done

    local config="agent:
  interfaces: [eth1]
  bind_address: 0.0.0.0
  log_level: warn
  http_port: 8080
firewall:
  enabled: $fw
  mode: block
  default_policy: pass
  rules:"

    local i=0
    while [ "$i" -lt "$nrules" ]; do
        local port=$((10000 + i))
        config="$config
    - id: fw-r${i}
      priority: $((100 + i))
      action: deny
      protocol: tcp
      dst_port: ${port}
      scope: global
      enabled: true"
        i=$((i + 1))
    done

    config="$config
ids:
  enabled: $ids
conntrack:
  enabled: $ct
ratelimit:
  enabled: $rl
  default_rate: 100000
  default_burst: 200000
  default_algorithm: token_bucket
threatintel:
  enabled: $ti
  mode: alert
ddos:
  enabled: $ddos
dns:
  enabled: $dns
alerting:
  enabled: false
audit:
  enabled: false"
    echo "$config"
}

start_with_rules() {
    local nrules="$1" features="${2:-}"
    cleanup
    gen_config "$nrules" "$features" | sa "sudo tee /tmp/b.yaml >/dev/null"
    sa "sudo EBPF_PROGRAM_DIR=/home/vagrant/ebpfsentinel/target/bpfel-unknown-none/release nohup /home/vagrant/ebpfsentinel/target/release/ebpfsentinel-agent --config /tmp/b.yaml >/dev/null 2>&1 &"
    sleep 5
    # Verify rule count
    local actual=$(sa "curl -sf http://127.0.0.1:8080/api/v1/firewall/rules 2>/dev/null" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null) || actual="?"
    echo "  Rules loaded: $actual"
}

VOLUMES="0 500 1000 5000"

echo "=== Rule Impact Benchmark v2 ==="
echo "  Agent: $AGENT, Duration: ${DUR}s × ${RUNS} runs"
echo "  Rules loaded via YAML config (guaranteed)"
echo "  Traffic: iperf3 TCP:5201 (traverses all deny rules, default-pass at end)"
echo ""

sa "pkill -f 'iperf3 -s' || true; nohup iperf3 -s -D 2>/dev/null &" || true; sleep 1

# Baseline
echo "=== BASELINE (no agent) ==="
cleanup
declare -A BL
for v in $VOLUMES; do
    p=$(measure_avg $v); BL[$v]="$p"
    [ "$v" = "0" ] && lbl="idle" || lbl="${v}M"
    printf "  %-6s %5s%%\n" "$lbl" "$p"
done

# Firewall with varying rule counts
for N in 0 10 100 500 1000; do
    echo ""
    echo "=== FIREWALL: $N rules ==="
    start_with_rules $N
    rss=$(get_rss)
    for v in $VOLUMES; do
        sys=$(measure_avg $v); bl="${BL[$v]}"
        cost=$(awk "BEGIN{c=$sys-$bl;if(c<0)c=0;printf \"%.1f\",c}")
        [ "$v" = "0" ] && lbl="idle" || lbl="${v}M"
        printf "  %-6s sys=%5s%% bl=%5s%% -> cost=%5s%%  RSS=%sMB\n" "$lbl" "$sys" "$bl" "$cost" "$rss"
    done
done

# Production-like: firewall(100) + conntrack + ids + ratelimit + threatintel + ddos + dns
echo ""
echo "=== PRODUCTION: 100 rules + all features ==="
start_with_rules 100 "ids conntrack ratelimit threatintel ddos dns"
rss=$(get_rss)
for v in $VOLUMES; do
    sys=$(measure_avg $v); bl="${BL[$v]}"
    cost=$(awk "BEGIN{c=$sys-$bl;if(c<0)c=0;printf \"%.1f\",c}")
    [ "$v" = "0" ] && lbl="idle" || lbl="${v}M"
    printf "  %-6s sys=%5s%% bl=%5s%% -> cost=%5s%%  RSS=%sMB\n" "$lbl" "$sys" "$bl" "$cost" "$rss"
done

cleanup
sa "pkill -f 'iperf3 -s'" || true
echo ""; echo "=== DONE ==="
