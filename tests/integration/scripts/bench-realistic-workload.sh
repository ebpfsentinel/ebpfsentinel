#!/bin/bash
# Realistic workload benchmark: diverse traffic patterns that exercise ALL eBPF programs.
#
# Unlike iperf3 (single TCP flow, fast-path only), this generates:
# - Multi-port TCP connections (hit firewall linear scan)
# - UDP floods on diverse ports (hit ratelimit, DDoS detection)
# - ICMP floods (hit DDoS ICMP protection)
# - SYN floods (hit syncookie forging)
# - DNS queries as UDP:53 (hit tc-dns capture)
# - IDS trigger payloads (hit tc-ids pattern matching)
# - Diverse 5-tuples (stress conntrack table)
# - Combined realistic mix (all of the above + iperf3 background)
#
# Run from ATTACKER VM with sudo (hping3 needs raw sockets).

AGENT=192.168.56.10
SSH_KEY="/home/vagrant/.ssh/agent_key"
DUR=10
RUNS=2

sa() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 vagrant@$AGENT "$@"; }

# Redirect ALL stderr from traffic generators to /dev/null.
# Only capture /proc/stat readings via SSH.
measure_avg() {
    local label="$1" gen_cmd="$2" total=0 i=0
    while [ "$i" -lt "$RUNS" ]; do
        local before=$(sa 'head -1 /proc/stat' | awk '{b=$2+$3+$4+$7+$8; t=$2+$3+$4+$5+$6+$7+$8+$9; print b,t}')
        eval "$gen_cmd" >/dev/null 2>&1
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

# ── Traffic generators ──

gen_idle() {
    sleep $DUR
}

# Mixed TCP connections to diverse ports (exercises firewall rule matching + conntrack)
# Avoids port 22 (SSH banner noise). Uses ports that hit firewall deny rules.
gen_tcp_multi_port() {
    local end=$((SECONDS + DUR))
    while [ $SECONDS -lt $end ]; do
        for port in 80 443 8080 8443 3306 5432 6379 9200 27017 10050; do
            echo "GET / HTTP/1.1" | timeout 1 ncat -w 1 $AGENT $port &
        done
        sleep 0.3
    done
    wait
}

# SYN flood with hping3 (exercises ratelimit + syncookie)
gen_syn_flood() {
    sudo timeout $DUR hping3 -S -p 80 -i u100 --rand-source $AGENT &
    sudo timeout $DUR hping3 -S -p 443 -i u100 --rand-source $AGENT &
    wait
}

# UDP flood on amp-detection ports (exercises DDoS UDP amp protection)
gen_udp_flood() {
    sudo timeout $DUR hping3 --udp -p 53 -i u200 $AGENT &
    sudo timeout $DUR hping3 --udp -p 123 -i u200 $AGENT &
    sudo timeout $DUR hping3 --udp -p 1900 -i u200 $AGENT &
    wait
}

# ICMP flood (exercises DDoS ICMP protection)
gen_icmp_flood() {
    sudo timeout $DUR hping3 --icmp -i u100 $AGENT &
    wait
}

# DNS-like UDP:53 traffic (exercises tc-dns capture). Raw UDP, no real DNS server needed.
gen_dns_traffic() {
    local end=$((SECONDS + DUR))
    while [ $SECONDS -lt $end ]; do
        # Raw DNS query bytes — tc-dns sees UDP:53 and captures
        printf '\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | \
            timeout 0.5 ncat -u -w 0 $AGENT 53 &
        printf '\x00\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07malware\x04evil\x03com\x00\x00\x01\x00\x01' | \
            timeout 0.5 ncat -u -w 0 $AGENT 53 &
        sleep 0.1
    done
    wait
}

# IDS trigger payloads (exercises tc-ids pattern matching)
gen_ids_payloads() {
    local end=$((SECONDS + DUR))
    while [ $SECONDS -lt $end ]; do
        echo '/bin/sh -i' | timeout 0.5 ncat -w 0 $AGENT 4444 &
        echo 'GET /wp-admin/install.php HTTP/1.1' | timeout 0.5 ncat -w 0 $AGENT 80 &
        echo 'GET /phpmyadmin/ HTTP/1.1' | timeout 0.5 ncat -w 0 $AGENT 8080 &
        echo 'GET /.env HTTP/1.0' | timeout 0.5 ncat -w 0 $AGENT 443 &
        sleep 0.2
    done
    wait
}

# Combined realistic workload: ALL traffic types simultaneously + iperf3 background
gen_realistic_mix() {
    gen_tcp_multi_port &
    gen_syn_flood &
    gen_udp_flood &
    gen_icmp_flood &
    gen_dns_traffic &
    gen_ids_payloads &
    iperf3 -c $AGENT -t $DUR -b 1G --json >/dev/null 2>&1 &
    wait
}

# ── Main ──
# Verify we have root (hping3 needs raw sockets)
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run with sudo (hping3 needs raw sockets)" >&2
    exit 1
fi

echo "=== Realistic Workload Benchmark ==="
echo "  Agent: $AGENT"
echo "  Duration: ${DUR}s × ${RUNS} runs per scenario"
echo "  Tools: hping3=$(command -v hping3 && echo OK || echo MISSING), ncat, iperf3"
echo ""

# Start iperf3 server for background TCP load
sa "pkill -f 'iperf3 -s' || true; nohup iperf3 -s -D 2>/dev/null &" || true
sleep 1

# ── Baseline per scenario (no agent) ──
echo "=== BASELINE (no agent) ==="
cleanup
declare -A BL

for scenario in idle tcp_multi syn_flood udp_flood icmp_flood dns ids_payloads realistic_mix; do
    case $scenario in
        idle)           cmd="gen_idle" ;;
        tcp_multi)      cmd="gen_tcp_multi_port" ;;
        syn_flood)      cmd="gen_syn_flood" ;;
        udp_flood)      cmd="gen_udp_flood" ;;
        icmp_flood)     cmd="gen_icmp_flood" ;;
        dns)            cmd="gen_dns_traffic" ;;
        ids_payloads)   cmd="gen_ids_payloads" ;;
        realistic_mix)  cmd="gen_realistic_mix" ;;
    esac
    p=$(measure_avg "$scenario" "$cmd")
    BL[$scenario]="$p"
    printf "  %-16s %5s%%\n" "$scenario" "$p"
done

# ── Production config: 100 rules + all features ──
echo ""
echo "=== PRODUCTION CONFIG (100 rules + all features) ==="

# Generate config with 100 deny rules + threatintel IOCs
RULES=""
for i in $(seq 0 99); do
    RULES="$RULES
    - id: fw-r${i}
      priority: $((100+i))
      action: deny
      protocol: tcp
      dst_port: $((10000+i))
      scope: global
      enabled: true"
done

CONFIG="agent:
  interfaces: [eth1]
  bind_address: 0.0.0.0
  log_level: warn
  http_port: 8080
firewall:
  enabled: true
  mode: block
  default_policy: pass
  rules:${RULES}
ids:
  enabled: true
  mode: alert
  rules:
    - id: ids-reverse-shell
      description: Reverse shell detection
      severity: critical
      protocol: tcp
      dst_port: 4444
      enabled: true
    - id: ids-ssh-brute
      description: SSH brute force
      severity: high
      protocol: tcp
      dst_port: 22
      threshold: 10
      enabled: true
ips:
  enabled: true
  mode: enforce
conntrack:
  enabled: true
ratelimit:
  enabled: true
  default_rate: 10000
  default_burst: 20000
  default_algorithm: token_bucket
threatintel:
  enabled: true
  mode: alert
ddos:
  enabled: true
dns:
  enabled: true
alerting:
  enabled: false
audit:
  enabled: false"

cleanup
echo "$CONFIG" | sa "sudo tee /tmp/b.yaml >/dev/null"
sa "sudo EBPF_PROGRAM_DIR=/home/vagrant/ebpfsentinel/target/bpfel-unknown-none/release nohup /home/vagrant/ebpfsentinel/target/release/ebpfsentinel-agent --config /tmp/b.yaml >/dev/null 2>&1 &"
sleep 5

rss=$(get_rss)
rules=$(sa "curl -sf http://127.0.0.1:8080/api/v1/firewall/rules 2>/dev/null" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null) || rules="?"
echo "  Rules loaded: $rules, RSS: ${rss}MB"
echo ""

for scenario in idle tcp_multi syn_flood udp_flood icmp_flood dns ids_payloads realistic_mix; do
    case $scenario in
        idle)           cmd="gen_idle" ;;
        tcp_multi)      cmd="gen_tcp_multi_port" ;;
        syn_flood)      cmd="gen_syn_flood" ;;
        udp_flood)      cmd="gen_udp_flood" ;;
        icmp_flood)     cmd="gen_icmp_flood" ;;
        dns)            cmd="gen_dns_traffic" ;;
        ids_payloads)   cmd="gen_ids_payloads" ;;
        realistic_mix)  cmd="gen_realistic_mix" ;;
    esac
    sys=$(measure_avg "$scenario" "$cmd")
    bl="${BL[$scenario]}"
    cost=$(awk "BEGIN{c=$sys-$bl;if(c<0)c=0;printf \"%.1f\",c}")
    rss_now=$(get_rss)
    printf "  %-16s sys=%5s%% bl=%5s%% -> cost=%5s%%  RSS=%sMB\n" "$scenario" "$sys" "$bl" "$cost" "$rss_now"
done

# Check alerts generated
echo ""
echo "  Alerts generated during benchmark:"
alerts=$(sa "curl -sf http://127.0.0.1:8080/api/v1/alerts 2>/dev/null" | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin)
    alerts=data if isinstance(data,list) else data.get('alerts',[])
    by_comp={}
    for a in alerts:
        c=a.get('component','unknown')
        by_comp[c]=by_comp.get(c,0)+1
    for c,n in sorted(by_comp.items()):
        print(f'    {c}: {n}')
    print(f'    total: {len(alerts)}')
except: print('    (could not parse)')
" 2>/dev/null)
echo "$alerts"

# Check metrics
echo ""
echo "  Key metrics:"
sa "curl -sf http://127.0.0.1:8080/metrics 2>/dev/null" | grep -E "^ebpfsentinel_(firewall|ids|ratelimit|ddos|conntrack|threatintel|dns)_" | head -20

cleanup
sa "pkill -f 'iperf3 -s'" || true
echo ""
echo "=== DONE ==="
