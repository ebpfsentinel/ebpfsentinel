#!/usr/bin/env bash
# run-profile.sh - one traffic profile of perf/09, run as root on the machine
# whose egress is shaped, printing one JSON object on stdout.
#
#   run-profile.sh <iface> <server_ip> <seconds> <flow>... [-- <ping_cgroup>...]
#
# A flow is `cgroup:port:streams:proto:length:bitrate`:
#   cgroup   a directory under /sys/fs/cgroup the sender is moved into, or `-`
#            to send from the cgroup this script runs in, which no rule names
#   port     the iperf3 server port on <server_ip> this flow uses alone
#   streams  parallel streams of the flow (iperf3 -P)
#   proto    tcp or udp
#   length   bytes written per send (iperf3 -l), 0 for iperf3's default
#   bitrate  offered rate for udp (iperf3 -b, 0 = unlimited), ignored for tcp
# Every flow runs at the same time, for <seconds>. A ping cgroup (`-` as
# above) pings <server_ip> from that cgroup every 0.2 s while the flows run.
#
# What is read before and after the flows, so that the caller can take the
# difference over the same window: /proc/stat's cpu line, the root qdisc's
# counters on <iface> (tc -s -j), and every BPF program's run time and run
# count (bpftool -j prog show, with kernel.bpf_stats_enabled set for the run
# and put back after).
set -euo pipefail

IFACE="${1:?usage: run-profile.sh <iface> <server_ip> <seconds> <flow>... [-- <ping_cgroup>...]}"
SERVER="${2:?missing server_ip}"
SECONDS_RUN="${3:?missing seconds}"
shift 3

flows=()
pings=()
while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then
        shift
        pings=("$@")
        break
    fi
    flows+=("$1")
    shift
done
[ "${#flows[@]}" -gt 0 ] || { echo "run-profile.sh: no flow" >&2; exit 2; }

WORK="$(mktemp -d /tmp/ebpfsentinel-qdisc-profile.XXXXXX)"
stats_before="$(sysctl -n kernel.bpf_stats_enabled)"
cleanup() {
    sysctl -qw "kernel.bpf_stats_enabled=${stats_before}" || true
    rm -rf "$WORK"
}
trap cleanup EXIT
sysctl -qw kernel.bpf_stats_enabled=1

# The command line of a task placed in a cgroup before it runs anything.
in_cgroup() {
    local cgroup="$1"
    shift
    if [ "$cgroup" = "-" ]; then
        exec "$@"
    fi
    echo "$BASHPID" > "/sys/fs/cgroup/${cgroup}/cgroup.procs"
    exec "$@"
}

cpu_line() { awk '$1 == "cpu" { $1 = ""; print substr($0, 2) }' /proc/stat; }
qdisc_json() { tc -s -j qdisc show dev "$IFACE" root; }
progs_json() { bpftool -j prog show; }

pids=()
i=0
for flow in "${flows[@]}"; do
    IFS=: read -r cgroup port streams proto length bitrate <<< "$flow"
    args=(-c "$SERVER" -p "$port" -t "$SECONDS_RUN" -P "$streams" -J)
    [ "$length" = "0" ] || args+=(-l "$length")
    [ "$proto" = "udp" ] && args+=(-u -b "$bitrate")
    ( in_cgroup "$cgroup" iperf3 "${args[@]}" ) > "${WORK}/flow-${i}.json" 2>/dev/null &
    pids+=("$!")
    i=$((i + 1))
done

ping_count=$((SECONDS_RUN * 5))
j=0
for cgroup in "${pings[@]}"; do
    ( in_cgroup "$cgroup" ping -n -i 0.2 -c "$ping_count" "$SERVER" ) > "${WORK}/ping-${j}.txt" 2>&1 &
    pids+=("$!")
    j=$((j + 1))
done

# Read the counters once the senders are past their first second, so the
# window covers the flows at their steady state and not their start.
sleep 1
cpu_before="$(cpu_line)"
qdisc_before="$(qdisc_json)"
progs_before="$(progs_json)"
t_before="$(date +%s%N)"
sleep "$((SECONDS_RUN - 2))"
cpu_after="$(cpu_line)"
qdisc_after="$(qdisc_json)"
progs_after="$(progs_json)"
t_after="$(date +%s%N)"

for pid in "${pids[@]}"; do
    wait "$pid" || true
done

printf '{"iface":"%s","seconds":%s,"clk_tck":%s,"window_ns":%s,' \
    "$IFACE" "$SECONDS_RUN" "$(getconf CLK_TCK)" "$((t_after - t_before))"
printf '"cpu_before":"%s","cpu_after":"%s",' "$cpu_before" "$cpu_after"
printf '"qdisc_before":%s,"qdisc_after":%s,' "$qdisc_before" "$qdisc_after"
printf '"progs_before":%s,"progs_after":%s,' "$progs_before" "$progs_after"
printf '"flows":['
for ((k = 0; k < ${#flows[@]}; k++)); do
    [ "$k" -eq 0 ] || printf ','
    body="$(cat "${WORK}/flow-${k}.json")"
    printf '{"spec":"%s","iperf3":%s}' "${flows[$k]}" "${body:-null}"
done
printf '],"pings":['
for ((k = 0; k < ${#pings[@]}; k++)); do
    [ "$k" -eq 0 ] || printf ','
    # Every reply's round trip, sorted, then its median, 99th percentile and
    # maximum; and the share of requests that got no reply.
    rtt="$({ grep -o 'time=[0-9.]*' "${WORK}/ping-${k}.txt" || true; } | cut -d= -f2 | sort -n | awk '
        { v[NR] = $1 }
        END {
            if (NR == 0) exit
            p50 = int((NR + 1) * 0.50); if (p50 < 1) p50 = 1
            p99 = int((NR + 1) * 0.99); if (p99 > NR) p99 = NR; if (p99 < 1) p99 = 1
            printf "%s,%s,%s", v[p50], v[p99], v[NR]
        }')"
    loss="$(awk '/packet loss/ { for (f = 1; f <= NF; f++) if ($f ~ /%$/) { sub("%", "", $f); print $f } }' "${WORK}/ping-${k}.txt")"
    printf '{"cgroup":"%s","rtt_ms_p50_p99_max":[%s],"loss_pct":%s}' "${pings[$k]}" "${rtt}" "${loss:-null}"
done
printf ']}\n'
