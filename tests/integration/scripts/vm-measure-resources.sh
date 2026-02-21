#!/bin/bash
# vm-measure-resources.sh — Measure agent CPU and RSS from /proc
#
# Used by perf-test-host-to-vm.sh. Runs inside the VM via vagrant ssh.
#
# Usage: sudo ./vm-measure-resources.sh <pid> <sample_secs>
# Output: JSON {"rss_kb": N, "cpu_pct": N}

set -u

PID=${1:?usage: vm-measure-resources.sh <pid> <sample_secs>}
SAMPLE=${2:-5}

if [ ! -f "/proc/$PID/status" ]; then
    echo '{"rss_kb": 0, "cpu_pct": 0, "error": "process not found"}'
    exit 0
fi

RSS=$(grep VmRSS "/proc/$PID/status" 2>/dev/null | awk '{print $2}')

STAT1=$(cat "/proc/$PID/stat" 2>/dev/null)
UT1=$(echo "$STAT1" | awk '{print $14}')
ST1=$(echo "$STAT1" | awk '{print $15}')
T1=$((UT1 + ST1))
C1=$(awk '{print $1}' /proc/uptime)

sleep "$SAMPLE"

STAT2=$(cat "/proc/$PID/stat" 2>/dev/null)
if [ -z "$STAT2" ]; then
    echo "{\"rss_kb\": ${RSS:-0}, \"cpu_pct\": 0, \"error\": \"process exited\"}"
    exit 0
fi
UT2=$(echo "$STAT2" | awk '{print $14}')
ST2=$(echo "$STAT2" | awk '{print $15}')
T2=$((UT2 + ST2))
C2=$(awk '{print $1}' /proc/uptime)

CLK=$(getconf CLK_TCK)
DT=$((T2 - T1))
CPU=$(echo "scale=2; ($DT / $CLK) / ($C2 - $C1) * 100" | bc -l 2>/dev/null)

echo "{\"rss_kb\": ${RSS:-0}, \"cpu_pct\": ${CPU:-0}}"
