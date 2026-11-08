#!/usr/bin/env bash
# measure-footprint.sh - what the agent holds in memory, steady and at start
#
# Starts the agent once per configuration profile on the agent VM of
# tests/integration/vagrant, each start in a transient systemd service of its
# own, so the service's cgroup holds what the agent allocated and nothing
# else. Per start it records:
#
#   - startup peak: `memory.peak` of the agent's cgroup, the figure a container
#     memory limit has to hold, reached while the programs load and verify
#   - steady cgroup memory: `memory.current` once the agent has been ready for
#     SETTLE seconds, with the `anon`, `kernel`, `percpu` and `file` lines of
#     `memory.stat` beside it
#   - steady resident size: `VmRSS` of the agent (and of the warden, which runs
#     in a cgroup of its own), plus the agent's own `VmHWM`
#   - map memory: `bytes_memlock` over every map the start created, and per map
#     its name, type, max_entries, key and value size and bytes_memlock
#   - possible and online CPUs, because per-CPU maps are sized by possible CPUs
#   - where the start's kernel memory went: the growth of the node's Percpu,
#     Slab, SUnreclaim and VmallocUsed lines of /proc/meminfo, and every cgroup
#     whose `kernel` or `percpu` counter grew by more than 1 MiB. The per-CPU
#     values of per-CPU maps show in the node's Percpu line and in no cgroup,
#     so they are memory the node pays and no container limit sees
#
# Run it on an otherwise idle VM: the maps and programs counted are the ones
# that appeared during the start, against a snapshot taken just before it.
#
# Launch models:
#   oss               the installed /usr/local/bin/ebpfsentinel-agent under
#                     `warden serve`, in its own user namespace over a BPF
#                     token, as production runs it
#   enterprise        ebpfsentinel-enterprise-agent as root, standalone, with
#                     capability loading, as the enterprise lab runs it
#   enterprise-token  the same binary under the warden over a BPF token, the
#                     way the enterprise chart runs it
#
# Profiles (the OSS benchmark fixtures, rendered for eth1):
#   none         config-ebpf-benchmark.yaml with every section switched off
#   firewall     config-perf-firewall-only.yaml
#   ratelimit    config-perf-ratelimit-only.yaml
#   threatintel  config-ebpf-benchmark.yaml with every section but threatintel off
#   benchmark    config-ebpf-benchmark.yaml as it stands
#   all          tests/integration/fixtures/config-ebpf-all-programs.yaml, every
#                feature that carries a kernel program
# The enterprise launches append the perf lane's enterprise block
# (ebpfsentinel-enterprise/tests/perf/fixtures/enterprise-features.yaml) to
# every profile but `none`.
#
# Usage, from the host, with the agent VM up and the build synced to it
# (tests/integration/scripts/sync-to-agent-vm.sh --binary --warden --ebpf):
#   tests/perf/measure-footprint.sh --launch oss --out DIR
#   tests/perf/measure-footprint.sh --launch enterprise \
#       --enterprise-bin PATH --license FILE --out DIR
#   tests/perf/measure-footprint.sh --summary DIR     # tables out of DIR/*.json
#
# Options:
#   --profiles a,b,c   subset of the profiles above (default: all six)
#   --runs N           starts per profile (default 3); the median start is kept
#                      for steady figures, the highest for the peak
# Environment:
#   VAGRANT_DIR   default tests/integration/vagrant
#   SETTLE        seconds between ready and the steady reading (default 30)
#   AGENT_IFACE   default eth1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSS_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VAGRANT_DIR="${VAGRANT_DIR:-${OSS_ROOT}/tests/integration/vagrant}"
SETTLE="${SETTLE:-30}"
AGENT_IFACE="${AGENT_IFACE:-eth1}"
AGENT_IP=192.168.56.10
PEER_IP=192.168.56.20
REMOTE=/tmp/ebpfsentinel-footprint
SIEM_PORT=6514

LAUNCH=""
OUT=""
PROFILES="none,firewall,ratelimit,threatintel,benchmark,all"
RUNS=3
ENTERPRISE_BIN=""
LICENSE_FILE=""
SUMMARY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --launch) LAUNCH="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --profiles) PROFILES="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --enterprise-bin) ENTERPRISE_BIN="$2"; shift 2 ;;
        --license) LICENSE_FILE="$2"; shift 2 ;;
        --summary) SUMMARY="$2"; shift 2 ;;
        *) echo "unknown argument $1" >&2; exit 2 ;;
    esac
done

summarise() {
    python3 - "$1" <<'PY'
import glob, json, os, statistics, sys

out = sys.argv[1]
runs = {}
for path in sorted(glob.glob(os.path.join(out, "*.json"))):
    r = json.load(open(path))
    if "launch" not in r:
        continue
    runs.setdefault((r["launch"], r["cpus"]["online"], r["profile"]), []).append(r)

MB = 1e6
MIB = 1048576
order = ["none", "firewall", "ratelimit", "threatintel", "benchmark", "all"]

def median_run(rs):
    rs = sorted(rs, key=lambda r: r["steady"]["cgroup_current"])
    return rs[len(rs) // 2]

print("| launch | CPUs online/possible | profile | programs | maps | map memory (MB) | agent RSS (MB) | warden RSS (MB) | steady cgroup (MiB) | startup peak (MiB) | starts |")
print("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
for (launch, online, profile), rs in sorted(runs.items(), key=lambda kv: (kv[0][0], kv[0][1], order.index(kv[0][2]) if kv[0][2] in order else 99)):
    m = median_run(rs)
    peak = max(r["peak"]["cgroup_peak"] for r in rs)
    print(f"| {launch} | {online}/{m['cpus']['possible_count']} | {profile} | {m['programs']} | {len(m['maps'])} | "
          f"{m['maps_memlock']/MB:.1f} | {m['steady']['agent_rss_kb']*1024/MB:.0f} | {m['steady']['warden_rss_kb']*1024/MB:.1f} | "
          f"{m['steady']['cgroup_current']/MIB:.0f} | {peak/MIB:.0f} | {len(rs)} |")

print()
for (launch, online, profile), rs in sorted(runs.items()):
    if profile != "all":
        continue
    m = median_run(rs)
    print(f"### top 25 maps, {launch}, {online} CPUs online, {m['cpus']['possible_count']} possible, profile {profile}")
    print()
    print("| map | type | max_entries | key | value | bytes_memlock (MB) |")
    print("|---|---|---:|---:|---:|---:|")
    for x in sorted(m["maps"], key=lambda x: -x["bytes_memlock"])[:25]:
        print(f"| `{x['name']}` | {x['type']} | {x['max_entries']} | {x['bytes_key']} | {x['bytes_value']} | {x['bytes_memlock']/MB:.2f} |")
    per_cpu = sum(x["bytes_memlock"] for x in m["maps"] if "percpu" in x["type"])
    print()
    print(f"per-CPU map types: {per_cpu/MB:.1f} MB of {m['maps_memlock']/MB:.1f} MB")
    if "node_growth" in m:
        growth = ", ".join(f"{k} {v/MIB:+.1f}" for k, v in sorted(m["node_growth"].items()))
        print(f"node growth (MiB): {growth}")
        for c in m["charged"]:
            print(f"charged: {c['counter']} {c['cgroup']} {c['grew']/MIB:+.1f} MiB")
    print()
PY
}

if [ -n "${SUMMARY}" ]; then
    summarise "${SUMMARY}"
    exit 0
fi

case "${LAUNCH}" in
    oss) ;;
    enterprise|enterprise-token)
        [ -x "${ENTERPRISE_BIN}" ] || { echo "--enterprise-bin must name the enterprise agent built for the VM" >&2; exit 2; }
        [ -f "${LICENSE_FILE}" ] || { echo "--license must name a licence file" >&2; exit 2; }
        ;;
    *) echo "--launch takes oss, enterprise or enterprise-token" >&2; exit 2 ;;
esac
[ -n "${OUT}" ] || { echo "--out is required" >&2; exit 2; }
mkdir -p "${OUT}/configs"

ENTERPRISE_FEATURES="${OSS_ROOT}/../ebpfsentinel-enterprise/tests/perf/fixtures/enterprise-features.yaml"
BENCH="${SCRIPT_DIR}/fixtures/config-ebpf-benchmark.yaml"

render() {
    sed -e "s|__INTERFACE__|${AGENT_IFACE}|g" \
        -e "s|__DATA_DIR__|${REMOTE}/data|g" \
        -e "s|__NS_IP__|${PEER_IP}|g" \
        -e "s|__HOST_IP__|${AGENT_IP}|g" \
        -e "s|__SIEM_SINK__|127.0.0.1:${SIEM_PORT}|g"
}

# Switch off the `enabled:` key directly under every top-level section except
# the ones named, which is how the benchmark fixture yields its single-feature
# rows. Nested switches stay as written: their section is off.
only_sections() {
    awk -v keep="$1" '
        BEGIN { n = split(keep, k, ","); for (i = 1; i <= n; i++) kept[k[i]] = 1 }
        /^[a-z_]+:/ { section = $1; sub(":", "", section) }
        /^  enabled: true/ && !(section in kept) { sub("enabled: true", "enabled: false") }
        { print }
    '
}

profile_config() {
    case "$1" in
        none) render < "${BENCH}" | only_sections "" ;;
        firewall) render < "${SCRIPT_DIR}/fixtures/config-perf-firewall-only.yaml" ;;
        ratelimit) render < "${SCRIPT_DIR}/fixtures/config-perf-ratelimit-only.yaml" ;;
        threatintel) render < "${BENCH}" | only_sections threatintel ;;
        benchmark) render < "${BENCH}" ;;
        all) render < "${OSS_ROOT}/tests/integration/fixtures/config-ebpf-all-programs.yaml" ;;
        *) echo "unknown profile $1" >&2; return 1 ;;
    esac
    if [ "${LAUNCH}" != oss ] && [ "$1" != none ]; then
        echo
        render < "${ENTERPRISE_FEATURES}"
    fi
}

SSH_CFG="$(mktemp)"
trap 'rm -f "${SSH_CFG}"' EXIT
(cd "${VAGRANT_DIR}" && timeout 120 vagrant ssh-config agent) > "${SSH_CFG}"
SSH_OPTS=(-F "${SSH_CFG}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20)
root_on() { timeout 900 ssh "${SSH_OPTS[@]}" agent sudo bash -s "$@"; }

root_on <<EOS
set -e
rm -rf ${REMOTE}
mkdir -p ${REMOTE}/data ${REMOTE}/logs
EOS
if [ "${LAUNCH}" != oss ]; then
    timeout 300 scp "${SSH_OPTS[@]}" "${ENTERPRISE_BIN}" "${LICENSE_FILE}" "agent:/tmp/"
    root_on <<EOS
set -e
install -m 755 /tmp/$(basename "${ENTERPRISE_BIN}") ${REMOTE}/ebpfsentinel-enterprise-agent
install -m 644 /tmp/$(basename "${LICENSE_FILE}") ${REMOTE}/license.key
EOS
fi

# The measurement itself, run as root on the VM. Arguments: launch, profile,
# config path, run number. Prints one JSON document.
REMOTE_MEASURE=$(cat <<'MEASURE'
set -euo pipefail
LAUNCH="$1"; PROFILE="$2"; CONFIG="$3"; RUN="$4"; SETTLE="$5"; REMOTE="$6"; IFACE="$7"; SIEM_PORT="$8"

stop_all() {
    systemctl stop fp-agent.service fp-warden.service fp-sink.service >/dev/null 2>&1 || true
    systemctl reset-failed fp-agent.service fp-warden.service fp-sink.service >/dev/null 2>&1 || true
    pkill -KILL -f 'ebpfsentinel-enterprise-agent|ebpfsentinel-agent --config|warden serve' 2>/dev/null || true
    sleep 1
    ip link set dev "${IFACE}" xdp off 2>/dev/null || true
    tc qdisc del dev "${IFACE}" clsact 2>/dev/null || true
    rm -rf /sys/fs/bpf/ebpfsentinel /sys/fs/bpf/ebpfsentinel-dlp 2>/dev/null || true
}
stop_all
mountpoint -q /sys/fs/bpf || mount -t bpf bpffs /sys/fs/bpf
sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
sync; echo 3 > /proc/sys/vm/drop_caches
# Let the previous start's deferred map frees land before the snapshot.
sleep 3

bpftool map show -j > "${REMOTE}/maps-before.json"
bpftool prog show -j > "${REMOTE}/progs-before.json"
snapshot_memory() {
    grep -E '^(Percpu|Slab|SUnreclaim|VmallocUsed):' /proc/meminfo > "${REMOTE}/meminfo-$1"
    find /sys/fs/cgroup -name memory.stat -print0 \
        | xargs -0 awk '$1 == "percpu" || $1 == "kernel" { print FILENAME, $1, $2 }' > "${REMOTE}/cgstat-$1"
}
snapshot_memory before

PROPS=(-p MemoryAccounting=yes -p CPUAccounting=yes -p LimitMEMLOCK=infinity --collect -q)
case "${LAUNCH}" in
    oss|enterprise-token)
        rm -f "${REMOTE}/warden.sock"
        systemd-run --unit fp-warden "${PROPS[@]}" -- /usr/local/bin/warden serve "${REMOTE}/warden.sock" --uid 0
        for _ in $(seq 1 100); do [ -S "${REMOTE}/warden.sock" ] && break; sleep 0.1; done
        [ -S "${REMOTE}/warden.sock" ] || { echo '{"error":"warden socket never appeared"}'; exit 1; }
        ENVS=(--setenv=EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel --setenv=EBPFSENTINEL_BPFFS=/sys/fs/bpf/ebpfsentinel --setenv=EBPFSENTINEL_WARDEN_SOCK="${REMOTE}/warden.sock")
        ;;
    enterprise)
        ENVS=(--setenv=EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel)
        ;;
esac
case "${LAUNCH}" in
    oss)
        CMD=(/usr/local/bin/ebpfsentinel-agent --config "${CONFIG}")
        READY=http://127.0.0.1:8080/readyz
        ;;
    enterprise|enterprise-token)
        systemd-run --unit fp-sink -q --collect -- python3 -c "
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${SIEM_PORT})); s.listen(16)
def drain(c):
    while c.recv(65536): pass
while True:
    c, _ = s.accept(); threading.Thread(target=drain, args=(c,), daemon=True).start()
"
        CMD=("${REMOTE}/ebpfsentinel-enterprise-agent" --config "${CONFIG}" --license "${REMOTE}/license.key")
        READY=http://127.0.0.1:8444/readyz
        ;;
esac

T0=$(date +%s.%N)
systemd-run --unit fp-agent "${PROPS[@]}" "${ENVS[@]}" -p StandardOutput=file:"${REMOTE}/logs/${LAUNCH}-${PROFILE}-${RUN}.log" -p StandardError=inherit -- "${CMD[@]}"
CG=/sys/fs/cgroup/system.slice/fp-agent.service
# Ready is the API answering with the firewall attached, or, for a profile
# that attaches no XDP firewall and so never reports `ebpf_loaded`, the API
# answering with the number of loaded programs unchanged for three seconds.
ready=false
last=-1
stable=0
for _ in $(seq 1 1800); do
    body="$(curl -s --max-time 1 "${READY}" 2>/dev/null || true)"
    if printf '%s' "${body}" | grep -q '"ebpf_loaded":true'; then ready=true; break; fi
    if [ -n "${body}" ]; then
        progs=$(bpftool prog show -j | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
        if [ "${progs}" = "${last}" ]; then stable=$((stable + 1)); else stable=0; last="${progs}"; fi
        if [ "${stable}" -ge 6 ]; then ready=true; break; fi
        sleep 0.5
        continue
    fi
    systemctl is-active -q fp-agent.service || break
    sleep 0.1
done
T_READY=$(date +%s.%N)
if ! systemctl is-active -q fp-agent.service; then
    tail -20 "${REMOTE}/logs/${LAUNCH}-${PROFILE}-${RUN}.log" >&2
    echo '{"error":"agent exited before ready"}'
    stop_all
    exit 1
fi
sleep "${SETTLE}"

agent_pid=$(systemctl show -p MainPID --value fp-agent.service)
warden_pid=$(systemctl show -p MainPID --value fp-warden.service 2>/dev/null || echo 0)
kb() { awk -v k="$1:" '$1 == k { print $2 }' "/proc/$2/status" 2>/dev/null || echo 0; }
# The agent's resident size is the sum over the service's processes: the
# OSS agent re-executes itself inside its user namespace.
agent_rss=0; agent_hwm=0; agent_procs=0
for p in $(cat "${CG}/cgroup.procs"); do
    agent_procs=$(( agent_procs + 1 ))
    agent_rss=$(( agent_rss + $(kb VmRSS "$p" || echo 0) ))
    agent_hwm=$(( agent_hwm + $(kb VmHWM "$p" || echo 0) ))
done
warden_rss=0
[ "${warden_pid:-0}" != 0 ] && warden_rss=$(kb VmRSS "${warden_pid}")

bpftool map show -j > "${REMOTE}/maps-after.json"
bpftool prog show -j > "${REMOTE}/progs-after.json"
snapshot_memory after

python3 - "${REMOTE}" "${CG}" "${LAUNCH}" "${PROFILE}" "${RUN}" "${ready}" "${T0}" "${T_READY}" "${agent_rss}" "${agent_hwm}" "${warden_rss:-0}" "${SETTLE}" "${agent_procs}" <<'PY'
import json, os, sys
remote, cg, launch, profile, run, ready, t0, tr, arss, ahwm, wrss, settle, nprocs = sys.argv[1:]
before = {m["id"] for m in json.load(open(f"{remote}/maps-before.json"))}
after = json.load(open(f"{remote}/maps-after.json"))
pb = {p["id"] for p in json.load(open(f"{remote}/progs-before.json"))}
pa = [p for p in json.load(open(f"{remote}/progs-after.json")) if p["id"] not in pb]
maps = [
    {k: m.get(k, 0) for k in ("name", "type", "max_entries", "bytes_key", "bytes_value", "bytes_memlock")}
    for m in after if m["id"] not in before
]
stat = dict(line.split() for line in open(f"{cg}/memory.stat"))
def meminfo(when):
    return {l.split(":")[0]: int(l.split()[1]) * 1024 for l in open(f"{remote}/meminfo-{when}")}
mb, ma = meminfo("before"), meminfo("after")
def cgstat(when):
    out = {}
    for line in open(f"{remote}/cgstat-{when}"):
        path, key, value = line.split()
        out[(path.removeprefix("/sys/fs/cgroup").removesuffix("/memory.stat") or "/", key)] = int(value)
    return out
cb, ca = cgstat("before"), cgstat("after")
# Where the start's kernel and per-CPU memory was charged: every cgroup whose
# counter grew by more than a MiB, the agent's own and its ancestors included.
charged = sorted(
    ({"cgroup": k[0], "counter": k[1], "grew": v - cb.get(k, 0)} for k, v in ca.items() if v - cb.get(k, 0) > 1048576),
    key=lambda x: (x["counter"], x["cgroup"]),
)
def read(p):
    return open(p).read().strip()
def cpus(path):
    total = 0
    for part in read(path).split(","):
        a, _, b = part.partition("-")
        total += (int(b) if b else int(a)) - int(a) + 1
    return total
print(json.dumps({
    "launch": launch,
    "profile": profile,
    "run": int(run),
    "ready": ready == "true",
    "seconds_to_ready": round(float(tr) - float(t0), 1),
    "settle_seconds": int(settle),
    "kernel": os.uname().release,
    "cpus": {
        "possible": read("/sys/devices/system/cpu/possible"),
        "online": cpus("/sys/devices/system/cpu/online"),
        "possible_count": cpus("/sys/devices/system/cpu/possible"),
    },
    "mem_total_kb": int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemTotal"))),
    "programs": len(pa),
    "maps_memlock": sum(m["bytes_memlock"] for m in maps),
    "maps": maps,
    "node_growth": {k: ma[k] - mb[k] for k in ma},
    "charged": charged,
    "steady": {
        "cgroup_current": int(read(f"{cg}/memory.current")),
        "anon": int(stat.get("anon", 0)),
        "file": int(stat.get("file", 0)),
        "kernel": int(stat.get("kernel", 0)),
        "percpu": int(stat.get("percpu", 0)),
        "agent_processes": int(nprocs),
        "agent_rss_kb": int(arss),
        "warden_rss_kb": int(wrss),
    },
    "peak": {
        "cgroup_peak": int(read(f"{cg}/memory.peak")),
        "agent_hwm_kb": int(ahwm),
    },
}))
PY
stop_all
MEASURE
)

IFS=',' read -r -a WANT <<< "${PROFILES}"
for profile in "${WANT[@]}"; do
    profile_config "${profile}" > "${OUT}/configs/${LAUNCH}-${profile}.yaml"
    timeout 120 scp "${SSH_OPTS[@]}" "${OUT}/configs/${LAUNCH}-${profile}.yaml" "agent:/tmp/fp-config.yaml"
    root_on <<EOS
install -o root -g root -m 640 /tmp/fp-config.yaml ${REMOTE}/${LAUNCH}-${profile}.yaml
EOS
    for run in $(seq 1 "${RUNS}"); do
        printf '[%s] %s %s run %s\n' "$(date -u +%H:%M:%S)" "${LAUNCH}" "${profile}" "${run}" >&2
        result="$(printf '%s\n' "${REMOTE_MEASURE}" | root_on -- "${LAUNCH}" "${profile}" "${REMOTE}/${LAUNCH}-${profile}.yaml" "${run}" "${SETTLE}" "${REMOTE}" "${AGENT_IFACE}" "${SIEM_PORT}")" || {
            echo "${LAUNCH} ${profile} run ${run} failed: ${result}" >&2
            continue
        }
        cpus="$(printf '%s' "${result}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["cpus"]["online"])')"
        printf '%s\n' "${result}" > "${OUT}/${LAUNCH}-${cpus}cpu-${profile}-r${run}.json"
    done
done
summarise "${OUT}"
