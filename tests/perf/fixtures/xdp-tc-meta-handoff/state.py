#!/usr/bin/env python3
"""state.py - the reading and detaching handoff.sh cannot do with bpftool alone.

  state.py sample <dev> <pin_root>
      One JSON line: monotonic time, the device's rx_packets, the cpu line of
      /proc/stat, run time and count of every loaded hm_ program summed by
      name (kernel.bpf_stats_enabled must be 1), the hm_cnt counters summed
      over CPUs and over every copy of the object, and the hm_probe counters
      of the first copy.
  state.py attached <dev>
      One JSON line: the XDP program on <dev> (name and mode) and the names of
      the tcx ingress programs, ours or not.
  state.py tcx-detach <dev> <pinned_prog>...
      Detach each pinned program from <dev>'s tcx ingress by its own file
      descriptor, so that nothing else attached there is touched. A program
      that is not attached is not an error.

Counter layout: handoff.bpf.c, enum C_* (hm_cnt) and enum P_* (hm_probe).
"""
import ctypes
import json
import os
import platform
import subprocess
import sys
import time

C_NAMES = ["xdp_run", "xdp_meta_refused", "xdp_unparsed", "xdp_vlan_inline",
           "tc_cb_hit", "tc_meta_hit", "tc_meta_bad", "tc_parse", "tc_unparsed"]
P_NAMES = ["runs", "dynptr_valid", "datameta_valid", "meta_absent", "meta_bad", "ip",
           "agree", "disagree", "agree_after_strip", "skb_vlan", "meta_vlan",
           "tc_inline_vlan", "vlan_id_agree", "readers_differ"]
C_MAX = 12
P_MAX = 16

BPF_OBJ_GET = 7
BPF_PROG_DETACH = 9
BPF_TCX_INGRESS = 46
SYS_BPF = {"x86_64": 321, "aarch64": 280}


def bpftool(*args):
    out = subprocess.run(["bpftool", "-j", *args], check=True, capture_output=True, text=True)
    return json.loads(out.stdout or "null")


def u64s(raw, count):
    """A value bpftool printed without BTF: a list of hex byte strings."""
    data = bytes(int(b, 16) for b in raw)
    return [int.from_bytes(data[i * 8:i * 8 + 8], "little") for i in range(count)]


def counters(path):
    total = [0] * C_MAX
    for entry in bpftool("map", "dump", "pinned", path):
        if "formatted" in entry:
            per_cpu = [v["value"]["c"] for v in entry["formatted"]["values"]]
        else:
            per_cpu = [u64s(v["value"], C_MAX) for v in entry["values"]]
        for values in per_cpu:
            for i, v in enumerate(values[:C_MAX]):
                total[i] += int(v)
    return total


def probe(path):
    total = [0] * P_MAX
    for entry in bpftool("map", "dump", "pinned", path):
        if "formatted" in entry:
            key, value = entry["formatted"]["key"], entry["formatted"]["value"]
        else:
            key = u64s(entry["key"] + ["0x00"] * 4, 1)[0]
            value = u64s(entry["value"], 1)[0]
        if int(key) < P_MAX:
            total[int(key)] = int(value)
    return total


def sample(dev, root):
    with open(f"/sys/class/net/{dev}/statistics/rx_packets", encoding="ascii") as fh:
        rx = int(fh.read())
    with open("/proc/stat", encoding="ascii") as fh:
        cpu = [int(x) for x in fh.readline().split()[1:8]]
    progs = {}
    for prog in bpftool("prog", "show"):
        name = prog.get("name", "")
        if not name.startswith("hm_"):
            continue
        slot = progs.setdefault(name, {"run_time_ns": 0, "run_cnt": 0})
        slot["run_time_ns"] += int(prog.get("run_time_ns", 0))
        slot["run_cnt"] += int(prog.get("run_cnt", 0))
    cnt = [0] * C_MAX
    copies = sorted(d for d in os.listdir(root) if d.startswith("m"))
    for copy in copies:
        cnt = [a + b for a, b in zip(cnt, counters(f"{root}/{copy}/hm_cnt"))]
    first = probe(f"{root}/m0/hm_probe") if copies else [0] * P_MAX
    return {
        "t_ns": time.monotonic_ns(),
        "rx_packets": rx,
        "cpu": dict(zip(["user", "nice", "system", "idle", "iowait", "irq", "softirq"], cpu)),
        "progs": progs,
        "cnt": dict(zip(C_NAMES, cnt)),
        "probe": dict(zip(P_NAMES, first)),
    }


def attached(dev):
    xdp, tcx = None, []
    for block in bpftool("net", "show", "dev", dev) or []:
        for entry in block.get("xdp", []):
            xdp = {"name": entry.get("name", ""), "mode": entry.get("mode", "")}
        for entry in block.get("tc", []):
            kind = entry.get("kind", "")
            if kind.startswith("tcx") and "ingress" in kind:
                tcx.append(entry.get("name", ""))
    return {"xdp": xdp, "tcx_ingress": tcx}


def tcx_detach(dev, pins):
    libc = ctypes.CDLL(None, use_errno=True)
    nr = SYS_BPF[platform.machine()]
    ifindex = int(open(f"/sys/class/net/{dev}/ifindex", encoding="ascii").read())
    for pin in pins:
        path = ctypes.create_string_buffer(pin.encode())
        attr = (ctypes.c_uint8 * 128)()
        ctypes.memmove(attr, ctypes.byref(ctypes.c_uint64(ctypes.addressof(path))), 8)
        fd = libc.syscall(nr, BPF_OBJ_GET, attr, ctypes.sizeof(attr))
        if fd < 0:
            continue
        attr = (ctypes.c_uint32 * 32)()
        attr[0], attr[1], attr[2] = ifindex, fd, BPF_TCX_INGRESS
        libc.syscall(nr, BPF_PROG_DETACH, attr, ctypes.sizeof(attr))
        os.close(fd)


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "sample":
        print(json.dumps(sample(sys.argv[2], sys.argv[3])))
    elif len(sys.argv) == 3 and sys.argv[1] == "attached":
        print(json.dumps(attached(sys.argv[2])))
    elif len(sys.argv) >= 3 and sys.argv[1] == "tcx-detach":
        tcx_detach(sys.argv[2], sys.argv[3:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
