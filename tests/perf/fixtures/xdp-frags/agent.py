#!/usr/bin/env python3
"""agent.py - the agent-side half of perf/10, run as root on the agent VM.

  agent.py snapshot <iface>
      One reading of what perf/10 takes the difference of over a run, as one
      JSON object: the time, /proc/stat's cpu line, the interface's receive
      counters, its MTU and XDP attachment (ip -j -d link), and the run time
      and run count of every XDP program (bpftool -j prog show, meaningful
      only while kernel.bpf_stats_enabled is 1).

  agent.py testrun <prog_name> <frame_len> <linear_len> <runs> <warmup>
      Time the loaded XDP program named <prog_name> on one built frame with
      BPF_PROG_TEST_RUN, <runs> times one run at a time, after <warmup> runs
      that are not kept. The frame is Ethernet, IPv4 and UDP to port 9,
      <frame_len> bytes from the Ethernet header on. <linear_len> 0 hands the
      kernel the frame as a whole, which it lays out in one buffer up to what
      a page holds and spills the rest into fragments. A non-zero
      <linear_len> asks for that many bytes in the first buffer (the xdp_md
      data_end of the context), which is how a frame whose headers straddle
      the first buffer is built on purpose. Prints one JSON object with the
      median, p10, p90, mean and minimum nanoseconds per run, the verdict,
      the frags_pulled growth read off the tested program's own metrics
      array (pulled_in_prog, null where it has no such slot), and the errno
      when the kernel refused the run.

      One run per call on purpose: with repeat above one the kernel runs the
      program again on the buffer the previous run left, and a pull that
      moved the headers into the first buffer would only run the first time.
"""

import ctypes
import json
import os
import platform
import statistics
import struct
import subprocess
import sys
import time

SYS_BPF = {"x86_64": 321, "aarch64": 280}.get(platform.machine())
BPF_PROG_TEST_RUN = 10
BPF_PROG_GET_FD_BY_ID = 13
ATTR_SIZE = 80

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


def bpf(cmd, attr):
    rc = LIBC.syscall(SYS_BPF, cmd, ctypes.byref(attr), ATTR_SIZE)
    if rc < 0:
        return rc, ctypes.get_errno()
    return rc, 0


def run_json(argv):
    return json.loads(subprocess.run(argv, check=True, capture_output=True, text=True).stdout)


def snapshot(iface):
    with open("/proc/stat", encoding="ascii") as f:
        cpu = next(line for line in f if line.startswith("cpu "))
    stats = f"/sys/class/net/{iface}/statistics"
    with open(f"{stats}/rx_packets", encoding="ascii") as f:
        rx_packets = int(f.read())
    with open(f"{stats}/rx_bytes", encoding="ascii") as f:
        rx_bytes = int(f.read())
    link = run_json(["ip", "-j", "-d", "link", "show", "dev", iface])[0]
    progs = [
        {
            "id": p.get("id"),
            "name": p.get("name"),
            "run_time_ns": p.get("run_time_ns"),
            "run_cnt": p.get("run_cnt"),
        }
        for p in run_json(["bpftool", "-j", "prog", "show"])
        if p.get("type") == "xdp"
    ]
    print(
        json.dumps(
            {
                "ns": time.monotonic_ns(),
                "clk_tck": os.sysconf("SC_CLK_TCK"),
                "cpu": cpu.split()[1:],
                "rx_packets": rx_packets,
                "rx_bytes": rx_bytes,
                "mtu": link.get("mtu"),
                "xdp": link.get("xdp"),
                "progs": progs,
            }
        )
    )


def checksum(header):
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(length):
    src = bytes([192, 168, 56, 20])
    dst = bytes([192, 168, 56, 10])
    eth = bytes.fromhex("020000000001" "020000000002") + struct.pack("!H", 0x0800)
    ip_len = length - len(eth)
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0, 0x4000, 64, 17, 0, src, dst))
    struct.pack_into("!H", ip, 10, checksum(bytes(ip)))
    udp = struct.pack("!HHHH", 40000, 9, ip_len - 20, 0)
    payload = bytes(ip_len - 20 - 8)
    return eth + bytes(ip) + udp + payload


def prog_fd(name):
    ids = [p["id"] for p in run_json(["bpftool", "-j", "prog", "show"])
           if p.get("type") == "xdp" and p.get("name") == name]
    if not ids:
        return None, None, ids
    # The program attached to an interface is the one whose maps the agent
    # reads; another loaded copy of the same name (a probe, or a program a
    # stopped agent left pinned) counts into maps nobody publishes.
    attached = {
        x.get("id")
        for dev in run_json(["bpftool", "-j", "net", "show"])
        for x in dev.get("xdp", [])
    }
    chosen = [i for i in ids if i in attached]
    prog_id = max(chosen or ids)
    attr = ctypes.create_string_buffer(ATTR_SIZE)
    struct.pack_into("<I", attr, 0, prog_id)
    fd, err = bpf(BPF_PROG_GET_FD_BY_ID, attr)
    if fd < 0:
        raise OSError(err, f"BPF_PROG_GET_FD_BY_ID {prog_id}")
    return prog_id, fd, ids


# The firewall's metrics array and the slot the pull counts in. The kernel
# keeps the first 15 bytes of a map name.
METRICS_MAP = "FIREWALL_METRICS"[:15]
FRAGS_PULLED_SLOT = 8


def pulled_in_prog(prog_id):
    """frags_pulled summed over CPUs, read from the tested program's own
    metrics array, or None where it has no such array. Read off the map the
    program writes, so it does not wait on the agent's poll nor depend on
    which map the agent publishes."""
    prog = run_json(["bpftool", "-j", "prog", "show", "id", str(prog_id)])
    for map_id in prog.get("map_ids", []):
        m = run_json(["bpftool", "-j", "map", "show", "id", str(map_id)])
        if m.get("name") != METRICS_MAP:
            continue
        if m.get("max_entries", 0) <= FRAGS_PULLED_SLOT:
            return None
        key = [str(b) for b in struct.pack("<I", FRAGS_PULLED_SLOT)]
        got = run_json(["bpftool", "-j", "map", "lookup", "id", str(map_id), "key", *key])
        return sum(v.get("value", 0) if isinstance(v.get("value"), int)
                   else int.from_bytes(bytes(int(b, 16) for b in v["value"]), "little")
                   for v in got.get("values", []))
    return None


def once(fd, data, ctx):
    attr = ctypes.create_string_buffer(ATTR_SIZE)
    struct.pack_into("<IIII", attr, 0, fd, 0, len(data), 0)
    struct.pack_into("<Q", attr, 16, ctypes.addressof(data))
    struct.pack_into("<I", attr, 32, 1)
    struct.pack_into("<I", attr, 40, len(ctx))
    struct.pack_into("<Q", attr, 48, ctypes.addressof(ctx))
    rc, err = bpf(BPF_PROG_TEST_RUN, attr)
    if rc < 0:
        return None, None, err
    retval, = struct.unpack_from("<I", attr, 4)
    duration, = struct.unpack_from("<I", attr, 36)
    return retval, duration, 0


def testrun(name, frame_len, linear_len, runs, warmup):
    out = {"prog": name, "frame_len": frame_len, "linear_len": linear_len,
           "runs": runs, "warmup": warmup, "runs_total": 0}
    if SYS_BPF is None:
        out.update(ok=False, error=f"no bpf syscall number for {platform.machine()}")
        print(json.dumps(out))
        return
    prog_id, fd, candidates = prog_fd(name)
    out["candidates"] = candidates
    if fd is None:
        out.update(ok=False, error=f"no loaded XDP program named {name}")
        print(json.dumps(out))
        return
    out["prog_id"] = prog_id
    pulled_before = pulled_in_prog(prog_id)
    raw = frame(frame_len)
    data = ctypes.create_string_buffer(raw, len(raw))
    # struct xdp_md: data, data_end, data_meta, ingress_ifindex,
    # rx_queue_index, egress_ifindex. No metadata, no device.
    ctx_bytes = struct.pack("<6I", 0, linear_len or frame_len, 0, 0, 0, 0)
    ctx = ctypes.create_string_buffer(ctx_bytes, len(ctx_bytes))
    durations = []
    retvals = set()
    for i in range(warmup + runs):
        retval, duration, err = once(fd, data, ctx)
        if err:
            out.update(ok=False, errno=err, error=os.strerror(err))
            print(json.dumps(out))
            os.close(fd)
            return
        out["runs_total"] += 1
        retvals.add(retval)
        if i >= warmup:
            durations.append(duration)
    os.close(fd)
    pulled_after = pulled_in_prog(prog_id)
    out["pulled_in_prog"] = (None if pulled_before is None or pulled_after is None
                             else pulled_after - pulled_before)
    durations.sort()
    out.update(
        ok=True,
        retvals=sorted(retvals),
        ns={
            "median": durations[(len(durations) - 1) // 2],
            "p10": durations[len(durations) // 10],
            "p90": durations[(len(durations) * 9) // 10],
            "mean": statistics.fmean(durations),
            "min": durations[0],
        },
    )
    print(json.dumps(out))


def main(argv):
    if len(argv) == 3 and argv[1] == "snapshot":
        snapshot(argv[2])
    elif len(argv) == 7 and argv[1] == "testrun":
        testrun(argv[2], int(argv[3]), int(argv[4]), int(argv[5]), int(argv[6]))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
