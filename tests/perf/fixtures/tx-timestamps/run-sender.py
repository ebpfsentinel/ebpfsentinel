#!/usr/bin/env python3
"""run-sender.py - the agent-side half of perf/12, run as root on the agent VM.

  run-sender.py <server> <port> <seconds> <write_len> <nodelay 0|1> [cpu]

Runs one iperf3 TCP sender to <server>:<port> for <seconds>, writing
<write_len> bytes per write (TCP_NODELAY when <nodelay> is 1, so a small
write leaves as its own segment instead of being coalesced), pinned to <cpu>
with taskset when one is given. Around it, one reading of what perf/12 takes
the difference of: /proc/stat's cpu line and the run time and run count of
every loaded program (bpftool -j prog show, meaningful only while
kernel.bpf_stats_enabled is 1). The sender's own CPU time comes from the
rusage wait4 returns for it, which counts the time its sendmsg calls spent
in the kernel, the sock_ops callbacks included.

Prints one JSON object: the window in nanoseconds, the two /proc/stat cpu
lines, the two program lists, the sender's user and system nanoseconds, the
write length and iperf3's own JSON report (or its error).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def cpu_line():
    with open("/proc/stat", encoding="ascii") as f:
        return next(line for line in f if line.startswith("cpu ")).split()[1:]


def programs():
    out = subprocess.run(["bpftool", "-j", "prog", "show"], check=True,
                         capture_output=True, text=True).stdout
    return [
        {
            "id": p.get("id"),
            "name": p.get("name"),
            "type": p.get("type"),
            "run_time_ns": p.get("run_time_ns"),
            "run_cnt": p.get("run_cnt"),
        }
        for p in json.loads(out)
    ]


def main(argv):
    if len(argv) not in (6, 7):
        print(__doc__, file=sys.stderr)
        return 2
    server, port, seconds, write_len, nodelay = argv[1:6]
    cpu = argv[6] if len(argv) == 7 else ""
    cmd = ["iperf3", "-c", server, "-p", port, "-t", seconds, "-l", write_len, "-J"]
    if nodelay == "1":
        cmd.append("-N")
    if cpu and shutil.which("taskset"):
        cmd = ["taskset", "-c", cpu] + cmd

    progs_before = programs()
    cpu_before = cpu_line()
    t0 = time.monotonic_ns()
    # stderr to a file, so a full pipe cannot stall the sender while stdout
    # is read; wait4 rather than communicate, for the child's rusage.
    errfile = tempfile.TemporaryFile()
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errfile)
    stdout = child.stdout.read()
    _, status, usage = os.wait4(child.pid, 0)
    t1 = time.monotonic_ns()
    cpu_after = cpu_line()
    progs_after = programs()
    child.returncode = os.waitstatus_to_exitcode(status)

    errfile.seek(0)
    stderr = errfile.read()
    try:
        report = json.loads(stdout)
    except ValueError:
        report = {"error": (stderr or stdout).decode(errors="replace").strip()[-400:]}

    print(json.dumps({
        "window_ns": t1 - t0,
        "clk_tck": os.sysconf("SC_CLK_TCK"),
        "cpu_before": cpu_before,
        "cpu_after": cpu_after,
        "progs_before": progs_before,
        "progs_after": progs_after,
        "sender_user_ns": int(usage.ru_utime * 1e9),
        "sender_sys_ns": int(usage.ru_stime * 1e9),
        "exit": child.returncode,
        "write_len": int(write_len),
        "pinned_cpu": cpu or None,
        "iperf3": report,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
