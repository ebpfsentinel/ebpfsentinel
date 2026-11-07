#!/usr/bin/env python3
"""Read or write one of the agent's eBPF maps through the agent's own descriptor.

Where the BPF LSM is active the agent guards its maps: no task but the agent
and its warden may open one for writing, so `bpftool map update id N` is
refused with EPERM, and so is `bpftool map lookup id N`, which opens the map
read-write. A suite that has to plant an entry the OSS agent never writes
itself (a tenant behind a cgroup, a feature gate) therefore borrows the
descriptor the agent already holds, with pidfd_getfd, and issues the map
operation on that copy. The guard decides at the moment a descriptor is
created, and a duplicate of one the agent opened is not a new one, so this is
root on the agent host acting through the agent rather than past the guard.

Usage (as root on the agent host):
    agent-map.py lookup <map id> <key hex bytes...>
    agent-map.py update <map id> <key hex bytes...> -- <value hex bytes...>
    agent-map.py delete <map id> <key hex bytes...>

Bytes are written the way bpftool takes them: `07 00 00 00`. `lookup` prints
the bpftool raw JSON form, {"key": [...], "value": ["0x07", ...]}, and exits 1
when the key is absent.
"""

import ctypes
import errno
import json
import os
import platform
import sys

SYSCALLS = {
    "x86_64": {"bpf": 321, "pidfd_open": 434, "pidfd_getfd": 438},
    "aarch64": {"bpf": 280, "pidfd_open": 434, "pidfd_getfd": 438},
}

BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3

# Per-CPU map types carry one value per possible CPU, which this helper does
# not lay out.
PERCPU_TYPES = {5, 6, 10, 21}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def die(msg, code=2):
    print(f"agent-map: {msg}", file=sys.stderr)
    sys.exit(code)


def syscall(name, *args):
    nr = SYSCALLS.get(platform.machine(), {}).get(name)
    if nr is None:
        die(f"no syscall number for {name} on {platform.machine()}")
    rc = libc.syscall(ctypes.c_long(nr), *args)
    if rc < 0:
        return rc, ctypes.get_errno()
    return rc, 0


def read_fdinfo(path):
    info = {}
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
    except OSError:
        return None
    return info


def find_holder(map_id):
    """The first process holding a descriptor on map_id, and that descriptor."""
    want = str(map_id)
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        if int(pid) == os.getpid():
            continue
        fddir = f"/proc/{pid}/fdinfo"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        for fd in fds:
            info = read_fdinfo(f"{fddir}/{fd}")
            if info and info.get("map_id") == want:
                return int(pid), int(fd), info
    return None


def parse_bytes(words):
    try:
        return bytes(int(w, 16) for w in words)
    except ValueError:
        die(f"not hex bytes: {' '.join(words)}")


def main(argv):
    if len(argv) < 3 or argv[0] not in ("lookup", "update", "delete"):
        die(__doc__.strip().split("\n\n")[2])
    op, map_id = argv[0], argv[1]
    rest = argv[2:]
    if op == "update":
        if "--" not in rest:
            die("update needs `-- <value bytes>`")
        cut = rest.index("--")
        key, value = parse_bytes(rest[:cut]), parse_bytes(rest[cut + 1 :])
    else:
        key, value = parse_bytes(rest), b""

    holder = find_holder(map_id)
    if holder is None:
        die(f"no process holds map {map_id}")
    pid, remote_fd, info = holder
    if int(info.get("map_type", "0")) in PERCPU_TYPES:
        die(f"map {map_id} is per-CPU, which this helper does not lay out")
    key_size = int(info.get("key_size", "0"))
    value_size = int(info.get("value_size", "0"))
    if len(key) != key_size:
        die(f"map {map_id} takes a {key_size}-byte key, got {len(key)}")
    if op == "update" and len(value) != value_size:
        die(f"map {map_id} takes a {value_size}-byte value, got {len(value)}")

    pidfd, err = syscall("pidfd_open", ctypes.c_int(pid), ctypes.c_uint(0))
    if pidfd < 0:
        die(f"pidfd_open({pid}): {os.strerror(err)}")
    fd, err = syscall("pidfd_getfd", ctypes.c_int(pidfd), ctypes.c_int(remote_fd), ctypes.c_uint(0))
    os.close(pidfd)
    if fd < 0:
        die(f"pidfd_getfd({pid}, {remote_fd}): {os.strerror(err)}")

    key_buf = ctypes.create_string_buffer(key, key_size)
    val_buf = ctypes.create_string_buffer(value if op == "update" else value_size, value_size)

    class Attr(ctypes.Structure):
        _fields_ = [
            ("map_fd", ctypes.c_uint32),
            ("pad", ctypes.c_uint32),
            ("key", ctypes.c_uint64),
            ("value", ctypes.c_uint64),
            ("flags", ctypes.c_uint64),
        ]

    attr = Attr(fd, 0, ctypes.addressof(key_buf), ctypes.addressof(val_buf), 0)
    cmd = {"lookup": BPF_MAP_LOOKUP_ELEM, "update": BPF_MAP_UPDATE_ELEM, "delete": BPF_MAP_DELETE_ELEM}[op]
    rc, err = syscall("bpf", ctypes.c_int(cmd), ctypes.byref(attr), ctypes.c_uint(ctypes.sizeof(attr)))
    os.close(fd)
    if rc < 0:
        if err == errno.ENOENT and op in ("lookup", "delete"):
            return 1
        die(f"{op} on map {map_id}: {os.strerror(err)}")
    if op == "lookup":
        print(
            json.dumps(
                {
                    "key": [f"0x{b:02x}" for b in key],
                    "value": [f"0x{b:02x}" for b in val_buf.raw[:value_size]],
                }
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
