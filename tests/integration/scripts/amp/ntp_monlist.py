#!/usr/bin/env python3
"""ntp_monlist.py — Flood an agent with reflected NTP amplification responses.

NTP monlist is a textbook amplification vector: a 234-byte response is
generated for a ~30-byte request, multiplied across thousands of stored
client addresses. This script models the victim-facing leg — a flood
sourced *from* the NTP port (123), the amplified responses a reflector
blasts at a spoofed victim. The agent's UDP amplification protection
rate-limits per source/amplifier-port and drops the flood beyond the
configured `max_pps`, emitting a MITRE T1498.002 alert.

Usage:
    sudo ntp_monlist.py --dst <agent_ip> [--spoof-src <reflector_ip>]
                        [--count N] [--rate PPS]
"""

from __future__ import annotations

import argparse
import ipaddress
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


# NTP mode-7 (private) MON_GETLIST_1 — the classic monlist payload.
# Byte 0: 0x17 = version=2, mode=7
# Byte 1: 0x00 = request, more=0, error=0, opcode=0
# Byte 2: 0x03 = MON_GETLIST_1
# Byte 3: 0x2a = padding
# Remainder: zero-fill to 192 bytes (the standard request length).
_MONLIST = b"\x17\x00\x03\x2a" + b"\x00" * 188


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
        / UDP(sport=123, dport=33333)
        / Raw(load=_MONLIST)
    )

    sent = 0
    start = time.monotonic()
    while sent < args.count:
        send(pkt, verbose=False)
        sent += 1
        time.sleep(inter)
    elapsed = time.monotonic() - start
    pps = sent / elapsed if elapsed > 0 else float(sent)
    print(f"ntp_monlist sent={sent} elapsed={elapsed:.2f}s pps={pps:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
