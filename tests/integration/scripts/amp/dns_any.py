#!/usr/bin/env python3
"""dns_any.py — Flood an agent with reflected DNS amplification responses.

Used by suite 44 (scapy amplification). The attacker VM models the
victim-facing leg of a DNS reflection attack: a flood of UDP datagrams
sourced *from* the DNS port (53) — the amplified responses a reflector
blasts at a spoofed victim. The source address is an arbitrary RFC1918
reflector. The agent's UDP amplification protection rate-limits traffic
per source/amplifier-port and drops the flood once it exceeds the
configured `max_pps`, emitting a MITRE T1498.002 (Reflection
Amplification) alert before any response leaves.

Usage:
    sudo dns_any.py --dst <agent_ip> [--spoof-src <reflector_ip>]
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
        help="apparent reflector source IP (must be RFC1918)",
    )
    p.add_argument("--count", type=int, default=500, help="packet count")
    p.add_argument("--rate", type=int, default=200, help="target pps")
    p.add_argument(
        "--qname",
        default="example.com",
        help="DNS qname used in the ANY query",
    )
    p.add_argument(
        "--query",
        action="store_true",
        help="send the reflector-direction query (dst=53) instead of the "
        "default victim-direction response flood (src=53)",
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
    if args.query:
        # Reflector-protection direction: a spoofed-source ANY query *to*
        # the DNS port. The firewall deny / scrub layer blocks the query
        # before any daemon can answer — used by the egress-zero guard to
        # confirm the agent never emits an amplified response.
        layer4 = UDP(sport=33333, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=args.qname, qtype="ANY")
        )
    else:
        # Victim-protection direction (default): the reflected ANY response
        # flood arriving *from* the DNS port. Exercises the UDP
        # amplification rate-drop and the MITRE T1498.002 alert.
        layer4 = UDP(sport=53, dport=33333) / DNS(
            qr=1, rd=1, qd=DNSQR(qname=args.qname, qtype="ANY")
        )
    pkt = IP(src=args.spoof_src, dst=args.dst) / layer4

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
