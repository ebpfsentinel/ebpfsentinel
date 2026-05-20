#!/usr/bin/env python3
"""ssdp_search.py — Spoofed-source SSDP M-SEARCH amplification probes.

SSDP M-SEARCH (UDP/1900) yields a multi-line UPnP response from any
discovered device — a ~30x amplification vector. Suite 44 uses a
spoofed source IP so the agent's scrub layer should fail RPF and drop
before any device on the lan can answer.

Usage:
    sudo ssdp_search.py --dst <agent_ip> [--spoof-src <victim_ip>]
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


_MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 1\r\n"
    b"ST: ssdp:all\r\n\r\n"
)


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
        / UDP(sport=33333, dport=1900)
        / Raw(load=_MSEARCH)
    )

    sent = 0
    start = time.monotonic()
    while sent < args.count:
        send(pkt, verbose=False)
        sent += 1
        time.sleep(inter)
    elapsed = time.monotonic() - start
    pps = sent / elapsed if elapsed > 0 else float(sent)
    print(f"ssdp_search sent={sent} elapsed={elapsed:.2f}s pps={pps:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
