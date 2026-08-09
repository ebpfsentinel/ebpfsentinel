#!/usr/bin/env python3
"""Minimal UDP DNS responder for the DNS datapath tests.

Not a resolver: it never recurses and holds no zone. Every A query is answered
with a fixed number of A records whose addresses are consecutive, so a test can
pick the exact response size and then check that the last address survived the
trip through the kernel ring buffer. A response truncated anywhere on the way
loses the tail addresses, which no amount of retrying hides.

Usage: dns-stub-responder.py <bind-ip> <answer-count> <first-ipv4>
"""

import socket
import struct
import sys


def build_response(query: bytes, count: int, first_ip: str) -> bytes | None:
    if len(query) < 12:
        return None

    # Walk the QNAME label chain to find where the question section ends.
    i = 12
    while i < len(query) and query[i] != 0:
        i += 1 + query[i]
        if i > len(query):
            return None
    question_end = i + 5  # terminating zero byte + QTYPE + QCLASS
    if question_end > len(query):
        return None

    transaction_id = query[:2]
    # QR=1, RD copied as set, RA=1: a plain non-authoritative answer.
    header = transaction_id + struct.pack(">HHHHH", 0x8180, 1, count, 0, 0)
    question = query[12:question_end]

    base = list(int(o) for o in first_ip.split("."))
    body = b""
    for n in range(count):
        octets = base.copy()
        octets[3] = (octets[3] + n) % 256
        # 0xC00C is a compression pointer back to the QNAME at offset 12.
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(octets)

    return header + question + body


def main() -> int:
    bind_ip = sys.argv[1]
    count = int(sys.argv[2])
    first_ip = sys.argv[3]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, 53))

    while True:
        query, peer = sock.recvfrom(4096)
        response = build_response(query, count, first_ip)
        if response is not None:
            sock.sendto(response, peer)

    return 0


if __name__ == "__main__":
    sys.exit(main())
