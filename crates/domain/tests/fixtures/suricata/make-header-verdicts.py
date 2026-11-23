#!/usr/bin/env python3
"""Run the rules of header.rules over crafted packets through a real Suricata.

Each rule gets a sid from 4000 in file order. Each packet below is built
byte for byte, written to one capture in order, and Suricata reads it with
every rule loaded; the alerts it writes, attributed to a packet by its
`pcap_cnt`, decide which rules each packet matched. A rule Suricata refuses
to load is recorded as refused. Suricata keeps 15 alerts per packet by
default; the run raises that so every rule a packet matches is written.

Writes header-verdicts.txt beside this script: each rule as written, then
one line per packet with its IP bytes and the sids that alerted on it, so the
test needs neither this script nor docker. Needs docker.
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = os.environ.get("SURICATA_IMAGE", "jasonish/suricata:8.0.8")
FIRST_SID = 4000

A = bytes([10, 0, 0, 1])
B = bytes([10, 0, 0, 2])
V6A = bytes.fromhex("20010db8000000000000000000000001")
V6B = bytes.fromhex("20010db8000000000000000000000099")

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(proto, body, src=A, dst=B, ttl=64, tos=0, ident=1, frag=0, options=b""):
    """An IPv4 packet; `frag` holds the flag bits and the offset as on the wire."""
    if len(options) % 4:
        sys.exit("IPv4 options must fill whole words")
    words = 5 + len(options) // 4
    total = words * 4 + len(body)
    head = struct.pack("!BBHHHBBH4s4s", 0x40 | words, tos, total, ident, frag, ttl, proto, 0, src, dst)
    head += options
    head = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    return head + body


def ipv6(next_header, body, src=V6A, dst=V6B, hops=64):
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), next_header, hops, src, dst) + body


def pseudo(src, dst, proto, length):
    if len(src) == 4:
        return src + dst + struct.pack("!BBH", 0, proto, length)
    return src + dst + struct.pack("!IxxxB", length, proto)


def tcp(sport, dport, flags, payload=b"", seq=1000, ack=0, window=65535, options=b"", src=A, dst=B):
    words = (20 + len(options)) // 4
    head = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, words << 4, flags, window, 0, 0) + options
    total = checksum(pseudo(src, dst, 6, len(head) + len(payload)) + head + payload)
    return head[:16] + struct.pack("!H", total) + head[18:] + payload


def udp(sport, dport, payload, src=A, dst=B):
    head = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    total = checksum(pseudo(src, dst, 17, len(head) + len(payload)) + head + payload) or 0xFFFF
    return head[:6] + struct.pack("!H", total) + payload


def icmp(kind, code, rest, payload=b""):
    body = struct.pack("!BBH", kind, code, 0) + rest + payload
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def icmpv6(kind, code, rest, payload=b"", src=V6A, dst=V6B):
    body = struct.pack("!BBH", kind, code, 0) + rest + payload
    total = checksum(pseudo(src, dst, 58, len(body)) + body)
    return body[:2] + struct.pack("!H", total) + body[4:]


MSS_WS = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 7])
DF, MF, RESERVED = 0x4000, 0x2000, 0x8000


def packets():
    """(name, IP bytes), in capture order; every TCP or UDP packet uses its
    own source port so no two share a flow."""
    out = []
    port = iter(range(40000, 41000))

    def v4tcp(name, dport, flags, payload=b"", **kw):
        src, dst = kw.pop("src", A), kw.pop("dst", B)
        ip_kw = {k: kw.pop(k) for k in ("ttl", "tos", "ident", "frag") if k in kw}
        sport = kw.pop("sport", None) or next(port)
        body = tcp(sport, dport, flags, payload, src=src, dst=dst, **kw)
        out.append((name, ipv4(6, body, src=src, dst=dst, **ip_kw)))

    def v4udp(name, dport, payload, **kw):
        src, dst = kw.pop("src", A), kw.pop("dst", B)
        out.append((name, ipv4(17, udp(next(port), dport, payload, src, dst), src=src, dst=dst, **kw)))

    v4tcp("syn with mss and wscale", 80, SYN, seq=12345, window=1024, options=MSS_WS, frag=DF)
    v4tcp("syn ack with ecn and cwr", 8080, SYN | ACK | ECE | CWR, ack=777)
    v4tcp("syn with ecn", 8443, SYN | ECE)
    v4tcp("ack push with a request", 80, ACK | PSH, b"GET / HTTP/1.0\r\n\r\n", ack=5)
    v4tcp("bare ack", 8443, ACK, ack=5)
    v4tcp("from 5555 to 8080", 8080, ACK, sport=5555, ack=5)
    v4tcp("fin push urg", 9000, FIN | PSH | URG)
    v4tcp("no flag", 9000, 0)
    v4tcp("reset", 9000, RST)
    v4tcp("syn with a small mss", 8050, SYN, options=bytes([2, 4, 0x02, 0x18]))
    v4tcp("big payload", 8050, ACK | PSH, b"A" * 1450, ack=5)
    v4tcp("from 8443 in the listed network", 40000, ACK, sport=8443, src=bytes([10, 9, 1, 1]), ack=5)
    v4tcp("from 8443 elsewhere", 40001, ACK, sport=8443, src=bytes([10, 8, 1, 1]), ack=5)
    v4tcp("same address", 80, SYN, src=bytes([10, 0, 0, 5]), dst=bytes([10, 0, 0, 5]))
    v4tcp("ttl 3, tos 16, id 4242", 80, SYN, ttl=3, tos=16, ident=4242)
    v4udp("dns query", 53, b"query 12345")
    v4udp("udp to a high port", 5000, b"hello")
    v4udp("udp with a 9 byte payload", 5000, b"123456789")
    v4udp("udp with a 20 byte payload", 5000, b"x" * 20)
    out.append(("echo request", ipv4(1, icmp(8, 0, struct.pack("!HH", 99, 7), b"ping"), ttl=255)))
    out.append(("echo reply", ipv4(1, icmp(0, 0, struct.pack("!HH", 98, 8), b"pong"))))
    inner = ipv4(17, udp(53, 33000, b"")[:8], src=B, dst=A)
    out.append(("port unreachable", ipv4(1, icmp(3, 3, b"\0\0\0\0", inner), src=A, dst=B)))
    out.append(("icmp type 200", ipv4(1, icmp(200, 0, b"\0\0\0\0"))))
    out.append(("gre", ipv4(47, b"\0\0\x08\x00" + b"\0" * 8)))

    options = {
        "nop": bytes([1, 1, 1, 1]),
        "eol": bytes([0, 0, 0, 0]),
        "rr": bytes([7, 7, 4, 0, 0, 0, 0, 0]),
        "ts": bytes([68, 8, 5, 0, 0, 0, 0, 1]),
        "sec": bytes([130, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        "lsrr": bytes([131, 7, 4, 10, 0, 0, 9, 0]),
        "ssrr": bytes([137, 7, 4, 10, 0, 0, 9, 0]),
        "satid": bytes([136, 4, 0, 1]),
        "esec": bytes([133, 4, 0, 0]),
        "lsrr cut short": bytes([131, 3, 4, 0]),
        "nop then rr": bytes([1, 7, 7, 4, 0, 0, 0, 0]),
        "rr with an address": bytes([7, 7, 4, 10, 0, 0, 9, 0]),
        "rr with a later pointer": bytes([7, 7, 8, 10, 0, 0, 9, 0]),
        "lsrr of zeros": bytes([131, 7, 4, 0, 0, 0, 0, 0]),
        "ts then padding": bytes([68, 4, 5, 0, 0, 0, 0, 0]),
        "satid then padding": bytes([136, 4, 0, 1, 0, 0, 0, 0]),
        "ts of twelve": bytes([68, 12, 5, 0, 0, 0, 0, 1, 0, 0, 0, 2]),
        "ts of six": bytes([68, 6, 5, 0, 0, 0, 0, 0]),
        "malformed ts pointing at four": bytes([68, 8, 4, 0, 0, 0, 0, 1]),
        "malformed ts pointing past": bytes([68, 8, 13, 0, 0, 0, 0, 1]),
        "ts full": bytes([68, 8, 9, 0, 0, 0, 0, 1]),
        "rr of three": bytes([7, 3, 4, 0]),
        "rr of six": bytes([7, 6, 4, 0, 0, 0, 0, 0]),
        "rr pointing at three": bytes([7, 7, 3, 0, 0, 0, 0, 0]),
        "rr pointing past": bytes([7, 7, 12, 0, 0, 0, 0, 0]),
        "rr pointing odd": bytes([7, 7, 5, 0, 0, 0, 0, 0]),
        "rr twice": bytes([7, 3, 4, 7, 3, 4, 0, 0]),
        "sec of four": bytes([130, 4, 0, 0]),
        "satid of three": bytes([136, 3, 0, 0]),
        "esec of three": bytes([133, 3, 0, 0]),
        "malformed unknown option": bytes([25, 4, 0, 0]),
        "malformed option of one": bytes([7, 1, 0, 0]),
        "malformed option overflowing": bytes([131, 9, 4, 0]),
    }
    for name, value in options.items():
        v4udp(f"option {name}", 5000, b"opt", options=value)

    v4udp("first fragment", 5000, b"f" * 16, ident=7001, frag=MF)
    v4udp("df", 5000, b"d", ident=7002, frag=DF)
    v4udp("reserved bit", 5000, b"r", ident=7003, frag=RESERVED)
    out.append(("fragment at offset 100", ipv4(17, b"z" * 16, ident=7004, frag=100)))
    out.append(("fragment with more at offset 100", ipv4(17, b"z" * 16, ident=7005, frag=MF | 100)))

    out.append(("ipv6 syn", ipv6(6, tcp(next(port), 80, SYN, src=V6A, dst=V6B, options=MSS_WS))))
    out.append(("ipv6 udp", ipv6(17, udp(next(port), 53, b"query 6", V6A, V6B))))
    out.append(("ipv6 echo request", ipv6(58, icmpv6(128, 0, struct.pack("!HH", 99, 7), b"ping"))))
    first = struct.pack("!BBHI", 17, 0, 1, 7101)
    out.append(("ipv6 first fragment", ipv6(44, first + udp(next(port), 53, b"f" * 16, V6A, V6B))))
    later = struct.pack("!BBHI", 17, 0, 100 << 3, 7102)
    out.append(("ipv6 later fragment", ipv6(44, later + b"z" * 16)))
    out.append(("ipv6 too big", ipv6(58, icmpv6(2, 0, struct.pack("!I", 1280), b"\0" * 40))))
    return out


def frame(ip):
    kind = b"\x86\xdd" if ip[0] >> 4 == 6 else b"\x08\x00"
    return b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + kind + ip


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, data in enumerate(frames):
            f.write(struct.pack("<IIII", 1_700_000_000 + n, 0, len(data), len(data)))
            f.write(data)


def read_rules(path):
    rules = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            rules.append(line)
    return rules


def main():
    rules = read_rules(os.path.join(HERE, "header.rules"))
    crafted = packets()
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        loaded = [rule[:-1] + f" sid:{FIRST_SID + n};)" for n, rule in enumerate(rules)]
        with open(os.path.join(work, "header.rules"), "w", encoding="utf-8") as f:
            f.write("\n".join(loaded) + "\n")
        write_pcap(os.path.join(work, "header.pcap"), [frame(ip) for _, ip in crafted])
        os.mkdir(os.path.join(work, "out"))
        os.chmod(os.path.join(work, "out"), 0o777)
        run = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "--entrypoint", "suricata", IMAGE,
             "-r", "/w/header.pcap", "-S", "/w/header.rules", "-l", "/w/out", "-k", "none",
             "--runmode", "single", "--set", "packet-alert-max=255"],
            capture_output=True, text=True, check=False,
        )
        log = run.stdout + run.stderr
        if os.environ.get("SHOW_LOG"):
            print(log)
        refused = {int(m.group(1)) for m in re.finditer(r"at line (\d+)$", log, re.M)}
        eve = os.path.join(work, "out", "eve.json")
        if not os.path.exists(eve):
            sys.exit(f"suricata wrote no eve.json:\n{log}")
        alerted = {}
        for line in open(eve, encoding="utf-8"):
            event = json.loads(line)
            if event.get("event_type") == "alert":
                packet = event["pcap_cnt"] - 1
                alerted.setdefault(packet, set()).add(event["alert"]["signature_id"])
        version = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "suricata", IMAGE, "-V"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    lines = [f"# {version}, run by make-header-verdicts.py; do not edit by hand."]
    lines.append("# 'rule SID RULE', or 'refused SID RULE' when Suricata does not load it,")
    lines.append("# then 'packet N HEX SIDS': the IP bytes of each packet and the sids")
    lines.append("# that alerted on it, '-' for none. # NAME before each packet says what it is.")
    for n, rule in enumerate(rules):
        word = "refused" if n + 1 in refused else "rule"
        lines.append(f"{word} {FIRST_SID + n} {rule}")
    for n, (name, ip) in enumerate(crafted):
        sids = ",".join(str(s) for s in sorted(alerted.get(n, ()))) or "-"
        lines.append(f"# {name}")
        lines.append(f"packet {n} {ip.hex()} {sids}")
    with open(os.path.join(HERE, "header-verdicts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
