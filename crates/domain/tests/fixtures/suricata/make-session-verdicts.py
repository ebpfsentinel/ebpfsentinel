#!/usr/bin/env python3
"""Run the session rules below over crafted conversations through a real Suricata.

Each conversation is a list of packets between a client and a server, sent in
order with their own timestamps: a TCP connection with its handshake and its
close, one without a handshake, one refused, UDP and ICMP exchanges. Every
rule is written on `ip any any -> any any`, so it is tried on every packet,
and asks for one thing a flow knows: whether it is established, which side
sent the packet, how many packets and bytes it has seen, how old it is.

Writes session-verdicts.txt beside this script: each rule, marked refused
when Suricata does not load it, then one line per packet with its time in
nanoseconds, its IP bytes and the sids that alerted on it, so the test needs
neither this script nor docker. Needs docker.
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = os.environ.get("SURICATA_IMAGE", "jasonish/suricata:8.0.8")
FIRST_SID = 5000
EPOCH = 1_700_000_000

spec = util.spec_from_file_location("header", os.path.join(HERE, "make-header-verdicts.py"))
header = util.module_from_spec(spec)
spec.loader.exec_module(header)

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 0x10

RULES = [
    "flow:established;",
    "flow:not_established;",
    "flow:to_server;",
    "flow:to_client;",
    "flow:established,to_server;",
    "flow:established,to_client;",
    "flow:not_established,to_server;",
    "flow:stateless;",
    "flow.pkts:toserver,>1;",
    "flow.pkts:toclient,1;",
    "flow.pkts:either,>=4;",
    "flow.bytes:toserver,>10;",
    "flow.bytes:toclient,>0;",
    "flow.bytes:either,<41;",
    "flow.age:0;",
    "flow.age:>=2;",
]


def tcp_conversation(packets, n, script):
    """`script` holds (seconds, side, flags, payload); sequence and
    acknowledgement numbers follow what each side has sent."""
    client, server = bytes([10, 3, 0, n]), bytes([10, 4, 0, n])
    cport, sport = 41000 + n, 22000 + n
    seq = {">": 1000, "<": 5000}
    for at, side, flags, payload in script:
        other = "<" if side == ">" else ">"
        src, dst, a, b = (client, server, cport, sport) if side == ">" else (server, client, sport, cport)
        ack = seq[other] if flags & ACK else 0
        body = header.tcp(a, b, flags, payload, seq=seq[side], ack=ack, src=src, dst=dst)
        seq[side] += len(payload) + (1 if flags & (SYN | FIN) else 0)
        packets.append((n, at, header.ipv4(6, body, src=src, dst=dst)))


def udp_conversation(packets, n, script):
    client, server = bytes([10, 5, 0, n]), bytes([10, 6, 0, n])
    cport, sport = 42000 + n, 23000 + n
    for at, side, payload in script:
        src, dst, a, b = (client, server, cport, sport) if side == ">" else (server, client, sport, cport)
        packets.append((n, at, header.ipv4(17, header.udp(a, b, payload, src, dst), src=src, dst=dst)))


def icmp_conversation(packets, n, script):
    client, server = bytes([10, 7, 0, n]), bytes([10, 8, 0, n])
    for at, side, kind, ident, payload in script:
        src, dst = (client, server) if side == ">" else (server, client)
        body = header.icmp(kind, 0, struct.pack("!HH", ident, 1), payload)
        packets.append((n, at, header.ipv4(1, body, src=src, dst=dst)))


def conversations():
    out = []
    tcp_conversation(out, 1, [
        (0.0, ">", SYN, b""),
        (0.1, "<", SYN | ACK, b""),
        (0.2, ">", ACK, b""),
        (0.3, ">", PSH | ACK, b"GET / HTTP/1.0\r\n\r\n"),
        (0.4, "<", PSH | ACK, b"HTTP/1.0 200 OK\r\n\r\n"),
        (2.5, ">", PSH | ACK, b"more"),
        (2.6, ">", FIN | ACK, b""),
        (2.7, "<", FIN | ACK, b""),
        (2.8, ">", ACK, b""),
    ])
    tcp_conversation(out, 2, [
        (0.0, ">", PSH | ACK, b"midstream one"),
        (0.1, "<", PSH | ACK, b"midstream two"),
        (0.2, ">", PSH | ACK, b"midstream three"),
    ])
    tcp_conversation(out, 3, [
        (0.0, ">", SYN, b""),
        (0.1, "<", RST | ACK, b""),
    ])
    tcp_conversation(out, 4, [
        (0.0, ">", SYN, b""),
        (0.1, "<", SYN | ACK, b""),
        (0.2, ">", PSH | ACK, b"data with the last ack"),
        (0.3, "<", ACK, b""),
    ])
    tcp_conversation(out, 5, [
        (0.0, ">", SYN, b""),
        (0.1, "<", SYN | ACK, b""),
        (0.2, ">", ACK, b""),
        (0.3, "<", RST, b""),
        (0.4, ">", PSH | ACK, b"after the reset"),
    ])
    udp_conversation(out, 6, [
        (0.0, ">", b"question"),
        (0.1, ">", b"again"),
        (0.2, "<", b"answer"),
        (3.0, ">", b"later"),
    ])
    udp_conversation(out, 7, [
        (0.0, ">", b"one way"),
        (0.1, ">", b"still one way"),
    ])
    icmp_conversation(out, 8, [
        (0.0, ">", 8, 77, b"ping"),
        (0.1, "<", 0, 77, b"ping"),
        (1.0, ">", 8, 77, b"ping"),
        (1.1, ">", 8, 78, b"other id"),
    ])
    udp_conversation(out, 9, [
        (0.9, ">", b"just before a second"),
        (1.1, ">", b"just after it"),
    ])
    return out


def main():
    rules = [f"alert ip any any -> any any (msg:\"session {FIRST_SID + n}\"; {r})" for n, r in enumerate(RULES)]
    packets = conversations()
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        loaded = [rule[:-1] + f" sid:{FIRST_SID + n};)" for n, rule in enumerate(rules)]
        with open(os.path.join(work, "session.rules"), "w", encoding="utf-8") as f:
            f.write("\n".join(loaded) + "\n")
        times = []
        with open(os.path.join(work, "session.pcap"), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for n, at, ip in packets:
                ns = (n * 10_000 * 1000 + round(at * 1000)) * 1_000_000
                times.append(ns)
                secs, rest = divmod(ns, 1_000_000_000)
                data = header.frame(ip)
                f.write(struct.pack("<IIII", EPOCH + secs, rest // 1000, len(data), len(data)))
                f.write(data)
        os.mkdir(os.path.join(work, "out"))
        os.chmod(os.path.join(work, "out"), 0o777)
        run = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "--entrypoint", "suricata", IMAGE,
             "-r", "/w/session.pcap", "-S", "/w/session.rules", "-l", "/w/out", "-k", "none",
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
                alerted.setdefault(event["pcap_cnt"] - 1, set()).add(event["alert"]["signature_id"])
        version = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "suricata", IMAGE, "-V"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    lines = [f"# {version}, run by make-session-verdicts.py; do not edit by hand."]
    lines.append("# 'rule SID RULE', or 'refused SID RULE' when Suricata does not load it,")
    lines.append("# then 'packet NS HEX SIDS': the packet's time in nanoseconds, its IP")
    lines.append("# bytes and the sids that alerted on it, '-' for none.")
    for n, rule in enumerate(rules):
        word = "refused" if n + 1 in refused else "rule"
        lines.append(f"{word} {FIRST_SID + n} {rule}")
    for n, ((_, _, ip), ns) in enumerate(zip(packets, times)):
        sids = ",".join(str(s) for s in sorted(alerted.get(n, ()))) or "-"
        lines.append(f"packet {ns} {ip.hex()} {sids}")
    with open(os.path.join(HERE, "session-verdicts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
