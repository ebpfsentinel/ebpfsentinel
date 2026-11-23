#!/usr/bin/env python3
"""Run the stream rules below over crafted TCP connections through a real Suricata.

Each connection opens with its handshake and carries data whose segments are
split, reordered, sent twice, overlapped with other bytes or left with a hole,
so a rule's pattern is whole in the byte stream and in no single segment, or
in one segment and not in the stream. The rules match a pattern on the stream
or on the packet alone, and the size of each side's stream.

Writes stream-verdicts.txt beside this script: each rule, marked refused when
Suricata does not load it, then one line per packet with its time in
nanoseconds, its IP bytes and the sids that alerted on it, a sid repeated as
often as it alerted, so the test needs neither this script nor docker. Needs
docker.
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
FIRST_SID = 6000
EPOCH = 1_700_000_000

spec = util.spec_from_file_location("header", os.path.join(HERE, "make-header-verdicts.py"))
header = util.module_from_spec(spec)
spec.loader.exec_module(header)

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 0x10
DATA = PSH | ACK

RULES = [
    'content:"ABCDEF"; flow:established,to_server;',
    'content:"ABCDEF"; flow:established,to_server,only_stream;',
    'content:"ABCDEF"; flow:established,to_server,no_stream;',
    'content:"WXYZ"; flow:established,to_client;',
    'content:"ORIG"; flow:to_server;',
    'content:"NEWD"; flow:to_server;',
    'content:"HELLO"; depth:5; flow:to_server;',
    "stream_size:client,>,20;",
    "stream_size:server,>=,4;",
    "stream_size:both,>,12;",
    "stream_size:either,>,12;",
    "stream_size:client,=,11;",
    'content:"ABCDEF"; depth:10; flow:to_server;',
    'content:"ABCDEF"; offset:2; flow:to_server;',
    'content:"ABCDEF";',
    'content:"HELLO"; startswith; flow:to_server;',
    'content:"ABC"; content:"DEF"; distance:0; flow:to_server;',
    'content:"ABCDEF"; dsize:>0;',
    'content:"MARK"; flow:to_server;',
    'content:"HELLO"; depth:5; flow:established,to_server;',
    'pcre:"/^HELLO/"; flow:to_server;',
    'pcre:"/ABCDEF/"; flow:to_server;',
    'byte_test:1,=,0x48,0; flow:to_server;',
    'content:"ABCDEF"; isdataat:2,relative; flow:to_server;',
    'content:"ABC"; offset:0; content:"DEF"; distance:0; flow:to_server;',
    'content:"SPLITX"; flow:to_server;',
    'flags:PA; content:"ABCDEF"; flow:to_server;',
    'flags:A+; content:"ABCDEF"; flow:to_server;',
    'ttl:64; content:"ABCDEF"; flow:to_server;',
    'stream_size:client,>,5; content:"ABCDEF"; flow:to_server;',
    'flow.pkts:toserver,>1; content:"ABCDEF"; flow:to_server;',
    'content:"ABCDEF"; tcp.hdr; content:"|50 18|"; offset:12; depth:2;',
    'flowbits:isnotset,nothere; content:"ABCDEF"; flow:to_server;',
    'flowint:nothere,notset; content:"ABCDEF"; flow:to_server;',
    'flow.age:<100; content:"ABCDEF"; flow:to_server;',
    'flow.bytes:toserver,>0; content:"ABCDEF"; flow:to_server;',
    'content:"ABCDEF"; flowbits:set,seen; flow:to_server;',
    ("tcp-stream", 'content:"ABCDEF"; flow:to_server;'),
    ("tcp-stream", 'content:"HELLO"; depth:5; flow:to_server;'),
    ("tcp-stream", 'ttl:64; content:"ABCDEF"; flow:to_server;'),
    ("tcp-stream", "stream_size:client,>,20;"),
]


def rule_text(n, entry):
    proto, options = entry if isinstance(entry, tuple) else ("tcp", entry)
    return f"alert {proto} any any -> any any (msg:\"stream {FIRST_SID + n}\"; {options})"



def connection(packets, n, script):
    """`script` holds (seconds, side, flags, payload, offset): `offset` is
    where the payload sits in its side's stream, None for right after what
    that side sent last. Each packet acknowledges everything the other side
    has sent so far."""
    client, server = bytes([10, 9, 0, n]), bytes([10, 10, 0, n])
    cport, sport = 43000 + n, 8000 + n
    isn = {">": 1000, "<": 5000}
    sent = {">": 0, "<": 0}
    syn = {">": 0, "<": 0}
    for at, side, flags, payload, offset in script:
        other = "<" if side == ">" else ">"
        src, dst, a, b = (client, server, cport, sport) if side == ">" else (server, client, sport, cport)
        if flags & SYN:
            seq = isn[side]
            syn[side] = 1
        else:
            start = sent[side] if offset is None else offset
            seq = isn[side] + syn[side] + start
            sent[side] = max(sent[side], start + len(payload))
        if flags & FIN:
            sent[side] += 1
        ack = isn[other] + syn[other] + sent[other] if flags & ACK else 0
        body = header.tcp(a, b, flags, payload, seq=seq, ack=ack, src=src, dst=dst)
        packets.append((n, at, header.ipv4(6, body, src=src, dst=dst)))


def opened(script):
    return [
        (0.0, ">", SYN, b"", None),
        (0.01, "<", SYN | ACK, b"", None),
        (0.02, ">", ACK, b"", None),
    ] + script


def closed(at):
    return [
        (at, ">", FIN | ACK, b"", None),
        (at + 0.01, "<", FIN | ACK, b"", None),
        (at + 0.02, ">", ACK, b"", None),
    ]


def connections():
    out = []
    # The pattern whole in one segment, an answer from the server.
    connection(out, 1, opened([
        (0.1, ">", DATA, b"xxABCDEFxx", None),
        (0.11, "<", ACK, b"", None),
        (0.2, "<", DATA, b"WXYZ", None),
        (0.21, ">", ACK, b"", None),
    ] + closed(0.3)))
    # The pattern cut across two segments.
    connection(out, 2, opened([
        (0.1, ">", DATA, b"xxABC", None),
        (0.11, "<", ACK, b"", None),
        (0.2, ">", DATA, b"DEFxx", None),
        (0.21, "<", ACK, b"", None),
    ] + closed(0.3)))
    # The second segment arrives first.
    connection(out, 3, opened([
        (0.1, ">", DATA, b"DEFxx", 5),
        (0.2, ">", DATA, b"xxABC", 0),
        (0.21, "<", ACK, b"", None),
    ] + closed(0.3)))
    # The segment holding the pattern is sent twice.
    connection(out, 4, opened([
        (0.1, ">", DATA, b"xxABCDEFxx", 0),
        (0.2, ">", DATA, b"xxABCDEFxx", 0),
        (0.21, "<", ACK, b"", None),
    ] + closed(0.3)))
    # A hole where the middle of the pattern was.
    connection(out, 5, opened([
        (0.1, ">", DATA, b"xxABC", 0),
        (0.2, ">", DATA, b"Fxx", 7),
        (0.21, "<", ACK, b"", None),
    ] + closed(0.3)))
    # The same sequence range sent again with other bytes.
    connection(out, 6, opened([
        (0.1, ">", DATA, b"xxORIGxx", 0),
        (0.2, ">", DATA, b"xxNEWDxx", 0),
        (0.21, "<", ACK, b"", None),
    ] + closed(0.3)))
    # The pattern at the start of the stream and again in a later segment.
    connection(out, 7, opened([
        (0.1, ">", DATA, b"HELLO", None),
        (0.11, "<", ACK, b"", None),
        (0.2, ">", DATA, b"xHELLO and ABCDEF", None),
        (0.21, "<", ACK, b"", None),
        (0.3, ">", DATA, b"ABCDEF again", None),
        (0.31, "<", ACK, b"", None),
    ] + closed(0.4)))
    # Data never acknowledged, then the connection is reset.
    connection(out, 8, opened([
        (0.1, ">", DATA, b"xxABC", None),
        (0.2, ">", DATA, b"DEFxx", None),
        (0.3, ">", RST | ACK, b"", None),
    ]))
    # Data the server never acknowledges, then the client closes.
    connection(out, 9, opened([
        (0.1, ">", DATA, b"xxABC", None),
        (0.2, ">", DATA, b"DEFxx", None),
    ] + closed(0.3)))
    # The pattern at the start of a packet, not of the stream.
    connection(out, 10, opened([
        (0.1, ">", DATA, b"zzzz", None),
        (0.11, "<", ACK, b"", None),
        (0.2, ">", DATA, b"HELLO ABCDEF", None),
        (0.21, "<", ACK, b"", None),
    ] + closed(0.3)))
    # A long stream, each segment acknowledged: when is it inspected.
    script = []
    for k in range(8):
        body = (b"MARK" if k == 2 else b"....") + bytes([0x61 + k]) * 596
        script += [(0.1 * (k + 1), ">", DATA, body, None), (0.1 * (k + 1) + 0.01, "<", ACK, b"", None)]
    connection(out, 11, opened(script + closed(1.0)))
    # A pattern across the end of the first inspected chunk, MARK in both chunks.
    script = []
    for k in range(10):
        body = bytearray(bytes([0x61 + k]) * 600)
        if k == 1:
            body[0:4] = b"MARK"
        if k == 4:
            body[597:600] = b"SPL"
        if k == 5:
            body[0:3] = b"ITX"
        if k == 8:
            body[0:4] = b"MARK"
        script += [(0.1 * (k + 1), ">", DATA, bytes(body), None), (0.1 * (k + 1) + 0.01, "<", ACK, b"", None)]
    connection(out, 12, opened(script + closed(1.2)))
    # The server resets while the client's data is not acknowledged.
    connection(out, 13, opened([
        (0.1, ">", DATA, b"xxABCDEFxx", None),
        (0.2, "<", RST | ACK, b"", None),
        (0.3, ">", DATA, b"late", None),
    ]))
    # Acknowledged data, the server closes first, the client never does.
    connection(out, 14, opened([
        (0.1, ">", DATA, b"xxABCDEFxx", None),
        (0.11, "<", ACK, b"", None),
        (0.2, "<", FIN | ACK, b"", None),
        (0.3, ">", ACK, b"", None),
        (0.4, ">", DATA, b"more", None),
    ]))
    # No handshake seen: the connection was already open.
    connection(out, 15, [
        (0.1, ">", DATA, b"xxABCDEFxx", None),
        (0.11, "<", ACK, b"", None),
        (0.2, ">", DATA, b"HELLO", None),
        (0.3, ">", FIN | ACK, b"", None),
        (0.31, "<", FIN | ACK, b"", None),
        (0.32, ">", ACK, b"", None),
    ])
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    packets = connections()
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        loaded = [rule[:-1] + f" sid:{FIRST_SID + n};)" for n, rule in enumerate(rules)]
        with open(os.path.join(work, "stream.rules"), "w", encoding="utf-8") as f:
            f.write("\n".join(loaded) + "\n")
        times = []
        with open(os.path.join(work, "stream.pcap"), "wb") as f:
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
             "-r", "/w/stream.pcap", "-S", "/w/stream.rules", "-l", "/w/out", "-k", "none",
             "--runmode", "single", "--set", "packet-alert-max=255",
             "--set", "stream.reassembly.randomize-chunk-size=no"],
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
        ended = {}
        for line in open(eve, encoding="utf-8"):
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            if "pcap_cnt" in event:
                alerted.setdefault(event["pcap_cnt"] - 1, []).append(event["alert"]["signature_id"])
            else:
                n = int(event["src_ip"].split(".")[3])
                ended.setdefault(n, []).append(event["alert"]["signature_id"])
        version = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "suricata", IMAGE, "-V"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    lines = [f"# {version}, run by make-stream-verdicts.py; do not edit by hand."]
    lines.append("# 'rule SID RULE', or 'refused SID RULE' when Suricata does not load it,")
    lines.append("# then 'packet NS HEX SIDS': the packet's time in nanoseconds, its IP")
    lines.append("# bytes and the sids that alerted on it, a sid once per alert, '-' for none,")
    lines.append("# then 'end N SIDS': what alerted when connection N was flushed at the")
    lines.append("# end of the capture, its last address byte being N.")
    for n, rule in enumerate(rules):
        word = "refused" if n + 1 in refused else "rule"
        lines.append(f"{word} {FIRST_SID + n} {rule}")
    for n, ((_, _, ip), ns) in enumerate(zip(packets, times)):
        sids = ",".join(str(s) for s in sorted(alerted.get(n, ()))) or "-"
        lines.append(f"packet {ns} {ip.hex()} {sids}")
    for n in sorted({n for n, _, _ in packets}):
        sids = ",".join(str(s) for s in sorted(ended.get(n, ()))) or "-"
        lines.append(f"end {n} {sids}")
    with open(os.path.join(HERE, "stream-verdicts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
