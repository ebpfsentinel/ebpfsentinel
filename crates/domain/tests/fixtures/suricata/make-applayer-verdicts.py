#!/usr/bin/env python3
"""Run the application-layer rules below over crafted conversations through a real Suricata.

Each conversation speaks one protocol, on its usual port or on another one,
or speaks none. The rules name an application protocol in their header or
ask for one with `app-layer-protocol`, so what alerts says which protocol
Suricata found on each flow and from which packet on.

Writes applayer-verdicts.txt beside this script: each rule, marked refused
when Suricata does not load it, then one line per packet with its time in
nanoseconds, its IP bytes and the sids that alerted on it, a sid repeated as
often as it alerted, then what alerted when each flow ended, then the
protocol Suricata logged for each flow. The test needs neither this script
nor docker. Needs docker.
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
FIRST_SID = 7000
EPOCH = 1_700_000_000

spec = util.spec_from_file_location("header", os.path.join(HERE, "make-header-verdicts.py"))
header = util.module_from_spec(spec)
spec.loader.exec_module(header)

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 0x10
DATA = PSH | ACK

RULES = [
    ("http", 'content:"GET";'),
    ("http", 'content:"200 OK"; flow:to_client;'),
    ("http1", 'content:"GET";'),
    ("tcp", 'app-layer-protocol:http; content:"GET";'),
    ("tcp", "app-layer-protocol:http;"),
    ("tcp", "app-layer-protocol:!http;"),
    ("tcp", "app-layer-protocol:failed;"),
    ("tcp", "app-layer-protocol:unknown;"),
    ("tls", 'content:"|16 03|";'),
    ("tcp", "app-layer-protocol:tls;"),
    ("ip", "app-layer-protocol:tls;"),
    ("ssh", 'content:"SSH-";'),
    ("smtp", 'content:"EHLO";'),
    ("ftp", 'content:"USER";'),
    ("dns", 'content:"|01 00 00 01|";'),
    ("udp", "app-layer-protocol:dns;"),
    ("tcp", "app-layer-protocol:dns;"),
    ("tcp", 'content:"GET";'),
    ("http", 'content:"GET"; flow:established,to_server;'),
    ("tcp", "app-layer-protocol:http,to_server;"),
    ("tcp", "app-layer-protocol:http,to_client;"),
    ("tcp", "app-layer-protocol:http,either;"),
    ("tcp", "app-layer-protocol:http,final;"),
    ("tcp", "app-layer-protocol:http,original;"),
    ("tcp", "app-layer-protocol:!tls; content:\"hello\";"),
    ("http", "flow:to_server;"),
    ("tls", "flow:to_server;"),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"applayer {FIRST_SID + n}\"; {options})"


def tcp_conversation(packets, n, port, script):
    """`script` holds (seconds, side, flags, payload). Each packet
    acknowledges everything the other side has sent so far."""
    client, server = bytes([10, 9, 0, n]), bytes([10, 10, 0, n])
    cport = 43000 + n
    isn = {">": 1000, "<": 5000}
    sent = {">": 0, "<": 0}
    syn = {">": 0, "<": 0}
    for at, side, flags, payload in script:
        other = "<" if side == ">" else ">"
        src, dst, a, b = (client, server, cport, port) if side == ">" else (server, client, port, cport)
        if flags & SYN:
            seq = isn[side]
            syn[side] = 1
        else:
            seq = isn[side] + syn[side] + sent[side]
            sent[side] += len(payload)
        if flags & FIN:
            sent[side] += 1
        ack = isn[other] + syn[other] + sent[other] if flags & ACK else 0
        body = header.tcp(a, b, flags, payload, seq=seq, ack=ack, src=src, dst=dst)
        packets.append((n, at, header.ipv4(6, body, src=src, dst=dst)))


def udp_conversation(packets, n, port, script):
    client, server = bytes([10, 9, 0, n]), bytes([10, 10, 0, n])
    cport = 43000 + n
    for at, side, payload in script:
        src, dst, a, b = (client, server, cport, port) if side == ">" else (server, client, port, cport)
        packets.append((n, at, header.ipv4(17, header.udp(a, b, payload, src=src, dst=dst), src=src, dst=dst)))


def talk(exchanges):
    """A connection opened, the exchanges each acknowledged, then closed."""
    script = [
        (0.0, ">", SYN, b""),
        (0.01, "<", SYN | ACK, b""),
        (0.02, ">", ACK, b""),
    ]
    at = 0.1
    for side, payload in exchanges:
        other = "<" if side == ">" else ">"
        script.append((at, side, DATA, payload))
        script.append((at + 0.01, other, ACK, b""))
        at += 0.1
    script += [
        (at, ">", FIN | ACK, b""),
        (at + 0.01, "<", FIN | ACK, b""),
        (at + 0.02, ">", ACK, b""),
    ]
    return script


def tls_hello(kind):
    body = b"\x03\x03" + bytes(range(32)) + b"\x00"
    body += b"\x00\x02\x00\x2f\x01\x00" if kind == 1 else b"\x00\x2f\x00"
    body += b"\x00\x00"
    handshake = bytes([kind]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def dns(ident, flags, answer):
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    counts = struct.pack(">HHHHHH", ident, flags, 1, 1 if answer else 0, 0, 0)
    record = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22" if answer else b""
    return counts + question + record


HTTP_REQUEST = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


def conversations():
    out = []
    tcp_conversation(out, 1, 80, talk([(">", HTTP_REQUEST), ("<", HTTP_RESPONSE)]))
    tcp_conversation(out, 2, 8443, talk([(">", HTTP_REQUEST), ("<", HTTP_RESPONSE)]))
    tcp_conversation(out, 3, 443, talk([(">", tls_hello(1)), ("<", tls_hello(2))]))
    tcp_conversation(out, 4, 80, talk([(">", tls_hello(1)), ("<", tls_hello(2))]))
    tcp_conversation(out, 5, 80, talk([(">", b"hello there\r\n"), ("<", b"hello back\r\n")]))
    tcp_conversation(out, 6, 2222, talk([("<", b"SSH-2.0-OpenSSH_9.6\r\n"), (">", b"SSH-2.0-OpenSSH_9.6\r\n")]))
    tcp_conversation(out, 7, 2525, talk([("<", b"220 mail ESMTP\r\n"), (">", b"EHLO client\r\n"), ("<", b"250 ok\r\n")]))
    tcp_conversation(out, 8, 21, talk([("<", b"220 FTP ready\r\n"), (">", b"USER anonymous\r\n"), ("<", b"331 password\r\n")]))
    tcp_conversation(out, 9, 2121, talk([("<", b"220 FTP ready\r\n"), (">", b"USER anonymous\r\n"), ("<", b"331 password\r\n")]))
    query, answer = dns(0x1234, 0x0100, False), dns(0x1234, 0x8180, True)
    udp_conversation(out, 10, 53, [(0.0, ">", query), (0.01, "<", answer)])
    udp_conversation(out, 11, 5300, [(0.0, ">", query), (0.01, "<", answer)])
    framed = lambda m: len(m).to_bytes(2, "big") + m
    tcp_conversation(out, 12, 53, talk([(">", framed(query)), ("<", framed(answer))]))
    tcp_conversation(out, 13, 5300, talk([(">", framed(query)), ("<", framed(answer))]))
    tcp_conversation(out, 14, 80, talk([(">", b"GE"), (">", b"T / HTTP/1.1\r\nHost: a\r\n\r\n"), ("<", HTTP_RESPONSE)]))
    tcp_conversation(out, 15, 80, talk([("<", HTTP_RESPONSE), (">", HTTP_REQUEST)]))
    return out


def verdicts(stem, script, first_sid, rules, packets):
    """Runs `rules` over `packets` through Suricata and writes
    `<stem>-verdicts.txt` beside this script."""
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        loaded = [rule[:-1] + f" sid:{first_sid + n};)" for n, rule in enumerate(rules)]
        with open(os.path.join(work, "case.rules"), "w", encoding="utf-8") as f:
            f.write("\n".join(loaded) + "\n")
        times = []
        with open(os.path.join(work, "case.pcap"), "wb") as f:
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
             "-r", "/w/case.pcap", "-S", "/w/case.rules", "-l", "/w/out", "-k", "none",
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
        protos = {}
        for line in open(eve, encoding="utf-8"):
            event = json.loads(line)
            kind = event.get("event_type")
            if kind == "flow":
                n = int(event["src_ip"].split(".")[3])
                protos[n] = event.get("app_proto", "-")
            if kind != "alert":
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
    lines = [f"# {version}, run by {script}; do not edit by hand."]
    lines.append("# 'rule SID RULE', or 'refused SID RULE' when Suricata does not load it,")
    lines.append("# then 'packet NS HEX SIDS': the packet's time in nanoseconds, its IP")
    lines.append("# bytes and the sids that alerted on it, a sid once per alert, '-' for none,")
    lines.append("# then 'end N SIDS': what alerted when flow N was flushed at the end of")
    lines.append("# the capture, its last address byte being N, then 'proto N NAME': the")
    lines.append("# application protocol Suricata logged for flow N.")
    for n, rule in enumerate(rules):
        word = "refused" if n + 1 in refused else "rule"
        lines.append(f"{word} {first_sid + n} {rule}")
    for n, ((_, _, ip), ns) in enumerate(zip(packets, times)):
        sids = ",".join(str(s) for s in sorted(alerted.get(n, ()))) or "-"
        lines.append(f"packet {ns} {ip.hex()} {sids}")
    flows = sorted({n for n, _, _ in packets})
    for n in flows:
        sids = ",".join(str(s) for s in sorted(ended.get(n, ()))) or "-"
        lines.append(f"end {n} {sids}")
    for n in flows:
        lines.append(f"proto {n} {protos.get(n, '-')}")
    with open(os.path.join(HERE, f"{stem}-verdicts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    verdicts("applayer", "make-applayer-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
