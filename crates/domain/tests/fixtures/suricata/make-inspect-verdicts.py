#!/usr/bin/env python3
"""Run the cases of inspect.cases through a real Suricata.

Every rule of the file gets the header `alert tcp-pkt any any -> any PORT`,
PORT unique to the rule; every payload under it is one TCP segment to that
port from its own source port. Suricata reads the capture and the rules, and
the alerts it writes decide, per rule and payload, whether the payload
matched. A rule Suricata refuses to load is recorded as refused.

A `hdr` case puts its bytes in a TCP option rather than in the payload, so a
rule reading `tcp.hdr` sees them through the transforms it names; `{md5}`,
`{sha1}` and `{sha256}` in such a rule stand for the digest of the header the
first payload under it produces.

Writes inspect-verdicts.txt beside this script: each rule as Suricata read it,
then one line per payload with the verdict and the bytes of the buffer the
rule inspects, so the test needs neither this script nor its parsing. Needs
docker.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = os.environ.get("SURICATA_IMAGE", "jasonish/suricata:8.0.8")
FIRST_PORT = 20000
FIRST_SID = 1000


def decode(text):
    """A Suricata content string, quotes included, to bytes."""
    if not (text.startswith('"') and text.endswith('"')):
        sys.exit(f"payload is not quoted: {text}")
    body = text[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "|":
            j = body.index("|", i + 1)
            out += bytes.fromhex(body[i + 1 : j].replace(" ", ""))
            i = j + 1
        elif c == "\\":
            out.append(ord(body[i + 1]))
            i += 2
        else:
            out.append(ord(c))
            i += 1
    return bytes(out)


def read_cases(path):
    cases = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith(("rule ", "hdr ")):
            kind, options = line.split(" ", 1)
            cases.append((kind, options.strip(), []))
        elif line.startswith("  "):
            cases[-1][2].append(decode(line.strip()))
        else:
            sys.exit(f"unreadable line: {line}")
    return cases


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def option(data):
    """The bytes as one experimental TCP option, padded with NOPs."""
    if len(data) > 38:
        sys.exit(f"a header case holds at most 38 bytes: {data!r}")
    body = bytes([254, 2 + len(data)]) + data
    return b"\x01" * (-len(body) % 4) + body


def segment(sport, dport, payload, options=b""):
    """The frame, and the TCP header as Suricata's tcp.hdr sees it."""
    src, dst = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    words = (20 + len(options)) // 4
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 1, words << 4, 0x18, 65535, 0, 0) + options
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ether = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00"
    return ether + ip + tcp + payload, tcp


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, frame in enumerate(frames):
            f.write(struct.pack("<IIII", 1_700_000_000 + n, 0, len(frame), len(frame)))
            f.write(frame)


def main():
    cases = read_cases(os.path.join(HERE, "inspect.cases"))
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        rules, frames, sources, written, buffers = [], [], {}, [], {}
        sport = 30000
        for index, (kind, options, payloads) in enumerate(cases):
            port, sid = FIRST_PORT + index, FIRST_SID + index
            for number, payload in enumerate(payloads):
                if kind == "hdr":
                    frame, header = segment(sport, port, b"x", option(payload))
                    buffers[(sid, number)] = header
                else:
                    frame, _ = segment(sport, port, payload)
                    buffers[(sid, number)] = payload
                frames.append(frame)
                sources[sport] = (sid, number)
                sport += 1
            if kind == "hdr":
                first = buffers[(sid, 0)]
                for name in ("md5", "sha1", "sha256"):
                    digest = hashlib.new(name, first).hexdigest()
                    options = options.replace("{" + name + "}", "\"|" + digest + "|\"")
            written.append((kind, options))
            rules.append(f"alert tcp-pkt any any -> any {port} (msg:\"case {sid}\"; {options} sid:{sid};)")
        with open(os.path.join(work, "cases.rules"), "w", encoding="utf-8") as f:
            f.write("\n".join(rules) + "\n")
        write_pcap(os.path.join(work, "cases.pcap"), frames)
        os.mkdir(os.path.join(work, "out"))
        os.chmod(os.path.join(work, "out"), 0o777)
        run = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "--entrypoint", "suricata", IMAGE,
             "-r", "/w/cases.pcap", "-S", "/w/cases.rules", "-l", "/w/out", "-k", "none",
             "--runmode", "single"],
            capture_output=True, text=True, check=False,
        )
        log = run.stdout + run.stderr
        refused = {int(m.group(1)) for m in re.finditer(r"at line (\d+)$", log, re.M)}
        alerted = set()
        eve = os.path.join(work, "out", "eve.json")
        if not os.path.exists(eve):
            sys.exit(f"suricata wrote no eve.json:\n{log}")
        for line in open(eve, encoding="utf-8"):
            event = json.loads(line)
            if event.get("event_type") == "alert":
                alerted.add((event["alert"]["signature_id"], sources[event["src_port"]]))
        version = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "suricata", IMAGE, "-V"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    lines = [f"# {version}, run by make-inspect-verdicts.py; do not edit by hand."]
    lines.append("# 'rule SID payload|hdr OPTIONS', or 'rule SID refused OPTIONS' when")
    lines.append("# Suricata does not load it, then 'SID N match|nomatch HEX' per payload,")
    lines.append("# HEX being the buffer: the payload, or the TCP header of a hdr case.")
    for index, (_, _, payloads) in enumerate(cases):
        sid = FIRST_SID + index
        kind, options = written[index]
        if index + 1 in refused:
            lines.append(f"rule {sid} refused {options}")
            continue
        lines.append(f"rule {sid} {'hdr' if kind == 'hdr' else 'payload'} {options}")
        for number in range(len(payloads)):
            hit = (sid, (sid, number)) in alerted
            verdict = "match" if hit else "nomatch"
            lines.append(f"{sid} {number} {verdict} {buffers[(sid, number)].hex()}")
    with open(os.path.join(HERE, "inspect-verdicts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
