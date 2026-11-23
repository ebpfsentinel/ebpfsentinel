"""Run the scenarios of flow.cases through a real Suricata.

Scenario N has server 10.2.0.N on port 21000+N and client 10.1.0.N; client
port cK is 40000+K. Its packets start at second N*10000 of the capture, so no
state of one scenario outlives into the next. A `>` rule gets the header
`alert tcp-pkt any any -> any PORT`, a `<` rule `alert tcp-pkt any PORT ->
any any`: Suricata inspects each segment as a packet, with no handshake.
Sequence numbers advance per direction of each connection.

Writes flow-verdicts.txt beside this script: each rule with `tcp` in place of
`tcp-pkt`, as the agent loads it, or marked refused when Suricata does not
load it, then one line per packet with its time, addresses, ports, payload
and the sids Suricata alerted on it, so the test needs neither this script
nor its parsing. Needs docker.
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
FIRST_SID = 3000
EPOCH = 1_700_000_000

spec = util.spec_from_file_location("inspect", os.path.join(HERE, "make-inspect-verdicts.py"))
inspect = util.module_from_spec(spec)
spec.loader.exec_module(inspect)

def read_cases(path):
    scenarios = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("scenario "):
            scenarios.append({"name": line[9:], "rules": [], "packets": []})
        elif line.startswith(("> ", "< ")):
            scenarios[-1]["rules"].append((line[0], line[2:].strip()))
        elif line.startswith("  "):
            m = re.fullmatch(r"\s+([\d.]+) ([<>])(?: c(\d+))? (\".*\")", line)
            if not m:
                sys.exit(f"unreadable packet: {line}")
            scenarios[-1]["packets"].append(
                (float(m.group(1)), m.group(2), int(m.group(3) or 0), inspect.decode(m.group(4)))
            )
        else:
            sys.exit(f"unreadable line: {line}")
    return scenarios

def frame(src, dst, sport, dport, seq, payload):
    """One TCP segment, PSH ACK, with valid checksums."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", inspect.checksum(pseudo + tcp + payload)) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", inspect.checksum(ip)) + ip[12:]
    ether = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00"
    return ether + ip + tcp + payload

def main():
    scenarios = read_cases(os.path.join(HERE, "flow.cases"))
    rules, written, packets = [], [], []
    sid = FIRST_SID
    for n, scenario in enumerate(scenarios, start=1):
        port = 21000 + n
        for direction, options in scenario["rules"]:
            head = f"any any -> any {port}" if direction == ">" else f"any {port} -> any any"
            rules.append(f"alert tcp-pkt {head} (msg:\"case {sid}\"; {options} sid:{sid};)")
            written.append((sid, f"alert tcp {head} (msg:\"case {sid}\"; {options} sid:{sid};)"))
            sid += 1
        client, server = bytes([10, 1, 0, n]), bytes([10, 2, 0, n])
        seqs = {}
        for at, direction, k, payload in scenario["packets"]:
            cport = 40000 + k
            if direction == ">":
                src, dst, sport, dport = client, server, cport, port
            else:
                src, dst, sport, dport = server, client, port, cport
            key = (sport, dport)
            seq = seqs.get(key, 1000)
            seqs[key] = seq + len(payload)
            ns = (n * 10_000_000 + round(at * 1000)) * 1_000_000
            packets.append((ns, src, dst, sport, dport, payload, frame(src, dst, sport, dport, seq, payload)))
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        with open(os.path.join(work, "flow.rules"), "w", encoding="utf-8") as f:
            f.write("\n".join(rules) + "\n")
        with open(os.path.join(work, "flow.pcap"), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ns, *_, data in packets:
                secs, rest = divmod(ns, 1_000_000_000)
                f.write(struct.pack("<IIII", EPOCH + secs, rest // 1000, len(data), len(data)))
                f.write(data)
        os.mkdir(os.path.join(work, "out"))
        os.chmod(os.path.join(work, "out"), 0o777)
        run = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "--entrypoint", "suricata", IMAGE,
             "-r", "/w/flow.pcap", "-S", "/w/flow.rules", "-l", "/w/out", "-k", "none",
             "--runmode", "single"],
            capture_output=True, text=True, check=False,
        )
        log = run.stdout + run.stderr
        refused = {FIRST_SID + int(m.group(1)) - 1 for m in re.finditer(r"at line (\d+)$", log, re.M)}
        eve = os.path.join(work, "out", "eve.json")
        if not os.path.exists(eve):
            sys.exit(f"suricata wrote no eve.json:\n{log}")
        alerts = {}
        for line in open(eve, encoding="utf-8"):
            event = json.loads(line)
            if event.get("event_type") == "alert":
                key = (event["src_ip"], event["src_port"], event["dest_ip"], event["dest_port"], event["pcap_cnt"])
                alerts.setdefault(key, set()).add(event["alert"]["signature_id"])
        version = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "suricata", IMAGE, "-V"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    lines = [f"# {version}, run by make-flow-verdicts.py; do not edit by hand."]
    lines.append("# 'rule SID loaded|refused RULE', then 'packet NS SRC SPORT DST DPORT HEX SIDS'")
    lines.append("# per packet, NS its time in nanoseconds and SIDS the alerted rules or '-'.")
    for sid, rule in written:
        lines.append(f"rule {sid} {'refused' if sid in refused else 'loaded'} {rule}")
    for count, (ns, src, dst, sport, dport, payload, _) in enumerate(packets, start=1):
        s, d = ".".join(map(str, src)), ".".join(map(str, dst))
        sids = sorted(alerts.get((s, sport, d, dport, count), ()))
        hit = ",".join(map(str, sids)) or "-"
        lines.append(f"packet {ns} {s} {sport} {d} {dport} {payload.hex()} {hit}")
    with open(os.path.join(HERE, "flow-verdicts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

if __name__ == "__main__":
    main()
