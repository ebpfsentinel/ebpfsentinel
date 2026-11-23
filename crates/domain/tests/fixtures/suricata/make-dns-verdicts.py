"""Run the DNS rules below over crafted DNS exchanges through a real Suricata.

The rules read `dns.query` on queries and answers over UDP and TCP, with
names in odd case, several questions, compressed names, labels holding a dot
or a zero byte, and messages cut short, so what alerts says what Suricata
puts in the buffer and on which packet it reads it. Some rules are written
to be refused, to show which mixes Suricata does not load.

Writes dns-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import os
import struct
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 9000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("dns", 'dns.query; content:"example.com"; startswith; endswith;'),
    ("dns", 'dns.query; content:"Example.COM"; startswith; endswith;'),
    ("udp", 'dns.query; content:"example.com"; startswith; endswith;'),
    ("tcp", 'dns.query; content:"example.com"; startswith; endswith;'),
    ("dns", 'flow:to_client; dns.query; content:"example.com";'),
    ("dns", 'flow:to_server; dns.query; content:"example.com";'),
    ("dns", 'dns.query; content:"second.org"; startswith; endswith;'),
    ("dns", 'dns.query; dotprefix; content:".example.com"; endswith;'),
    ("dns", 'dns.query; content:"evil.example"; nocase;'),
    ("http", 'dns.query; content:"example";'),
    ("dns", 'content:"|01 00|"; dns.query; content:"example";'),
    ("dns", "dns.query; bsize:11;"),
    ("dns", 'dns_query; content:"example.com"; startswith; endswith;'),
    ("dns", 'dns.query; content:"a.b.test"; startswith; endswith;'),
    ("dns", 'dns.query; content:"a|00|b.test"; startswith; endswith;'),
    ("dns", 'dns.query; pcre:"/^example\\.com$/";'),
    ("ip", 'dns.query; content:"example.com"; startswith; endswith;'),
    ("dns", 'dns.query; content:"comp.example.com"; startswith; endswith;'),
    ("dns", 'flow:established; dns.query; content:"example.com";'),
    ("dns", "dns.query; bsize:0;"),
    ("dns", 'dns.query; content:"resp.example";'),
    ("udp", 'content:"example";'),
    ("dns", 'dns.query; content:"exam";'),
    ("dns", 'dns.query; content:"one.test"; startswith; endswith;'),
    ("dns", 'dns.query; content:"two.test"; startswith; endswith;'),
    ("dns", 'dns.query; content:"example.com"; dns.query; content:"second.org";'),
    ("dns", 'dns.query; content:"|5c|"; '),
    ("dns", 'dns.query; content:"bad|20|name.test"; startswith; endswith;'),
    ("dns", 'flow:not_established; dns.query; content:"example.com";'),
    ("tcp-pkt", 'dns.query; content:"example.com";'),
    ("dns", 'dns.query; content:"example.com"; flowbits:set,asked; noalert;'),
    ("dns", 'flowbits:isset,asked; content:"|81 80|";'),
    ("dns", 'dns.queries.rrname; content:"example.com"; startswith; endswith;'),
    ("dns", 'dns.queries.rrname; content:"full.test"; startswith; endswith;'),
    ("dns", 'dns.answers.rrname; content:"full.test"; startswith; endswith;'),
    ("dns", 'dns.answers.rrname; content:"alias.test"; startswith; endswith;'),
    ("dns", 'dns.authorities.rrname; content:"test"; startswith; endswith;'),
    ("dns", 'dns.additionals.rrname; content:"ns1.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"full.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"alias.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"ns1.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"target.test"; startswith; endswith;'),
    ("dns", "dns.opcode:0;"),
    ("dns", "dns.opcode:2;"),
    ("dns", "dns.opcode:!0;"),
    ("dns", "dns.rcode:0;"),
    ("dns", "dns.rcode:3;"),
    ("dns", "dns.rcode:>0;"),
    ("dns", "dns.rrtype:1;"),
    ("dns", "dns.rrtype:15;"),
    ("dns", "dns.rrtype:5;"),
    ("dns", "dns.rrtype:2;"),
    ("dns", "flow:to_server; dns.rcode:0;"),
    ("dns", "flow:to_client; dns.opcode:0;"),
    ("dns", 'dns.opcode:0; dns.query; content:"example.com";'),
    ("dns", 'flow:to_server; dns.answers.rrname; content:"full";'),
    ("dns", 'flow:to_server; dns.queries.rrname; content:"full";'),
    ("dns", 'dns.rrtype:15; dns.query; content:"mx.test";'),
    ("udp", "dns.opcode:0;"),
    ("dns", 'dns.queries.rrname; content:"Example.COM"; startswith; endswith;'),
    ("dns", 'dns.answers.rrname; content:"Example.COM"; startswith; endswith;'),
    ("dns", 'dns.answers.rrname; content:"target.test"; startswith; endswith;'),
    ("dns", "dns.rrtype:28;"),
    ("dns", 'dns.response.rrname; content:"mx.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"nsonly.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"mxhost.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"q.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"ptr.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"soa-m.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"soa-r.test"; startswith; endswith;'),
    ("dns", 'dns.response.rrname; content:"srv.test"; startswith; endswith;'),
    ("dns", 'flow:to_server; dns.response.rrname; content:"test";'),
    ("dns", 'flow:to_client; dns.queries.rrname; content:"srvq.test";'),
    ("dns", 'dns.response.rrname; content:"txt.test";'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"dns {FIRST_SID + n}\"; {options})"


def name(*labels):
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def message(ident, flags, questions, answers=b"", count=0):
    head = struct.pack(">HHHHHH", ident, flags, len(questions), count, 0, 0)
    return head + b"".join(q + b"\x00\x01\x00\x01" for q in questions) + answers


A = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"
EXAMPLE = name(b"example", b"com")


def query(*questions, ident=0x1234):
    return message(ident, 0x0100, list(questions))


def answer(*questions, ident=0x1234):
    return message(ident, 0x8180, list(questions), A, 1)


def framed(*messages):
    return b"".join(len(m).to_bytes(2, "big") + m for m in messages)


def conversations():
    out = []
    udp = applayer.udp_conversation
    tcp = applayer.tcp_conversation
    talk = applayer.talk
    udp(out, 1, 53, [(0.0, ">", query(EXAMPLE)), (0.01, "<", answer(EXAMPLE))])
    mixed = name(b"Example", b"COM")
    udp(out, 2, 53, [(0.0, ">", query(mixed)), (0.01, "<", answer(mixed))])
    udp(out, 3, 5353, [(0.0, ">", query(EXAMPLE)), (0.01, "<", answer(EXAMPLE))])
    tcp(out, 4, 53, talk([(">", framed(query(EXAMPLE))), ("<", framed(answer(EXAMPLE)))]))
    second = name(b"second", b"org")
    udp(out, 5, 53, [(0.0, ">", query(EXAMPLE, second))])
    udp(out, 6, 53, [(0.0, ">", query(name(b"a.b", b"test")))])
    udp(out, 7, 53, [(0.0, ">", query(name(b"a\x00b", b"test")))])
    udp(out, 8, 53, [(0.0, "<", answer(name(b"resp", b"example")))])
    udp(out, 9, 53, [(0.0, ">", query(name(b"evil", b"EXAMPLE", b"com")))])
    one, two = name(b"one", b"test"), name(b"two", b"test")
    tcp(out, 10, 53, talk([
        (">", framed(query(one, ident=1), query(two, ident=2))),
        ("<", framed(answer(one, ident=1), answer(two, ident=2))),
    ]))
    udp(out, 11, 53, [(0.0, ">", query(EXAMPLE, b"\x04comp\xc0\x0c"))])
    udp(out, 12, 53, [(0.0, ">", query(b"\x00"))])
    udp(out, 13, 53, [(0.0, ">", struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"\x07exam")])
    udp(out, 14, 53, [(0.0, ">", query(name(b"bad name", b"test")))])
    udp(out, 15, 53, [(0.0, ">", query(name(b"a\\b", b"test")))])
    udp(out, 16, 53, [
        (0.0, ">", query(EXAMPLE)),
        (0.01, ">", query(EXAMPLE)),
        (0.02, "<", answer(EXAMPLE)),
    ])
    tcp(out, 17, 53, talk([
        (">", framed(query(EXAMPLE))[:10]),
        (">", framed(query(EXAMPLE))[10:]),
        ("<", framed(answer(EXAMPLE))),
    ]))
    # A full answer: the question, a CNAME then an A in the answers, an NS
    # in the authorities and an A in the additionals.
    full = name(b"full", b"test")
    alias = name(b"alias", b"test")
    rr = lambda owner, kind, data: owner + struct.pack(">HHIH", kind, 1, 60, len(data)) + data
    sections = (
        rr(b"\xc0\x0c", 5, alias)
        + rr(alias, 1, b"\x01\x02\x03\x04")
        + rr(name(b"test"), 2, name(b"ns1", b"test"))
        + rr(name(b"ns1", b"test"), 1, b"\x05\x06\x07\x08")
    )
    reply = struct.pack(">HHHHHH", 9, 0x8180, 1, 2, 1, 1) + full + b"\x00\x01\x00\x01" + sections
    udp(out, 18, 53, [(0.0, ">", query(full, ident=9)), (0.01, "<", reply)])
    mx = name(b"mx", b"test")
    mxq = struct.pack(">HHHHHH", 10, 0x0100, 1, 0, 0, 0) + mx + b"\x00\x0f\x00\x01"
    nx = struct.pack(">HHHHHH", 10, 0x8183, 1, 0, 0, 0) + mx + b"\x00\x0f\x00\x01"
    udp(out, 19, 53, [(0.0, ">", mxq), (0.01, "<", nx)])
    status = struct.pack(">HHHHHH", 11, 0x1100, 1, 0, 0, 0) + EXAMPLE + b"\x00\x01\x00\x01"
    udp(out, 20, 53, [(0.0, ">", status)])
    tcp(out, 21, 53, talk([(">", framed(query(full, ident=9))), ("<", framed(reply))]))
    udp(out, 22, 53, [(0.0, "<", query(EXAMPLE))])
    # A CNAME whose target is named nowhere else, and an AAAA in the
    # additionals alone.
    q = name(b"q", b"test")
    cname = rr(b"\xc0\x0c", 5, name(b"target", b"test"))
    extra = rr(name(b"other", b"test"), 28, bytes(16))
    reply = struct.pack(">HHHHHH", 12, 0x8180, 1, 1, 0, 1) + q + b"\x00\x01\x00\x01" + cname + extra
    udp(out, 23, 53, [(0.0, ">", query(q, ident=12)), (0.01, "<", reply)])
    # An MX answer, a PTR answer and an NS in the authorities whose
    # targets are named nowhere else.
    mxa = rr(b"\xc0\x0c", 15, b"\x00\x0a" + name(b"mxhost", b"test"))
    ptr = rr(b"\xc0\x0c", 12, name(b"ptr", b"test"))
    ns = rr(name(b"zone"), 2, name(b"nsonly", b"test"))
    reply = struct.pack(">HHHHHH", 13, 0x8180, 1, 2, 1, 0) + mx + b"\x00\x0f\x00\x01" + mxa + ptr + ns
    udp(out, 24, 53, [(0.0, ">", mxq), (0.01, "<", reply)])
    # An SRV and a TXT answer and an SOA in the authorities.
    srvq = name(b"srvq", b"test")
    srv = rr(b"\xc0\x0c", 33, b"\x00\x01\x00\x02\x00\x50" + name(b"srv", b"test"))
    txt = rr(b"\xc0\x0c", 16, b"\x08txt.test")
    soa = rr(name(b"test"), 6, name(b"soa-m", b"test") + name(b"soa-r", b"test") + bytes(20))
    question = srvq + b"\x00\x21\x00\x01"
    reply = struct.pack(">HHHHHH", 14, 0x8180, 1, 2, 1, 0) + question + srv + txt + soa
    ask = struct.pack(">HHHHHH", 14, 0x0100, 1, 0, 0, 0) + question
    udp(out, 25, 53, [(0.0, ">", ask), (0.01, "<", reply)])
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("dns", "make-dns-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
