"""Run rules carrying each action through a real Suricata, as an IDS and as an IPS.

The conversations put a marker in each packet, before, at and after the one a
`pass`, `drop` or `reject` rule matches, on TCP, UDP and HTTP, in both
directions, so what alerts says how far each action reaches: the packet, the
rest of the flow, or the other direction. Suricata runs as an IDS, reading
the capture as the agent reads what the kernel hands it: after the packet
went through.

Writes action-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor
docker. Needs docker.
"""

import os
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 16000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("pass", "tcp", 'content:"PASSME";'),
    ("alert", "tcp", 'content:"PASSME";'),
    ("alert", "tcp", 'content:"AFTERPASS";'),
    ("alert", "tcp", 'content:"REPLYPASS";'),
    ("drop", "tcp", 'content:"DROPME";'),
    ("alert", "tcp", 'content:"DROPME";'),
    ("alert", "tcp", 'content:"AFTERDROP";'),
    ("alert", "tcp", 'content:"REPLYDROP";'),
    ("reject", "tcp", 'content:"REJECTME";'),
    ("alert", "tcp", 'content:"AFTERREJECT";'),
    ("pass", "udp", 'content:"UPASS";'),
    ("alert", "udp", 'content:"UPASS";'),
    ("alert", "udp", 'content:"UAFTER";'),
    ("drop", "udp", 'content:"UDROP";'),
    ("alert", "udp", 'content:"UDAFTER";'),
    ("alert", "tcp", 'content:"BEFOREPASS";'),
    ("pass", "tcp-pkt", 'content:"PKTPASS";'),
    ("alert", "tcp", 'content:"PKTAFTER";'),
    ("pass", "http", 'http.uri; content:"/passed";'),
    ("alert", "http", 'http.uri; content:"/passed";'),
    ("alert", "tcp", 'content:"after http pass";'),
    ("alert", "ip", 'content:"PASSME";'),
    ("pass", "tcp", 'flow:to_client; content:"SRVPASS";'),
    ("alert", "tcp", 'content:"CLIAFTER";'),
    ("alert", "tcp", 'content:"SRVPASS";'),
    ("drop", "tcp", 'content:"BOTHDROP";'),
    ("alert", "tcp", 'content:"BOTHDROP";'),
    ("pass", "tcp", 'content:"BOTHDROP";'),
    ("alert", "tcp", 'content:"LATERBOTH";'),
]


def rule_text(n, entry):
    action, proto, options = entry
    return f"{action} {proto} any any -> any any (msg:\"action {FIRST_SID + n}\"; {options})"


def conversations():
    out = []
    talk, tcp, udp = applayer.talk, applayer.tcp_conversation, applayer.udp_conversation
    tcp(out, 1, 9001, talk([(">", b"BEFOREPASS"), (">", b"PASSME"), ("<", b"REPLYPASS"), (">", b"AFTERPASS")]))
    tcp(out, 2, 9002, talk([(">", b"DROPME"), ("<", b"REPLYDROP"), (">", b"AFTERDROP")]))
    tcp(out, 3, 9003, talk([(">", b"REJECTME"), (">", b"AFTERREJECT")]))
    udp(out, 4, 9004, [(0.1, ">", b"UPASS"), (0.2, "<", b"UAFTER"), (0.3, ">", b"UAFTER")])
    udp(out, 5, 9005, [(0.1, ">", b"UDROP"), (0.2, ">", b"UDAFTER")])
    tcp(out, 6, 9006, talk([(">", b"PKTPASS"), (">", b"PKTAFTER")]))
    tcp(out, 7, 80, talk([
        (">", b"GET /passed HTTP/1.1\r\nHost: a\r\n\r\n"),
        ("<", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        (">", b"GET /other HTTP/1.1\r\nHost: a\r\nX: after http pass\r\n\r\n"),
        ("<", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
    ]))
    tcp(out, 8, 9008, talk([("<", b"SRVPASS"), (">", b"CLIAFTER")]))
    tcp(out, 9, 9009, talk([(">", b"BOTHDROP"), (">", b"LATERBOTH")]))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("action", "make-action-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
