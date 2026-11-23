"""Run the RDP, SMB, DCE/RPC and Telnet rules below over crafted conversations through a real Suricata.

The conversations open the way each protocol opens, on its usual port and on
another one, with keepalives and partial headers in front, and carry the
messages whose parsing asks Suricata to inspect a stream at once, beside
ones that do not, so what alerts says which protocol Suricata found and on
which packet it read the stream.

Writes windows-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import os
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 11000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("rdp", 'content:"|03 00|";'),
    ("tcp", "app-layer-protocol:rdp;"),
    ("rdp", 'content:"again";'),
    ("smb", 'content:"SMB";'),
    ("tcp", "app-layer-protocol:smb;"),
    ("dcerpc", 'content:"|05 00|";'),
    ("dcerpc", 'content:"SMB";'),
    ("tcp", "app-layer-protocol:dcerpc;"),
    ("tcp", "app-layer-protocol:!dcerpc;"),
    ("udp", "app-layer-protocol:dcerpc;"),
    ("udp", "app-layer-protocol:failed;"),
    ("dcerpc", 'content:"|04 00|";'),
    ("telnet", 'content:"login";'),
    ("tcp", "app-layer-protocol:telnet;"),
    ("tcp", "app-layer-protocol:failed;"),
    ("tcp", "app-layer-protocol:http;"),
    ("dcerpc", 'flow:established,to_server; content:"AAAA";'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"windows {FIRST_SID + n}\"; {options})"


def tpkt(body):
    return b"\x03\x00" + (len(body) + 4).to_bytes(2, "big") + body


def x224(code, rest):
    return bytes([len(rest) + 6, code]) + b"\x00" * 5 + rest


# An X.224 connection request carrying a cookie and an RDP negotiation
# request, its confirm, and a data message.
CR = tpkt(x224(0xE0, b"Cookie: mstshash=user\r\n" + b"\x01\x00\x08\x00\x03\x00\x00\x00"))
CC = tpkt(x224(0xD0, b"\x02\x1f\x08\x00\x01\x00\x00\x00"))
DT = tpkt(b"\x02\xf0\x80" + b"again")


def nbss(body):
    return b"\x00" + len(body).to_bytes(3, "big") + body


KEEPALIVE = b"\x85\x00\x00\x00"
SMB2 = nbss(b"\xfeSMB" + b"\x40\x00" + b"\x00" * 58 + b"\x24\x00\x01\x00" + b"\x00" * 30 + b"\x02\x02")
SMB2_REPLY = nbss(b"\xfeSMB" + b"\x40\x00" + b"\x00" * 4 + b"\x00\x00\x01\x00" + b"\x00" * 52 + b"\x41\x00" + b"\x00" * 64)
SMB1 = nbss(b"\xffSMBr" + b"\x00" * 27 + b"\x00\x0c\x00\x02NT LM 0.12\x00")

IFACE = bytes.fromhex("c84f324b7016d30112785a47bf6ee188")
NDR = bytes.fromhex("045d888aeb1cc9119fe808002b104860")


def pdu(ptype, body, length=None, flags=3):
    length = 16 + len(body) if length is None else length
    return (
        b"\x05\x00" + bytes([ptype, flags]) + b"\x10\x00\x00\x00"
        + length.to_bytes(2, "little") + b"\x00\x00\x01\x00\x00\x00" + body
    )


BIND = pdu(11, b"\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00" + IFACE + b"\x03\x00\x00\x00" + NDR + b"\x02\x00\x00\x00")
BIND_ACK = pdu(12, b"\xb8\x10\xb8\x10\x12\x34\x00\x00\x04\x00135\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" + NDR + b"\x02\x00\x00\x00")
EMPTY_BIND_ACK = pdu(12, b"\x00" * 16)


def request(stub):
    return pdu(0, len(stub).to_bytes(4, "little") + b"\x00\x00\x1f\x00" + stub)


BARE = request(b"")


def datagram(ptype, size=80):
    return bytes([4, ptype]) + b"\x00" * (size - 2)


def conversations():
    out = []
    tcp, udp, talk = applayer.tcp_conversation, applayer.udp_conversation, applayer.talk
    # RDP: the connection request and confirm ask for inspection; a data
    # message does not, and neither does TLS once the connection moved to it.
    tcp(out, 1, 3389, talk([(">", CR), ("<", CC), (">", DT), ("<", b"zz")]))
    tcp(out, 2, 3389, talk([(">", CR[:2]), (">", CR[2:]), ("<", CC)]))
    tcp(out, 3, 3389, talk([(">", DT), ("<", b"zz"), (">", b"again")]))
    tcp(out, 4, 3389, talk([("<", CC), (">", CR)]))
    tcp(out, 5, 3389, talk([(">", CR), ("<", CC), (">", applayer.tls_hello(1)), ("<", applayer.tls_hello(2)), (">", b"again")]))
    tcp(out, 6, 13389, talk([(">", CR), ("<", CC)]))
    tcp(out, 7, 3389, talk([(">", b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), ("<", b"HTTP/1.1 200 OK\r\n\r\n")]))
    # SMB on its port and elsewhere, after keepalives, from either side.
    tcp(out, 8, 445, talk([(">", SMB2), ("<", SMB2_REPLY)]))
    tcp(out, 9, 4450, talk([(">", KEEPALIVE + SMB1), ("<", SMB2_REPLY)]))
    tcp(out, 10, 445, talk([(">", KEEPALIVE), (">", SMB2[:6]), (">", SMB2[6:]), ("<", SMB2_REPLY)]))
    tcp(out, 11, 445, talk([("<", SMB2_REPLY), (">", SMB2)]))
    tcp(out, 12, 445, talk([(">", SMB2 + BIND), ("<", SMB2_REPLY)]))
    # DCE/RPC over TCP: what asks and what waits for the close.
    tcp(out, 13, 135, talk([(">", BIND), ("<", BIND_ACK), (">", request(b"AAAA")), ("<", b"zz")]))
    tcp(out, 14, 1350, talk([(">", BARE), ("<", b"zz"), (">", BARE), ("<", b"zz")]))
    tcp(out, 15, 1350, talk([(">", BARE + BARE), ("<", b"zz")]))
    tcp(out, 16, 1350, talk([(">", BARE), ("<", b"zz"), (">", b"\x05"), ("<", b"zz")]))
    tcp(out, 17, 1350, talk([(">", request(b"AAAA")[:20]), ("<", b"zz"), (">", request(b"AAAA")[20:]), ("<", b"zz")]))
    tcp(out, 18, 1350, talk([("<", EMPTY_BIND_ACK), (">", b"q"), ("<", BIND_ACK), (">", b"q")]))
    tcp(out, 19, 1350, talk([(">", pdu(0, b"\x00" * 4, length=20)), ("<", b"zz"), (">", BARE + BARE), ("<", b"zz")]))
    tcp(out, 20, 1350, talk([(">", pdu(2, b"\x00" * 16)), ("<", b"zz"), (">", pdu(14, b"\x00" * 16)), ("<", b"zz")]))
    tcp(out, 21, 1350, talk([(">", pdu(0xFF, b"\x00" * 16) + BIND), ("<", b"zz")]))
    tcp(out, 22, 1350, talk([(">", b"\x05\x01" + b"\x00" * 30), ("<", b"zz" * 8)]))
    # DCE/RPC over UDP: a request with its whole header, on any port.
    udp(out, 23, 139, [(0.0, ">", datagram(0) + b"AAAA"), (0.01, "<", datagram(2))])
    udp(out, 24, 5000, [(0.0, ">", datagram(0, 79))])
    udp(out, 25, 5000, [(0.0, ">", datagram(2))])
    udp(out, 26, 5000, [(0.0, ">", datagram(9))])
    # Telnet: whatever is said on port 23, unless it names another protocol.
    tcp(out, 27, 23, talk([("<", b"login: "), (">", b"root\r\n")]))
    tcp(out, 28, 23, talk([(">", b"\xff\xfd\x18\xff\xfd\x20"), ("<", b"\xff\xfb\x18login: ")]))
    tcp(out, 29, 2323, talk([("<", b"login: " * 3), (">", b"root\r\n" * 4)]))
    tcp(out, 30, 23, talk([(">", b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), ("<", b"HTTP/1.1 200 OK\r\n\r\n")]))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("windows", "make-windows-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
