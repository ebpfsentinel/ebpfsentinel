"""Run the DCE/RPC rules below over crafted conversations through a real Suricata.

The conversations carry DCE/RPC straight over TCP, in named pipes over SMB2
and SMB1 (writes, reads and pipe transactions), and over UDP. They bind an
interface and call it, bind it and see it refused, call another context than
the one bound, call without a bind, split a call in fragments or across
segments, sign a call, and write a bind on a disk share, so what alerts says
when Suricata holds a call to be on an interface, an operation number and a
stub.

The PDUs follow the DCE 1.1 RPC specification (C706) and the SMB framing
[MS-SMB2] and [MS-CIFS]; nothing here is taken from Suricata.

Writes dcerpc-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import os
import struct
import uuid
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 13000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

SRVSVC = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
OTHER = "12345778-1234-abcd-ef00-0123456789ac"
NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le + struct.pack("<I", 2)

RULES = [
    ("tcp", f"dcerpc.iface:{SRVSVC};"),
    ("tcp", f"dcerpc.iface:{SRVSVC}; dcerpc.opnum:31;"),
    ("tcp", f'dcerpc.iface:{SRVSVC}; dcerpc.opnum:31; dcerpc.stub_data; content:"../";'),
    ("tcp", f'flow:established,to_server; content:"|0B|"; offset:2; depth:1; dcerpc.iface:{SRVSVC};'),
    ("tcp", "dcerpc.opnum:31;"),
    ("tcp", 'dcerpc.stub_data; content:"STUBX";'),
    ("tcp", f"dcerpc.iface:{SRVSVC},=3;"),
    ("tcp", f"dcerpc.iface:{SRVSVC},>3;"),
    ("tcp", f"dcerpc.iface:{SRVSVC},any_frag;"),
    ("tcp", f"dcerpc.iface:{OTHER};"),
    ("udp", f'dcerpc.iface:{SRVSVC}; dcerpc.opnum:31; dcerpc.stub_data; content:"../";'),
    ("smb", f"dcerpc.iface:{SRVSVC};"),
    ("dcerpc", f"dcerpc.iface:{SRVSVC};"),
    ("tcp", 'flow:to_client; dcerpc.stub_data; content:"RESPX";'),
    ("tcp", "dcerpc.opnum:30-32;"),
    ("tcp", "dcerpc.opnum:5,31;"),
    ("tcp", 'dcerpc.stub_data; content:"AB"; content:"CD"; distance:0;'),
    ("tcp", f'dcerpc.iface:{SRVSVC}; dcerpc.stub_data; content:!"zzz";'),
    ("udp", f"dcerpc.iface:{SRVSVC};"),
    ("udp", 'dcerpc.stub_data; content:"STUBX";'),
    ("tcp", 'dcerpc.stub_data; content:"SIGNED"; isdataat:!1,relative;'),
    ("tcp", f'dcerpc.iface:{SRVSVC}; content:"STUBX";'),
    ("tcp", "dcerpc.opnum:7;"),
    ("tcp", 'dcerpc.stub_data; content:"STUBX"; depth:5;'),
    ("udp", "dcerpc.opnum:31;"),
    ("tcp", 'dcerpc.stub_data; content:"VERIFIER"; isdataat:!1,relative;'),
    ("tcp", 'dcerpc.stub_data; content:"SIGNED"; content:"|0a 06|"; distance:0;'),
    ("udp", 'flow:to_client; dcerpc.stub_data; content:"RESPX";'),
    ("udp", f"dcerpc.iface:{OTHER};"),
    ("tcp", 'flow:to_client; dcerpc.stub_data; content:"SEVENRESP";'),
    ("tcp", 'dcerpc.opnum:7; flow:to_client; dcerpc.stub_data; content:"RESP";'),
    ("tcp", 'dcerpc.opnum:31; flow:to_client; dcerpc.stub_data; content:"SEVENRESP";'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"dcerpc {FIRST_SID + n}\"; {options})"


# DCE/RPC connection oriented PDUs, little endian, NDR.

BIND, BIND_ACK, ALTER, ALTER_RESP, REQUEST, RESPONSE = 11, 12, 14, 15, 0, 2
FIRST, LAST = 1, 2


def co(ptype, body, call=1, flags=FIRST | LAST, auth=b"", big=False):
    length = 16 + len(body) + len(auth)
    auth_len = len(auth) - 8 if auth else 0
    rep = b"\0\0\0\0" if big else b"\x10\0\0\0"
    head = struct.pack("BBBB4s", 5, 0, ptype, flags, rep)
    return head + struct.pack(">HHI" if big else "<HHI", length, auth_len, call) + body + auth


def bind(contexts, call=1, ptype=BIND):
    """`contexts` holds (context id, interface, major, minor)."""
    body = struct.pack("<HHIB3x", 4280, 4280, 0, len(contexts))
    for ctx, iface, major, minor in contexts:
        body += struct.pack("<HBx", ctx, 1) + uuid.UUID(iface).bytes_le + struct.pack("<HH", major, minor) + NDR
    return co(ptype, body, call)


def bind_ack(results, call=1, ptype=BIND_ACK, address=b"\\PIPE\\srvsvc\0"):
    """`results` holds the result of each context, 0 accepted, 2 refused."""
    body = struct.pack("<HHIH", 4280, 4280, 0x1234, len(address)) + address
    while (16 + len(body)) % 4:
        body += b"\0"
    body += struct.pack("<B3x", len(results))
    for result in results:
        body += struct.pack("<HH", result, 0) + (NDR if result == 0 else b"\0" * 20)
    return co(ptype, body, call)


def request(ctx, opnum, stub, call=2, flags=FIRST | LAST, auth=b"", big=False):
    head = struct.pack(">IHH" if big else "<IHH", len(stub), ctx, opnum)
    return co(REQUEST, head + stub, call, flags, auth, big)


def response(ctx, stub, call=2):
    return co(RESPONSE, struct.pack("<IHBx", len(stub), ctx, 0) + stub, call)


STUB = b"\\\\SRV\0..\\..\\STUBX ../x\0"
CALL = request(0, 31, STUB)
ANSWER = response(0, b"RESPX\0\0\0")


def cl_request(iface, opnum, stub, version=3, ptype=0):
    """A connectionless request, version 4 of the protocol, or with `ptype`
    2 its response."""
    head = struct.pack("<BBBB3sB", 4, ptype, 0x08, 0, b"\x10\0\0", 0)
    head += b"\0" * 16 + uuid.UUID(iface).bytes_le + uuid.UUID(int=7).bytes_le
    head += struct.pack("<IIIHHHHHBB", 0, version, 1, opnum, 0xFFFF, 0xFFFF, len(stub), 0, 0, 0)
    return head + stub


# SMB2 [MS-SMB2] 2.2.

TREE_CONNECT, CREATE, READ, WRITE, IOCTL = 3, 5, 8, 9, 11
FID = bytes(range(1, 17))


def nb(message):
    return struct.pack("!I", len(message)) + message


def smb2(command, body, mid, reply=False, tree=0):
    flags = 1 if reply else 0
    head = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ16s", 64, 0, 0, command, 1, flags, 0, mid, 0xFEFF, tree, 0x77, b"")
    return nb(head + body)


def utf16(text):
    return text.encode("utf-16-le")


def tree_connect(mid, share):
    path = utf16("\\\\srv\\" + share)
    return smb2(TREE_CONNECT, struct.pack("<HHHH", 9, 0, 72, len(path)) + path, mid)


def tree_connected(mid, tree, pipe):
    return smb2(TREE_CONNECT, struct.pack("<HBBIII", 16, 2 if pipe else 1, 0, 0, 0, 0x1F01FF), mid, True, tree)


def create(mid, tree, name):
    raw = utf16(name)
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x12019F, 0, 7, 1, 0x40, 120, len(raw), 0, 0)
    return smb2(CREATE, body + raw, mid, tree=tree)


def created(mid, tree):
    body = struct.pack("<HBBIQQQQQQII16sII", 89, 0, 0, 1, 0, 0, 0, 0, 4096, 0, 0x80, 0, FID, 0, 0) + b"\0"
    return smb2(CREATE, body, mid, True, tree)


def write(mid, tree, data):
    body = struct.pack("<HHIQ16sIIHHI", 49, 112, len(data), 0, FID, 0, 0, 0, 0, 0)
    return smb2(WRITE, body + data, mid, tree=tree)


def written(mid, tree, count):
    return smb2(WRITE, struct.pack("<HHIIHH", 17, 0, count, 0, 0, 0) + b"\0", mid, True, tree)


def read(mid, tree):
    body = struct.pack("<HBBIQ16sIIIHH", 49, 0x50, 0, 4280, 0, FID, 0, 0, 0, 0, 0) + b"\0"
    return smb2(READ, body, mid, tree=tree)


def read_back(mid, tree, data):
    return smb2(READ, struct.pack("<HBBIII", 17, 80, 0, len(data), 0, 0) + data, mid, True, tree)


def ioctl(mid, tree, data):
    body = struct.pack("<HHI16sIIIIIIII", 57, 0, 0x11C017, FID, 120, len(data), 0, 120, 0, 4280, 1, 0)
    return smb2(IOCTL, body + data, mid, tree=tree)


def ioctl_back(mid, tree, data):
    body = struct.pack("<HHI16sIIIIII", 49, 0, 0x11C017, FID, 112, 0, 112, len(data), 0, 0)
    return smb2(IOCTL, body + data, mid, True, tree)


def smb2_session(share, pipe, bind_pdu, ack_pdu, call_pdu, answer_pdu, by_ioctl=True):
    tree = 5
    out = [
        (">", tree_connect(1, share)),
        ("<", tree_connected(1, tree, pipe)),
        (">", create(2, tree, "srvsvc")),
        ("<", created(2, tree)),
        (">", write(3, tree, bind_pdu)),
        ("<", written(3, tree, len(bind_pdu))),
        (">", read(4, tree)),
        ("<", read_back(4, tree, ack_pdu)),
    ]
    if by_ioctl:
        out += [(">", ioctl(5, tree, call_pdu)), ("<", ioctl_back(5, tree, answer_pdu))]
    else:
        out += [
            (">", write(5, tree, call_pdu)),
            ("<", written(5, tree, len(call_pdu))),
            (">", read(6, tree)),
            ("<", read_back(6, tree, answer_pdu)),
        ]
    return out


# SMB1 [MS-CIFS] 2.2.

TREE_CONNECT_ANDX, NT_CREATE_ANDX, READ_ANDX, WRITE_ANDX, TRANS = 0x75, 0xA2, 0x2E, 0x2F, 0x25
FID1 = 0x4000


def smb1(command, words, data, reply=False, tid=0, mid=1):
    flags = 0x98 if reply else 0x18
    head = b"\xffSMB" + struct.pack("<BIBHH8sHHHHH", command, 0, flags, 0x4001, 0, b"", 0, tid, 0xFEFF, 0x64, mid)
    return nb(head + struct.pack("<B", len(words) // 2) + words + struct.pack("<H", len(data)) + data)


def tree_connect1(mid):
    data = b"\0" + b"\\\\SRV\\IPC$\0" + b"?????\0"
    return smb1(TREE_CONNECT_ANDX, struct.pack("<BBHHH", 0xFF, 0, 0, 0, 1), data, mid=mid)


def tree_connected1(mid, tid, service=b"IPC"):
    return smb1(TREE_CONNECT_ANDX, struct.pack("<BBHH", 0xFF, 0, 0, 1), service + b"\0\0", True, tid, mid)


def create1(mid, tid, name):
    raw = name.encode() + b"\0"
    words = struct.pack("<BBHBHIIIQIIIIIB", 0xFF, 0, 0, 0, len(raw) - 1, 0, 0, 0x2019F, 0, 0, 3, 1, 0, 2, 0)
    return smb1(NT_CREATE_ANDX, words, raw, tid=tid, mid=mid)


def created1(mid, tid):
    words = struct.pack("<BBHBHI32sIQQHHB", 0xFF, 0, 0, 0, FID1, 1, b"", 0x80, 4096, 0, 2, 0x5FF, 0)
    return smb1(NT_CREATE_ANDX, words, b"", True, tid, mid)


def write1(mid, tid, data):
    words = struct.pack("<BBHHIIHHHHHI", 0xFF, 0, 0, FID1, 0, 0, 0x08, len(data), 0, len(data), 64, 0)
    return smb1(WRITE_ANDX, words, b"\0" + data, tid=tid, mid=mid)


def written1(mid, tid, count):
    return smb1(WRITE_ANDX, struct.pack("<BBHHHHH", 0xFF, 0, 0, count, 0xFFFF, 0, 0), b"", True, tid, mid)


def read1(mid, tid):
    words = struct.pack("<BBHHIHHIHI", 0xFF, 0, 0, FID1, 0, 4280, 4280, 0, 4280, 0)
    return smb1(READ_ANDX, words, b"", tid=tid, mid=mid)


def read_back1(mid, tid, data):
    words = struct.pack("<BBHHHHHHH8s", 0xFF, 0, 0, 0xFFFF, 0, 0, len(data), 60, 0, b"")
    return smb1(READ_ANDX, words, b"\0" + data, True, tid, mid)


def trans1(mid, tid, data):
    name = b"\\PIPE\\\0"
    offset = 32 + 1 + 32 + 2 + len(name)
    words = struct.pack("<HHHHBBHIHHHHHBBHH", 0, len(data), 0, 4280, 0, 0, 0, 0, 0, 0, offset, len(data), offset, 2, 0, 0x26, FID1)
    return smb1(TRANS, words, name + data, tid=tid, mid=mid)


def trans_back1(mid, tid, data):
    offset = 32 + 1 + 20 + 2 + 1
    words = struct.pack("<HHHHHHHHHBB", 0, len(data), 0, 0, offset, 0, len(data), offset, 0, 0, 0)
    return smb1(TRANS, words, b"\0" + data, True, tid, mid)


def conversations():
    out = []
    talk, tcp, udp = applayer.talk, applayer.tcp_conversation, applayer.udp_conversation
    bound = bind([(0, SRVSVC, 3, 0)])
    ack = bind_ack([0])
    # Straight over TCP: bind, accepted, call, answer.
    tcp(out, 1, 135, talk([(">", bound), ("<", ack), (">", CALL), ("<", ANSWER)]))
    # The bind refused.
    tcp(out, 2, 135, talk([(">", bound), ("<", bind_ack([2])), (">", CALL), ("<", ANSWER)]))
    # Two contexts, the call on the one bound to another interface.
    both = bind([(0, OTHER, 1, 0), (1, SRVSVC, 3, 0)])
    tcp(out, 3, 135, talk([(">", both), ("<", bind_ack([0, 0])), (">", CALL), ("<", ANSWER)]))
    # A call without a bind.
    tcp(out, 4, 135, talk([(">", CALL), ("<", ANSWER)]))
    # A call in two fragments, each in its segment.
    first = request(0, 31, b"..AB", flags=FIRST)
    last = request(0, 31, b"CD/STUBX", flags=LAST)
    tcp(out, 5, 135, talk([(">", bound), ("<", ack), (">", first), (">", last), ("<", ANSWER)]))
    # A call split across two segments.
    cut = len(CALL) // 2
    tcp(out, 6, 135, talk([(">", bound), ("<", ack), (">", CALL[:cut]), (">", CALL[cut:]), ("<", ANSWER)]))
    # SMB2 on IPC$: bind written and read back, the call through the pipe's
    # transaction, then through a write and a read.
    tcp(out, 7, 445, talk(smb2_session("IPC$", True, bound, ack, CALL, ANSWER)))
    tcp(out, 8, 445, talk(smb2_session("IPC$", True, bound, ack, CALL, ANSWER, by_ioctl=False)))
    # SMB1 over NetBIOS on IPC$: session request, bind written and read back,
    # the call through a pipe transaction.
    tid = 0x800
    smb1_talk = [
        (">", b"\x81\0\0\x44" + b" " * 0x44),
        ("<", b"\x82\0\0\0"),
        (">", tree_connect1(1)),
        ("<", tree_connected1(1, tid)),
        (">", create1(2, tid, "\\srvsvc")),
        ("<", created1(2, tid)),
        (">", write1(3, tid, bound)),
        ("<", written1(3, tid, len(bound))),
        (">", read1(4, tid)),
        ("<", read_back1(4, tid, ack)),
        (">", trans1(5, tid, CALL)),
        ("<", trans_back1(5, tid, ANSWER)),
    ]
    tcp(out, 9, 139, talk(smb1_talk))
    smb1_disk = list(smb1_talk)
    smb1_disk[3] = ("<", tree_connected1(1, tid, b"A:"))
    # SMB2 on a disk share: the same bytes written to a file.
    tcp(out, 10, 445, talk(smb2_session("data", False, bound, ack, CALL, ANSWER, by_ioctl=False)))
    # Over UDP, the interface in each request.
    udp(out, 11, 139, [(0.1, ">", cl_request(SRVSVC, 31, STUB))])
    udp(out, 12, 135, [(0.1, ">", cl_request(OTHER, 31, STUB))])
    # The interface added by an alter context after a bind to another.
    other = bind([(0, OTHER, 1, 0)])
    alter = bind([(1, SRVSVC, 3, 0)], call=2, ptype=ALTER)
    altered = bind_ack([0], call=2, ptype=ALTER_RESP, address=b"\0")
    on_one = request(1, 31, STUB, call=3)
    tcp(out, 13, 135, talk([(">", other), ("<", bind_ack([0])), (">", alter), ("<", altered), (">", on_one), ("<", response(1, b"RESPX", 3))]))
    # A signed call: the stub runs to the end of the PDU, the verifier
    # included.
    signed = request(0, 31, b"..SIGNED", auth=struct.pack("<BBBBI", 10, 6, 0, 0, 1) + b"VERIFIER")
    tcp(out, 14, 135, talk([(">", bound), ("<", ack), (">", signed), ("<", ANSWER)]))
    seven = request(0, 7, b"SEVEN", call=3)
    # Bind and call in the same segment.
    tcp(out, 16, 135, talk([(">", bound + CALL), ("<", ack + ANSWER)]))
    # A middle fragment alone, then a last fragment alone.
    tcp(out, 17, 135, talk([(">", bound), ("<", ack), (">", request(0, 31, STUB, flags=0)), ("<", ANSWER)]))
    tcp(out, 18, 135, talk([(">", bound), ("<", ack), (">", request(0, 31, STUB, flags=LAST)), ("<", ANSWER)]))
    # Over UDP, a request and its response.
    udp(out, 19, 4000, [(0.1, ">", cl_request(SRVSVC, 31, STUB)), (0.2, "<", cl_request(SRVSVC, 31, b"RESPX", ptype=2))])
    # A call in big endian after a little endian bind.
    tcp(out, 20, 135, talk([(">", bound), ("<", ack), (">", request(0, 31, STUB, big=True)), ("<", ANSWER)]))
    # SMB2: IPC$ answered as a disk share, a disk name answered as a pipe
    # share, and no tree connect seen.
    tcp(out, 21, 445, talk(smb2_session("IPC$", False, bound, ack, CALL, ANSWER)))
    tcp(out, 22, 445, talk(smb2_session("data", True, bound, ack, CALL, ANSWER)))
    tcp(out, 23, 445, talk(smb2_session("IPC$", True, bound, ack, CALL, ANSWER)[2:]))
    tcp(out, 24, 445, talk(smb2_session("IPC$", True, bound, ack, CALL, ANSWER)[4:]))
    # Two calls in one segment, their responses in two, or the second alone.
    seven_back = response(0, b"SEVENRESP", 3)
    tcp(out, 25, 135, talk([(">", bound), ("<", ack), (">", CALL + seven), ("<", ANSWER), ("<", seven_back)]))
    # SMB1 on a tree answered as a disk.
    tcp(out, 26, 139, talk(smb1_disk))
    tcp(out, 27, 135, talk([(">", bound), ("<", ack), (">", CALL + seven), ("<", seven_back)]))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("dcerpc", "make-dcerpc-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
