"""Ask the warden for a route, as the agent would, and print how it answered.

Says `Hello` at protocol version 3, then sends one `RouteAdd` frame (a u32 little-endian length, then the postcard
encoding of the command) for the default route through <gateway> on <iface>,
and prints the answer's kind:

    refused  the warden's policy refused the command
    ok       the warden installed the route
    error    the warden tried and the kernel refused
    other:N  any other answer, by its tag

The bytes are pinned by a unit test in crates/warden-proto
(`the_integration_probe_speaks_the_wire_format`), so a change to the wire
format fails there before it fails here.

Usage:
    warden-route-probe.py <socket_path> <gateway> <iface>
"""

import socket
import struct
import sys

HELLO = 0
PROTOCOL_VERSION = 3
ROUTE_ADD = 5
OK = 6
ERROR = 8
REFUSED = 31


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def text(s: str) -> bytes:
    raw = s.encode()
    return varint(len(raw)) + raw


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("the warden closed the connection")
        buf += chunk
    return buf


def exchange(sock: socket.socket, body: bytes) -> bytes:
    sock.sendall(struct.pack("<I", len(body)) + body)
    (length,) = struct.unpack("<I", recv_exact(sock, 4))
    return recv_exact(sock, length)


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    path, gateway, iface = sys.argv[1:]
    body = (varint(ROUTE_ADD) + text("0.0.0.0/0") + text(gateway)
            + text(iface) + varint(254))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(path)
    greeting = exchange(sock, varint(HELLO) + varint(PROTOCOL_VERSION))
    if not greeting or greeting[0] != 0:
        print(f"hello-refused:{greeting[:1].hex()}")
        return 0
    answer = exchange(sock, body)
    sock.close()
    tag = answer[0] if answer else -1
    print({REFUSED: "refused", OK: "ok", ERROR: "error"}.get(tag, f"other:{tag}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
