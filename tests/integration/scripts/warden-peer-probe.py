#!/usr/bin/env python3
"""Probe the warden broker socket and report how the peer was treated.

The warden authenticates connections by SO_PEERCRED: a peer whose uid is
not the one it serves is accepted by the kernel and then dropped without
being served. From the client side the two outcomes are distinguishable:

    closed         the server hung up without sending anything (rejected)
    open           the connection stayed up past the timeout (served,
                   waiting for a request frame)
    connect-failed the socket could not be connected at all
    data           the server sent unsolicited bytes (unexpected)

Usage:
    warden-peer-probe.py <socket_path> [timeout_secs]
"""

import socket
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: warden-peer-probe.py <socket_path> [timeout_secs]",
              file=sys.stderr)
        return 2
    path = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except OSError as exc:
        print(f"connect-failed:{exc.errno}")
        return 0

    try:
        data = sock.recv(1)
    except socket.timeout:
        print("open")
        return 0
    except OSError:
        print("closed")
        return 0
    finally:
        sock.close()

    print("closed" if data == b"" else "data")
    return 0


if __name__ == "__main__":
    sys.exit(main())
