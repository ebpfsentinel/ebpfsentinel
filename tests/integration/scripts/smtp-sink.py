#!/usr/bin/env python3
"""Minimal SMTP sink used to assert outbound alert email delivery.

Speaks just enough SMTP for the agent's lettre transport configured with
`tls: false` (plain SMTP, no STARTTLS, no AUTH) and records every accepted
message as one JSON object per line:

    {"index": 1, "mail_from": "...", "rcpt_to": ["..."], "data": "..."}

No third-party dependency (aiosmtpd is not guaranteed on the test VM), so
this is a hand-rolled socket server. It intentionally advertises nothing in
its EHLO response: no STARTTLS, so the client cannot try to upgrade, and no
SIZE/8BITMIME, so no MAIL FROM parameters need parsing.

Usage:
    smtp-sink.py --bind 127.0.0.1 --port 18087 --log /tmp/mail.jsonl
"""

import argparse
import json
import socket
import sys
import threading

_LOCK = threading.Lock()
_STATE = {"seen": 0}


def _record(log_path: str, mail_from: str, rcpt_to: list, data: str) -> None:
    with _LOCK:
        _STATE["seen"] += 1
        entry = {
            "index": _STATE["seen"],
            "mail_from": mail_from,
            "rcpt_to": rcpt_to,
            "data": data,
        }
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
            fh.flush()


def _readline(fh) -> str:
    line = fh.readline()
    if not line:
        return ""
    return line.decode("utf-8", errors="replace").rstrip("\r\n")


def handle(conn: socket.socket, log_path: str) -> None:
    conn.settimeout(30)
    fh = conn.makefile("rb")

    def reply(text: str) -> None:
        conn.sendall((text + "\r\n").encode("utf-8"))

    reply("220 ebpfsentinel-test-sink ESMTP")

    mail_from = ""
    rcpt_to: list = []
    try:
        while True:
            line = _readline(fh)
            if not line:
                break
            upper = line.upper()

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                # Single-line: advertise no extension at all.
                reply("250 ebpfsentinel-test-sink")
            elif upper.startswith("MAIL FROM:"):
                mail_from = line[len("MAIL FROM:"):].strip().strip("<>")
                reply("250 2.1.0 Ok")
            elif upper.startswith("RCPT TO:"):
                rcpt_to.append(line[len("RCPT TO:"):].strip().strip("<>"))
                reply("250 2.1.5 Ok")
            elif upper == "DATA":
                reply("354 End data with <CR><LF>.<CR><LF>")
                chunks = []
                while True:
                    data_line = _readline(fh)
                    if data_line == ".":
                        break
                    if data_line == "" and not chunks:
                        # Connection dropped mid-DATA.
                        break
                    # Undo dot-stuffing.
                    chunks.append(data_line[1:] if data_line.startswith("..") else data_line)
                _record(log_path, mail_from, list(rcpt_to), "\n".join(chunks))
                mail_from = ""
                rcpt_to = []
                reply("250 2.0.0 Ok: queued")
            elif upper == "RSET":
                mail_from = ""
                rcpt_to = []
                reply("250 2.0.0 Ok")
            elif upper == "QUIT":
                reply("221 2.0.0 Bye")
                break
            elif upper == "NOOP":
                reply("250 2.0.0 Ok")
            else:
                # Be permissive: an unknown verb must not wedge the session.
                reply("250 2.0.0 Ok")
    except (TimeoutError, OSError):
        pass
    finally:
        try:
            fh.close()
            conn.close()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()

    with open(args.log, "w", encoding="utf-8"):
        pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(16)

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(
                target=handle, args=(conn, args.log), daemon=True
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
