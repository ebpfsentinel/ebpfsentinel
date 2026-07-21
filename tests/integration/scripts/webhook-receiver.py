#!/usr/bin/env python3
"""Minimal HTTP sink used to assert outbound alert delivery.

Records every request it receives as one JSON object per line so a bats
suite can assert on method, path, headers and body without parsing an
HTTP server log. Optionally answers the first N requests with HTTP 500 so
the agent's retry path can be exercised.

Usage:
    webhook-receiver.py --bind 203.0.113.10 --port 18080 \
        --log /tmp/hook.jsonl [--fail-first 1]

The bind address matters: the agent's webhook sender refuses to connect to
loopback/private/link-local addresses (SSRF guard, shared with the feed
fetcher), so the sink must live on a routable-looking address. TEST-NET-3
(203.0.113.0/24) is neither private nor loopback and is safe to assign to a
dummy interface.
"""

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LOCK = threading.Lock()


def build_handler(log_path: str, fail_first: int):
    state = {"seen": 0}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _record(self, body: bytes) -> int:
            with _LOCK:
                state["seen"] += 1
                index = state["seen"]
                entry = {
                    "index": index,
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body.decode("utf-8", errors="replace"),
                }
                with open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
                    fh.flush()
            return index

        def do_POST(self):  # noqa: N802 — BaseHTTPRequestHandler API
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            index = self._record(body)

            # Answer the first `fail_first` requests with 500 so the sender
            # retries; everything after that succeeds.
            status = 500 if index <= fail_first else 200
            payload = b'{"ok":true}' if status == 200 else b'{"error":"forced"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802 — readiness probe for the suite
            payload = b'{"ready":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):  # silence stderr noise
            return

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--fail-first", type=int, default=0)
    args = ap.parse_args()

    # Truncate so a re-run never inherits a previous run's deliveries.
    with open(args.log, "w", encoding="utf-8"):
        pass

    server = ThreadingHTTPServer(
        (args.bind, args.port), build_handler(args.log, args.fail_first)
    )
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
