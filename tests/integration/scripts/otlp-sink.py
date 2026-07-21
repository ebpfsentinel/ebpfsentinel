#!/usr/bin/env python3
"""Minimal OTLP/HTTP sink used to assert alert export over OpenTelemetry.

The agent's OTLP sender batches alerts through the OpenTelemetry SDK and
POSTs them to `<endpoint>/v1/logs` as protobuf. Decoding protobuf would
need a dependency, so this sink records the raw body decoded permissively:
the serialized alert JSON travels inside the payload as a length-prefixed
string, which makes a substring assertion (on the rule id, say) both simple
and sufficient to prove the export reached the collector.

Every request is recorded as one JSON object per line:

    {"index": 1, "path": "/v1/logs", "content_type": "application/x-protobuf",
     "length": 512, "body_text": "..."}

The response is an empty 200 with `application/x-protobuf`, which the SDK
accepts as a successful export (an empty ExportLogsServiceResponse).

Usage:
    otlp-sink.py --bind 127.0.0.1 --port 18088 --log /tmp/otlp.jsonl
"""

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LOCK = threading.Lock()


def build_handler(log_path: str):
    state = {"seen": 0}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):  # noqa: N802 — BaseHTTPRequestHandler API
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""

            with _LOCK:
                state["seen"] += 1
                entry = {
                    "index": state["seen"],
                    "path": self.path,
                    "content_type": self.headers.get("Content-Type", ""),
                    "length": len(body),
                    "body_text": body.decode("utf-8", errors="replace"),
                }
                with open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
                    fh.flush()

            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.end_headers()

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
    args = ap.parse_args()

    with open(args.log, "w", encoding="utf-8"):
        pass

    server = ThreadingHTTPServer((args.bind, args.port), build_handler(args.log))
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
