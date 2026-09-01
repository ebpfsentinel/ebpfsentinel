#!/usr/bin/env python3
"""Minimal OTLP/HTTP logs sink used by the alert-delivery integration suite.

Every accepted export is decoded and appended to the log file as one JSON
object per line:

    {"index": 1, "transport": "http", "path": "/v1/logs",
     "content_type": "application/x-protobuf", "length": 812,
     "resource": {"service.name": "ebpfsentinel", ...},
     "scope": "ebpfsentinel",
     "records": [{"severity_number": 17, "time_unix_seconds": 1756..., ...}]}

The raw body is deliberately not recorded: a test matching substrings inside
an encoded payload proves an export arrived and nothing more, while the
decoded record makes the resource, the severity and the clock assertable.
"""

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from otlp_decode import DecodeError, decode_export  # noqa: E402

LOG_LOCK = threading.Lock()

class OtlpSinkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log_path = None
    counter = 0

    def do_POST(self):  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        content_type = self.headers.get("Content-Type", "")

        try:
            export = decode_export(body, content_type)
            status = 200
        except (DecodeError, ValueError) as error:
            export = {"format": "undecodable", "error": str(error), "resource": {}, "scope": "", "records": []}
            status = 400

        with LOG_LOCK:
            OtlpSinkHandler.counter += 1
            entry = {
                "index": OtlpSinkHandler.counter,
                "transport": "http",
                "path": self.path,
                "content_type": content_type,
                "length": length,
            }
            entry.update(export)
            if self.log_path:
                with open(self.log_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry) + "\n")
                    handle.flush()

        self.send_response(status)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 - readiness probe for the test harness
        payload = json.dumps({"ready": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return

def main():
    parser = argparse.ArgumentParser(description="OTLP/HTTP logs sink")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18088)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    OtlpSinkHandler.log_path = args.log
    with open(args.log, "w", encoding="utf-8"):
        pass

    server = ThreadingHTTPServer((args.bind, args.port), OtlpSinkHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
