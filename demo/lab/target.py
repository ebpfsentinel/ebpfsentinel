#!/usr/bin/env python3
"""The protected service: answers HTTP on port 80 and HTTPS on port 443.

It runs on the host network and binds the lab bridge's address only, so the
attacker and the app reach it across the interface the agent watches. The
certificate is generated at start-up and is self-signed: the demo is about
what crosses the wire, not about who the server is.
"""

import http.server
import os
import ssl
import subprocess
import sys
import threading

BIND = os.environ.get("TARGET_ADDRESS", "172.30.66.1")
CERT = "/tmp/target.pem"


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "demo-target"

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = b'{"status":"ok"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (self.client_address[0], fmt % args))
        sys.stdout.flush()


def serve(port, tls):
    server = http.server.ThreadingHTTPServer((BIND, port), Handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print("listening on %s:%d (%s)" % (BIND, port, "https" if tls else "http"), flush=True)
    server.serve_forever()


def main():
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-subj", "/CN=demo-target",
            "-keyout", CERT, "-out", CERT,
        ],
        check=True,
        capture_output=True,
    )
    threading.Thread(target=serve, args=(80, False), daemon=True).start()
    serve(443, True)


if __name__ == "__main__":
    main()
