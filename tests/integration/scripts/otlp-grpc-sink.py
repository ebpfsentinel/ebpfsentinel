#!/usr/bin/env python3
"""Minimal OTLP/gRPC logs sink used by the alert-delivery integration suite.

gRPC is the agent's documented default transport, so it needs a lane of its
own: an HTTP sink can only prove the fallback works. Rather than pull a gRPC
stack into the test image, this speaks the small slice of HTTP/2 cleartext an
exporter actually uses - the connection preface, a SETTINGS exchange, request
HEADERS whose HPACK block is skipped because nothing here needs to read it,
DATA frames carrying the gRPC length-prefixed message, then a response of
HEADERS, one empty message and END_STREAM trailers carrying grpc-status 0.

Each decoded export is appended to the log file in the same shape the HTTP
sink writes, with the transport named, so one set of assertions covers both.
"""

import argparse
import json
import os
import socket
import socketserver
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from otlp_decode import DecodeError, decode_export  # noqa: E402

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8

FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4

# ":status: 200" as a static-table index, then "content-type" by static name
# with a literal value, which is all a gRPC client needs off the response.
RESPONSE_HEADERS = b"\x88" + b"\x0f\x10" + bytes([len(b"application/grpc")]) + b"application/grpc"
# "grpc-status: 0" as a literal header with a new name.
RESPONSE_TRAILERS = b"\x00" + bytes([len(b"grpc-status")]) + b"grpc-status" + b"\x01" + b"0"
EMPTY_MESSAGE = b"\x00\x00\x00\x00\x00"

LOG_LOCK = threading.Lock()

class SinkState:
    log_path = None
    counter = 0

def record(export, length):
    with LOG_LOCK:
        SinkState.counter += 1
        entry = {
            "index": SinkState.counter,
            "transport": "grpc",
            "path": "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
            "content_type": "application/grpc",
            "length": length,
        }
        entry.update(export)
        if SinkState.log_path:
            with open(SinkState.log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()

def frame(frame_type, flags, stream_id, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([frame_type, flags]) + struct.pack(">I", stream_id) + payload

class Http2Handler(socketserver.BaseRequestHandler):
    def handle(self):
        connection = self.request
        connection.settimeout(30)
        try:
            self._serve(connection)
        except (OSError, socket.timeout, DecodeError):
            return

    def _read_exactly(self, connection, count):
        buf = b""
        while len(buf) < count:
            chunk = connection.recv(count - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _serve(self, connection):
        if self._read_exactly(connection, len(PREFACE)) != PREFACE:
            return
        connection.sendall(frame(FRAME_SETTINGS, 0, 0))

        streams = {}
        while True:
            header = self._read_exactly(connection, 9)
            if header is None:
                return
            length = int.from_bytes(header[0:3], "big")
            frame_type = header[3]
            flags = header[4]
            stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            payload = self._read_exactly(connection, length) if length else b""
            if payload is None:
                return

            if frame_type == FRAME_SETTINGS:
                if not flags & FLAG_ACK:
                    connection.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0))
            elif frame_type == FRAME_PING:
                if not flags & FLAG_ACK:
                    connection.sendall(frame(FRAME_PING, FLAG_ACK, 0, payload))
            elif frame_type == FRAME_HEADERS:
                streams.setdefault(stream_id, b"")
            elif frame_type == FRAME_DATA:
                streams[stream_id] = streams.get(stream_id, b"") + payload
                if length:
                    connection.sendall(frame(FRAME_WINDOW_UPDATE, 0, 0, struct.pack(">I", length)))
                    connection.sendall(frame(FRAME_WINDOW_UPDATE, 0, stream_id, struct.pack(">I", length)))
                if flags & FLAG_END_STREAM:
                    self._respond(connection, stream_id, streams.pop(stream_id, b""))
            elif frame_type == FRAME_RST_STREAM:
                streams.pop(stream_id, None)
            elif frame_type == FRAME_GOAWAY:
                return

    def _respond(self, connection, stream_id, body):
        offset = 0
        while offset + 5 <= len(body):
            message_length = int.from_bytes(body[offset + 1:offset + 5], "big")
            message = body[offset + 5:offset + 5 + message_length]
            offset += 5 + message_length
            try:
                export = decode_export(message, "application/grpc")
            except (DecodeError, ValueError) as error:
                export = {"format": "undecodable", "error": str(error), "resource": {}, "scope": "", "records": []}
            record(export, message_length)

        connection.sendall(frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, RESPONSE_HEADERS))
        connection.sendall(frame(FRAME_DATA, 0, stream_id, EMPTY_MESSAGE))
        connection.sendall(
            frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream_id, RESPONSE_TRAILERS)
        )

class Http2Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    parser = argparse.ArgumentParser(description="OTLP/gRPC logs sink")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18089)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    SinkState.log_path = args.log
    with open(args.log, "w", encoding="utf-8"):
        pass

    server = Http2Server((args.bind, args.port), Http2Handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
