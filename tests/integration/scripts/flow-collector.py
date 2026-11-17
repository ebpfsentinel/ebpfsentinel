#!/usr/bin/env python3
"""A local collector for the flow export sinks, one port per format.

    --ipfix-port    IPFIX (RFC 7011) over UDP: templates are learned from the
                    template sets as they arrive and every data record is
                    decoded with the template it names, so a check reads
                    element values rather than offsets into a datagram
    --syslog-port   RFC 5424 over TCP, RFC 6587 octet counting
    --cef-port      RFC 5424 over UDP, one message per datagram

Each decoded record or message is appended to the log as one JSON object:

    {"channel": "ipfix", "template": 256, "domain": 0, "fields": {"8": "10.200.0.2", ...},
     "reverse": {"2": 3, ...}}
    {"channel": "ipfix-template", "template": 256, "elements": [[8, 4, 0], ...]}
    {"channel": "syslog", "pri": 134, "version": 1, "timestamp": "...", "hostname": "...",
     "app": "ebpfsentinel", "msgid": "flow", "sd": "-", "msg": "...", "kv": {...}}
    {"channel": "cef", ... same envelope ..., "cef": {"vendor": "...", ...}, "kv": {...}}

`fields` is keyed by IANA element id; elements under the RFC 5103 reverse
PEN go in `reverse`, under the same ids. Addresses are written as text,
integers as numbers.
"""

import argparse
import ipaddress
import json
import re
import socketserver
import struct
import threading

LOCK = threading.Lock()
REVERSE_PEN = 29305
ADDRESS_ELEMENTS = {8, 12, 27, 28}
KV = re.compile(r"(\w+)=(.*?)(?= \w+=|$)", re.S)
HEADER = re.compile(
    r"^<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\]) ?(.*)$", re.S
)


def record(log, entry):
    with LOCK, open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def unescape(value):
    return re.sub(r"\\(.)", r"\1", value)


def pairs(text):
    return {key: unescape(value) for key, value in KV.findall(text)}


def envelope(channel, raw):
    match = HEADER.match(raw.rstrip("\n"))
    if not match:
        return {"channel": channel, "unparsed": raw}
    pri, version, ts, host, app, procid, msgid, sd, msg = match.groups()
    entry = {"channel": channel, "pri": int(pri), "version": int(version), "timestamp": ts,
             "hostname": host, "app": app, "procid": procid, "msgid": msgid, "sd": sd,
             "msg": msg}
    if msg.startswith("CEF:"):
        # Seven unescaped pipes end the header; the extension follows.
        parts = re.split(r"(?<!\\)\|", msg, maxsplit=7)
        if len(parts) == 8:
            keys = ["version", "vendor", "product", "device_version", "signature",
                    "name", "severity"]
            entry["cef"] = dict(zip(keys, (unescape(part) for part in parts[:7])))
            entry["kv"] = pairs(parts[7])
    else:
        entry["kv"] = pairs(msg)
    return entry


# ── IPFIX ──────────────────────────────────────────────────────────────

TEMPLATES = {}


def decode_value(element, data):
    if element in ADDRESS_ELEMENTS:
        return str(ipaddress.ip_address(data))
    if len(data) <= 8:
        return int.from_bytes(data, "big")
    return data.hex()


def decode_ipfix(log, data):
    if len(data) < 16:
        return
    version, length, _export, _sequence, domain = struct.unpack("!HHIII", data[:16])
    if version != 10:
        record(log, {"channel": "ipfix-error", "error": f"version {version}"})
        return
    offset = 16
    end = min(length, len(data))
    while offset + 4 <= end:
        set_id, set_length = struct.unpack("!HH", data[offset:offset + 4])
        if set_length < 4:
            return
        body = data[offset + 4:offset + set_length]
        offset += set_length
        if set_id == 2:
            decode_templates(log, domain, body)
        elif set_id >= 256:
            decode_records(log, domain, set_id, body)


def decode_templates(log, domain, body):
    cursor = 0
    while cursor + 4 <= len(body):
        template, count = struct.unpack("!HH", body[cursor:cursor + 4])
        cursor += 4
        elements = []
        for _ in range(count):
            element, size = struct.unpack("!HH", body[cursor:cursor + 4])
            cursor += 4
            pen = 0
            if element & 0x8000:
                element &= 0x7FFF
                (pen,) = struct.unpack("!I", body[cursor:cursor + 4])
                cursor += 4
            elements.append((element, size, pen))
        TEMPLATES[(domain, template)] = elements
        record(log, {"channel": "ipfix-template", "domain": domain, "template": template,
                     "elements": elements})


def decode_records(log, domain, template, body):
    elements = TEMPLATES.get((domain, template))
    if elements is None:
        record(log, {"channel": "ipfix-error", "error": f"data before template {template}"})
        return
    cursor = 0
    while cursor < len(body):
        fields, reverse, extra = {}, {}, {}
        start = cursor
        for element, size, pen in elements:
            if size == 0xFFFF:
                size = body[cursor]
                cursor += 1
                if size == 255:
                    (size,) = struct.unpack("!H", body[cursor:cursor + 2])
                    cursor += 2
                value = body[cursor:cursor + size].decode("utf-8", "replace")
            else:
                if cursor + size > len(body):
                    return
                value = decode_value(element, body[cursor:cursor + size])
            cursor += size
            if pen == 0:
                fields[str(element)] = value
            elif pen == REVERSE_PEN:
                reverse[str(element)] = value
            else:
                extra[f"{pen}/{element}"] = value
        if cursor == start:
            return
        record(log, {"channel": "ipfix", "domain": domain, "template": template,
                     "fields": fields, "reverse": reverse, "private": extra})


class Udp(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class Tcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_ipfix(log):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            decode_ipfix(log, self.request[0])
    return Handler


def make_datagram_text(log, channel):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            record(log, envelope(channel, self.request[0].decode("utf-8", "replace")))
    return Handler


def make_octet_counted(log, channel):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                digits = b""
                while True:
                    byte = self.rfile.read(1)
                    if not byte:
                        return
                    if byte == b" ":
                        break
                    digits += byte
                if not digits.isdigit():
                    record(log, {"channel": f"{channel}-error",
                                 "error": f"not octet counted: {digits[:32]!r}"})
                    return
                message = self.rfile.read(int(digits))
                record(log, envelope(channel, message.decode("utf-8", "replace")))
    return Handler


def main():
    parser = argparse.ArgumentParser(description="Local IPFIX, syslog and CEF collector")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--ipfix-port", type=int, required=True)
    parser.add_argument("--syslog-port", type=int, required=True)
    parser.add_argument("--cef-port", type=int, required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    with open(args.log, "w", encoding="utf-8"):
        pass
    servers = [
        Udp((args.bind, args.ipfix_port), make_ipfix(args.log)),
        Tcp((args.bind, args.syslog_port), make_octet_counted(args.log, "syslog")),
        Udp((args.bind, args.cef_port), make_datagram_text(args.log, "cef")),
    ]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
