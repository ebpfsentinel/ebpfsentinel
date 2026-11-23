"""Run the HTTP rules below, each reading an HTTP buffer beside a content on
the payload, over crafted HTTP/1 conversations through a real Suricata.

The payload content sits in the message the buffer comes from, in the other
direction, in an earlier message of the same connection, in a later segment
than the header or split across two, so what alerts says which bytes Suricata
reads a payload content on when the rule also reads a transaction, and on
which packet.

Writes http-payload-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import gzip
import os
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 12000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("http", 'content:"PAYREQ"; http.method; content:"POST";'),
    ("http", 'content:"Host|3a|"; http.uri; content:"/p";'),
    ("http", 'flow:to_client; content:"PAYRSP"; http.stat_code; content:"200";'),
    ("http", 'content:"PAYRSP"; http.method; content:"POST";'),
    ("http", 'content:"POST"; depth:4; http.uri; content:"/p";'),
    ("http", 'content:"PAYREQ"; http.uri; content:"/p";'),
    ("http", 'content:"gzip"; http.response_body; content:"secret";'),
    ("http", 'content:"OLDREQ"; http.uri; content:"/second";'),
    ("http", 'http.method; content:"POST"; pkt_data; content:"PAYREQ";'),
    ("http", 'content:"PAYREQ"; content:"LATER"; distance:0; http.uri; content:"/p";'),
    ("tcp", 'content:"PAYREQ"; http.uri; content:"/p";'),
    ("http", 'flow:to_server; content:"PAYREQ"; http.header; content:"Host";'),
    ("http", 'content:"PAYREQ"; http.request_body; content:"LATER";'),
    ("http", 'content:!"NOPE"; http.uri; content:"/p";'),
    ("http", 'content:"PAYRSP"; http.stat_code; content:"200";'),
    ("http", 'http.uri; content:"/p";'),
    ("http", 'content:"PAYREQ";'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"http payload {FIRST_SID + n}\"; {options})"


def message(line, *headers, body=b""):
    return line + b"\r\n" + b"".join(h + b"\r\n" for h in headers) + b"\r\n" + body


def length(body):
    return f"Content-Length: {len(body)}".encode()


OK = message(b"HTTP/1.1 200 OK", length(b"PAYRSP"), body=b"PAYRSP")
EMPTY = message(b"HTTP/1.1 200 OK", b"Content-Length: 0")


def conversations():
    out = []
    talk, tcp = applayer.talk, applayer.tcp_conversation
    post = message(b"POST /p HTTP/1.1", b"Host: a", length(b"PAYREQ"), body=b"PAYREQ")
    # The payload content in the request the buffer comes from, in one packet.
    tcp(out, 1, 80, talk([(">", post), ("<", OK)]))
    # The body, with the payload content, a segment after the header.
    head, body = post[: -len(b"PAYREQ")], b"PAYREQ"
    tcp(out, 2, 80, talk([(">", head), (">", body), ("<", OK)]))
    # Keep-alive: the payload content in the first request only.
    first = message(b"GET /first HTTP/1.1", b"Host: a", b"X-Old: OLDREQ")
    second = message(b"GET /second HTTP/1.1", b"Host: a")
    tcp(out, 3, 80, talk([(">", first), ("<", EMPTY), (">", second), ("<", EMPTY)]))
    tcp(out, 4, 80, talk([(">", first + second), ("<", EMPTY + EMPTY)]))
    # A compressed response body: the payload carries the header, the
    # buffer the decompressed body.
    packed = gzip.compress(b"secret", mtime=0)
    gz = message(b"HTTP/1.1 200 OK", b"Content-Encoding: gzip", length(packed), body=packed)
    tcp(out, 5, 80, talk([(">", message(b"GET /g HTTP/1.1", b"Host: a")), ("<", gz)]))
    # The payload content in a header, a later one in the body's segment.
    later = message(b"POST /p HTTP/1.1", b"Host: a", b"X-A: PAYREQ", length(b"LATER"))
    tcp(out, 6, 80, talk([(">", later), (">", b"LATER"), ("<", EMPTY)]))
    # The payload content split across two segments of the header.
    split = message(b"POST /p HTTP/1.1", b"Host: a", b"X-A: PAYREQ", b"Content-Length: 0")
    cut = split.index(b"PAYREQ") + 3
    tcp(out, 7, 80, talk([(">", split[:cut]), (">", split[cut:]), ("<", EMPTY)]))
    # The payload content only in the response.
    plain = message(b"POST /p HTTP/1.1", b"Host: a", b"Content-Length: 0")
    rsp = message(b"HTTP/1.1 200 OK", length(b"PAYREQ"), body=b"PAYREQ")
    tcp(out, 8, 80, talk([(">", plain), ("<", rsp)]))
    # The response header and body in two segments.
    tcp(out, 9, 80, talk([(">", plain), ("<", OK[: -len(b"PAYRSP")]), ("<", b"PAYRSP")]))
    # The payload content in the request, the rule's buffer in the response.
    tcp(out, 10, 80, talk([(">", post), ("<", EMPTY)]))
    # A request whose header waits for a later segment, the content before.
    tcp(out, 11, 80, talk([(">", post[:12]), (">", post[12:]), ("<", OK)]))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("http-payload", "make-http-payload-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
