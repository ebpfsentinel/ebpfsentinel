"""Run the HTTP rules below over crafted HTTP/1 conversations through a real Suricata.

The rules read the HTTP buffers (method, URI raw and normalised, host,
headers, cookies, status, bodies once dechunked and decompressed), so what
alerts says what Suricata put in each buffer and on which packet it read it.
Some rules are written to be refused, to show which mixes Suricata does not
load.

Writes http-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import gzip
import os
import zlib
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 8000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("http", 'flow:to_server; http.method; content:"GET";'),
    ("http", 'http.uri; content:"/index.html"; endswith;'),
    ("http", 'http.uri.raw; content:"%2e%2e";'),
    ("http", 'http.uri; content:"/a/b?"; startswith;'),
    ("http", 'http.uri; content:"?q=a b";'),
    ("http", 'http.uri; content:"?q=a+b";'),
    ("http", 'http.uri; content:"&r= x#f";'),
    ("http", 'http.host; content:"example.com"; startswith; endswith;'),
    ("http", 'http.host.raw; content:"Example.COM"; startswith; endswith;'),
    ("http", 'http.user_agent; content:"curl/8"; startswith; endswith;'),
    ("http", 'http.header; content:"X-Test: 1|0d 0a|";'),
    ("http", 'http.header; content:"Cookie";'),
    ("http", 'http.cookie; content:"sess=1"; startswith; endswith;'),
    ("http", 'http.request_line; content:"GET /index.html HTTP/1.1"; startswith; endswith;'),
    ("http", 'http.stat_code; content:"200"; startswith; endswith;'),
    ("http", 'http.stat_msg; content:"Not Found"; startswith; endswith;'),
    ("http", 'http.response_line; content:"HTTP/1.1 404 Not Found|0d 0a|"; startswith; endswith;'),
    ("http", 'http.server; content:"nginx"; startswith; endswith;'),
    ("http", 'http.response_body; content:"secret"; startswith; endswith;'),
    ("http", 'file.data; content:"secret"; startswith; endswith;'),
    ("http", 'http.request_body; content:"user=admin"; startswith; endswith;'),
    ("http", 'http.content_type; content:"text/html"; startswith; endswith;'),
    ("http", 'http.header_names; content:"|0d 0a|Host|0d 0a|";'),
    ("http", 'http.start; content:"GET /index.html HTTP/1.1|0d 0a|Host:"; startswith;'),
    ("http", 'http.start; content:"200 OK|0d 0a 0d 0a|Server"; '),
    ("http", 'http.protocol; content:"HTTP/1.1"; startswith; endswith;'),
    ("http", 'flow:to_server; http.response_body; content:"secret";'),
    ("http", 'flow:to_client; http.uri; content:"/";'),
    ("http", 'http.uri; content:"/"; http.stat_code; content:"200";'),
    ("http", 'http.host; content:"Example";'),
    ("http", "urilen:>20;"),
    ("http", "urilen:11;"),
    ("http", 'uricontent:"index";'),
    ("http", 'http.uri; content:"/z"; startswith; endswith;'),
    ("http", 'http.uri; content:"/w/|e9|"; startswith;'),
    ("http", 'http.uri; content:"/w/??"; startswith;'),
    ("http", 'http.request_header; content:"X-Test: 1"; startswith; endswith;'),
    ("http", 'http.response_header; content:"Server: nginx"; startswith; endswith;'),
    ("http", 'http.location; content:"/next"; startswith; endswith;'),
    ("http", 'http.content_len; content:"6"; startswith; endswith;'),
    ("tcp", 'file.data; content:"secret";'),
    ("http", 'http.accept; content:"*/*"; startswith; endswith;'),
    ("http", 'http.referer; content:"ref"; startswith; endswith;'),
    ("http", 'http.connection; content:"close"; startswith; endswith;'),
    ("http", 'flow:to_server; http.header.raw; content:"X-Test";'),
    ("http", 'http.header.raw; content:"X-Test";'),
    ("http", 'http.uri; content:"/pipe"; startswith;'),
    ("http", 'http.response_body; content:"chunked-secret"; startswith; endswith;'),
    ("http", 'http.response_body; content:"gzipped secret"; startswith; endswith;'),
    ("http", 'http.response_body; content:"deflated secret"; startswith; endswith;'),
    ("http", 'http.response_body; content:"until close"; startswith; endswith;'),
    ("http", 'http.response_body; content:"split body"; startswith; endswith;'),
    ("http", 'http.host; content:"dotted.example"; startswith; endswith;'),
    ("http", 'http.stat_code; content:"100";'),
    ("http", 'http.method; content:"HEAD"; http.method; content:"HEAD";'),
    ("http", 'http.header; content:"X-Fold: a b";'),
    ("http", 'http.header; content:"X-Dup: 1, 2|0d 0a|";'),
    ("http", 'flow:to_client; http.header; content:"Server";'),
    ("http", 'flow:to_server; http.cookie; content:"sess";'),
    ("http", 'flow:to_client; http.cookie; content:"set=2";'),
    ("http", 'http.uri; content:"/?"; startswith; endswith;'),
    ("http", 'http.uri; content:"/%u017a";'),
    ("http", 'http.host; content:"dotted.example."; startswith; endswith;'),
    ("http", 'http.host.raw; content:"dotted.example."; startswith; endswith;'),
    ("http", 'http.uri; content:"/y/z"; startswith; endswith;'),
    ("http", 'http.uri; content:"/x/z"; startswith; endswith;'),
    ("http", 'http.uri; content:"/y/?"; startswith; endswith;'),
    ("http", 'http.uri; content:"/x/?"; startswith; endswith;'),
    ("http", 'http.uri; content:"/v/|e9|"; startswith; endswith;'),
    ("http", 'http.uri; content:"/v/?"; startswith; endswith;'),
    ("http", 'http.uri; content:"/u/|e9|"; startswith; endswith;'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"http {FIRST_SID + n}\"; {options})"


def request(line, *headers, body=b""):
    head = line + b"\r\n" + b"".join(h + b"\r\n" for h in headers) + b"\r\n"
    return head + body


def response(line, *headers, body=b""):
    return request(line, *headers, body=body)


def chunked(*parts):
    out = b""
    for part in parts:
        out += f"{len(part):x}".encode() + b"\r\n" + part + b"\r\n"
    return out + b"0\r\n\r\n"


def conversations():
    out = []
    talk = applayer.talk
    tcp = applayer.tcp_conversation
    first = request(
        b"GET /index.html HTTP/1.1",
        b"Host: Example.COM",
        b"User-Agent: curl/8",
        b"X-Test: 1",
        b"Cookie: sess=1",
        b"Accept: */*",
        b"Referer: ref",
        b"Connection: close",
    )
    ok = response(
        b"HTTP/1.1 200 OK",
        b"Server: nginx",
        b"Content-Type: text/html",
        b"Content-Length: 6",
        b"Set-Cookie: set=2",
        body=b"secret",
    )
    tcp(out, 1, 80, talk([(">", first), ("<", ok)]))
    odd = request(
        b"GET /a/./c/../b/%2e%2e/b?q=a+b&r=%20x#f HTTP/1.1",
        b"Host: example.com:8080",
    )
    missing = response(b"HTTP/1.1 404 Not Found", b"Location: /next", b"Content-Length: 0")
    tcp(out, 2, 80, talk([(">", odd), ("<", missing)]))
    login = request(
        b"POST /login HTTP/1.1",
        b"Host: example.com",
        b"Content-Length: 10",
        body=b"user=admin",
    )
    chunks = response(
        b"HTTP/1.1 200 OK",
        b"Transfer-Encoding: chunked",
        body=chunked(b"chunked-", b"secret"),
    )
    tcp(out, 3, 80, talk([(">", login), ("<", chunks)]))
    packed = gzip.compress(b"gzipped secret", mtime=0)
    zipped = response(
        b"HTTP/1.1 200 OK",
        b"Content-Encoding: gzip",
        f"Content-Length: {len(packed)}".encode(),
        body=packed,
    )
    tcp(out, 4, 80, talk([(">", request(b"GET /gz HTTP/1.1", b"Host: example.com")), ("<", zipped)]))
    squeezed = zlib.compress(b"deflated secret")
    deflated = response(
        b"HTTP/1.1 200 OK",
        b"Content-Encoding: deflate",
        f"Content-Length: {len(squeezed)}".encode(),
        body=squeezed,
    )
    tcp(out, 5, 80, talk([(">", request(b"GET /df HTTP/1.1", b"Host: example.com")), ("<", deflated)]))
    closing = response(b"HTTP/1.0 200 OK", b"Server: old", body=b"until close")
    tcp(out, 6, 80, talk([(">", request(b"GET /old HTTP/1.0")), ("<", closing)]))
    pipe = request(b"GET /pipe1 HTTP/1.1", b"Host: example.com") + request(
        b"GET /pipe2 HTTP/1.1", b"Host: example.com"
    )
    two = response(b"HTTP/1.1 200 OK", b"Content-Length: 1", body=b"a") + response(
        b"HTTP/1.1 200 OK", b"Content-Length: 1", body=b"b"
    )
    tcp(out, 7, 80, talk([(">", pipe), ("<", two)]))
    tcp(out, 8, 80, talk([
        (">", request(b"GET /%u017a HTTP/1.1", b"Host: dotted.example.")),
        ("<", response(b"HTTP/1.1 204 No Content")),
        (">", request(b"GET /w/%u00e9%u1234 HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 204 No Content")),
    ]))
    split = response(b"HTTP/1.1 200 OK", b"Content-Length: 10")
    tcp(out, 9, 80, talk([
        (">", request(b"GET /split HTTP/1.1", b"Host: example.com")),
        ("<", split),
        ("<", b"split "),
        ("<", b"body"),
    ]))
    tcp(out, 10, 80, talk([
        (">", request(b"HEAD /index.html HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 200 OK", b"Content-Length: 6")),
        (">", request(b"GET /after HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 200 OK", b"Content-Length: 6", body=b"secret")),
    ]))
    tcp(out, 11, 8080, talk([(">", first), ("<", ok)]))
    tcp(out, 12, 80, talk([
        (">", request(
            b"POST /up HTTP/1.1",
            b"Host: example.com",
            b"Expect: 100-continue",
            b"Content-Length: 10",
        )),
        ("<", response(b"HTTP/1.1 100 Continue")),
        (">", b"user=admin"),
        ("<", response(b"HTTP/1.1 200 OK", b"Content-Length: 6", body=b"secret")),
    ]))
    tcp(out, 13, 80, talk([
        (">", request(
            b"GET /fold HTTP/1.1",
            b"Host: example.com",
            b"X-Fold: a",
            b" b",
            b"X-Dup: 1",
            b"X-Dup: 2",
        )),
        ("<", response(b"HTTP/1.1 200 OK", b"Content-Length: 0")),
    ]))
    tcp(out, 14, 80, talk([
        (">", request(b"GET /y/%c5%ba HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 204 No Content")),
        (">", request(b"GET /x/\xc5\xba HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 204 No Content")),
        (">", request(b"GET /v/\xc3\xa9 HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 204 No Content")),
        (">", request(b"GET /u/%e9 HTTP/1.1", b"Host: example.com")),
        ("<", response(b"HTTP/1.1 204 No Content")),
    ]))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("http", "make-http-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
