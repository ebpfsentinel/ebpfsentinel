"""Run the SMTP file.data rules below over crafted mail through a real Suricata.

The conversations send messages as RFC 5321 and RFC 2045 write them: an
attachment in base64, one in quoted-printable, one sent as is, a body with no
attachment, a message with no MIME structure, nested multiparts, a part named
only by Content-Type, lines split across segments and a dot stuffed line, so
what alerts says which parts of a message Suricata reads as files and what
their content is once decoded.

Writes smtp-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import base64
import os
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 15000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("smtp", 'file.data; content:"ustar";'),
    ("smtp", 'file.data; content:"070707"; startswith;'),
    ("smtp", 'file.data; content:"Hello body";'),
    ("smtp", 'file.data; content:"quoted=printable";'),
    ("smtp", 'file.data; content:"quoted printable joined";'),
    ("smtp", 'file.data; content:"plain attachment";'),
    ("smtp", 'file.data; content:"AAAA";'),
    ("smtp", 'file.data; content:"nested part";'),
    ("smtp", 'file.data; content:"named by type";'),
    ("smtp", 'file.data; content:"no mime";'),
    ("smtp", 'file.data; content:"dot.stuffed";'),
    ("smtp", 'file.data; content:"..stuffed";'),
    ("smtp", 'flow:established,to_server; file.data; content:"split across";'),
    ("tcp", 'file.data; content:"ustar";'),
    ("smtp", 'file.data; content:"inline part";'),
    ("smtp", 'file.data; content:"|0d 0a|second line";'),
    ("smtp", 'file.data; content:"Content-Type";'),
    ("smtp", 'file.data; content:"ustar"; isdataat:!1,relative;'),
    ("smtp", 'file.data; content:"trailing"; isdataat:!1,relative;'),
    ("smtp", 'file.data; content:"plain attachment"; startswith;'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"smtp {FIRST_SID + n}\"; {options})"


def b64(data):
    text = base64.b64encode(data).decode()
    return "\r\n".join(text[i:i + 76] for i in range(0, len(text), 76)).encode()


TAR = b"payload/jetty/webapps/zimbra/public/x.jsp" + bytes(216) + b"ustar\x0000" + bytes(100)
CPIO = b"070707" + bytes(20) + b"/jetty/x/webapps/zimbra/public/y.jsp"


def multipart(parts, boundary=b"BOUND"):
    out = b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"" + boundary + b"\"\r\n\r\n"
    out += b"This is a multi-part message.\r\n"
    for headers, body in parts:
        out += b"--" + boundary + b"\r\n" + headers + b"\r\n\r\n" + body + b"\r\n"
    return out + b"--" + boundary + b"--\r\n"


def mail(message):
    """A session around one message, the server answering each command."""
    return [
        ("<", b"220 mx.example ESMTP\r\n"),
        (">", b"EHLO client.example\r\n"),
        ("<", b"250-mx.example\r\n250 8BITMIME\r\n"),
        (">", b"MAIL FROM:<a@client.example>\r\n"),
        ("<", b"250 OK\r\n"),
        (">", b"RCPT TO:<b@mx.example>\r\n"),
        ("<", b"250 OK\r\n"),
        (">", b"DATA\r\n"),
        ("<", b"354 Go ahead\r\n"),
        *message,
        ("<", b"250 Queued\r\n"),
        (">", b"QUIT\r\n"),
        ("<", b"221 Bye\r\n"),
    ]


HEAD = b"From: a@client.example\r\nTo: b@mx.example\r\nSubject: test\r\n"


def conversations():
    out = []
    talk, tcp = applayer.talk, applayer.tcp_conversation
    # A tar archive attached in base64, beside a text body.
    body = HEAD + multipart([
        (b"Content-Type: text/plain", b"Hello body\r\nsecond line"),
        (b"Content-Type: application/x-tar\r\nContent-Disposition: attachment; filename=\"a.tar\"\r\n"
         b"Content-Transfer-Encoding: base64", b64(TAR)),
    ])
    tcp(out, 1, 25, talk(mail([(">", body + b".\r\n")])))
    # A cpio archive in base64 and a quoted-printable attachment.
    body = HEAD + multipart([
        (b"Content-Type: application/octet-stream; name=\"b.cpio\"\r\nContent-Transfer-Encoding: base64",
         b64(CPIO)),
        (b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"q.txt\"\r\n"
         b"Content-Transfer-Encoding: quoted-printable",
         b"quoted=3Dprintable and quoted printable=\r\n joined"),
    ])
    tcp(out, 2, 25, talk(mail([(">", body + b".\r\n")])))
    # An attachment sent as is, a dot stuffed line, and a trailing word.
    body = HEAD + multipart([
        (b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"p.txt\"",
         b"plain attachment\r\n..stuffed dot.stuffed\r\ntrailing"),
    ])
    tcp(out, 3, 25, talk(mail([(">", body + b".\r\n")])))
    # A message with no MIME structure at all.
    tcp(out, 4, 25, talk(mail([(">", HEAD + b"\r\nno mime here\r\n.\r\n")])))
    # Nested multiparts, an inline part, a part named by its type alone.
    inner = multipart([
        (b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"n.txt\"",
         b"nested part"),
    ], b"INNER")
    inner = inner[inner.index(b"\r\n\r\n") + 4:]
    body = HEAD + multipart([
        (b"Content-Type: multipart/mixed; boundary=\"INNER\"", inner.rstrip(b"\r\n")),
        (b"Content-Type: text/plain\r\nContent-Disposition: inline", b"inline part"),
        (b"Content-Type: application/octet-stream; name=\"t.bin\"", b"named by type"),
        (b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64",
         b64(b"AAAA unnamed")),
    ])
    tcp(out, 5, 25, talk(mail([(">", body + b".\r\n")])))
    # The tar attachment split across segments, on another port.
    body = HEAD + multipart([
        (b"Content-Type: application/x-tar\r\nContent-Disposition: attachment; filename=\"a.tar\"\r\n"
         b"Content-Transfer-Encoding: base64", b64(TAR)),
        (b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"s.txt\"",
         b"split across segments"),
    ]) + b".\r\n"
    cut = len(body) // 2
    tcp(out, 6, 587, talk(mail([(">", body[:cut]), (">", body[cut:])])))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("smtp", "make-smtp-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
