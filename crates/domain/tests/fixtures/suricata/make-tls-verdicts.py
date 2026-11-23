"""Run the TLS rules below over real and crafted TLS handshakes through a real Suricata.

The certificates are made by the openssl command line and the handshakes
of conversations 1 to 3 and 9 are spoken by the OpenSSL library behind
Python's ssl module, TLS 1.2 and 1.3; the other conversations carry hellos
built here, with an uppercase server name, GREASE values, a fixed random,
a hello cut over two segments or over two records, and a record cut short.
Suricata first reads the handshakes with no rule loaded and its log gives
the strings it computes (subject, issuer, serial, fingerprint, JA3, JA3S,
JA4), from its TLS records and from the alerts of a rule matching every JA4; the rules are then written against those strings, so what alerts
says what Suricata puts in each buffer and on which packet it reads it.
Some rules are written to be refused, to show which mixes Suricata does not
load.

Writes tls-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The certificates and keys are made afresh on each run
in a temporary directory, so the fingerprints change from one run to the
next. The test needs neither this script nor docker. Needs docker, openssl
3.4 or later and Python's ssl module.
"""

import json
import os
import ssl
import struct
import subprocess
import tempfile
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 10000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def key_and_request(work, name, subject):
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{work}/{name}.key", "-out", f"{work}/{name}.csr", "-subj", subject, "-utf8")


def sign(work, name, issuer, serial, not_before, not_after, extensions):
    with open(f"{work}/{name}.ext", "w", encoding="utf-8") as f:
        f.write(extensions)
    openssl("x509", "-req", "-in", f"{work}/{name}.csr", "-CA", f"{work}/{issuer}.pem",
            "-CAkey", f"{work}/{issuer}.key", "-set_serial", serial, "-out", f"{work}/{name}.pem",
            "-not_before", not_before, "-not_after", not_after, "-extfile", f"{work}/{name}.ext")


def certificates(work):
    """A root, an intermediate, a leaf valid at the capture's time and one
    that expired before it."""
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{work}/root.key", "-out", f"{work}/root.pem",
            "-subj", "/C=FR/O=Root Authority/CN=Root CA", "-set_serial", "1",
            "-not_before", "20200101000000Z", "-not_after", "20400101000000Z", "-utf8")
    key_and_request(work, "middle", "/C=FR/O=Middle, Inc./OU=Issuing/CN=Middle CA")
    sign(work, "middle", "root", "0x8a0102", "20200101000000Z", "20390101000000Z",
         "basicConstraints=critical,CA:true\n")
    key_and_request(work, "leaf", "/C=DE/ST=Berlin/L=Mitte/O=Leaf GmbH/OU=Web/CN=leaf.example.test"
                    "/emailAddress=ops@example.test")
    sign(work, "leaf", "middle", "0x00fe0102030405060708090a0b0c0d0e0f", "20230101120000Z",
         "20250601120000Z", "subjectAltName=DNS:leaf.example.test,DNS:*.alt.test,IP:10.1.2.3\n")
    key_and_request(work, "old", "/CN=old.example.test")
    sign(work, "old", "middle", "0x42", "20200101000000Z", "20230601000000Z",
         "subjectAltName=DNS:old.example.test\n")
    for name in ("leaf", "old"):
        with open(f"{work}/{name}-chain.pem", "w", encoding="utf-8") as f:
            f.write(open(f"{work}/{name}.pem", encoding="utf-8").read())
            f.write(open(f"{work}/middle.pem", encoding="utf-8").read())


def handshake(work, version, name, chain="leaf"):
    """The flights a client and a server of the OpenSSL library exchange,
    then one request from the client."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(f"{work}/{chain}-chain.pem", f"{work}/{chain}.key")
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    for context in (server, client):
        context.minimum_version = context.maximum_version = version
        context.set_alpn_protocols(["http/1.1"])
    ins = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    outs = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    ends = [
        client.wrap_bio(ins[0], outs[0], server_hostname=name),
        server.wrap_bio(ins[1], outs[1], server_side=True),
    ]
    flights, done = [], [False, False]
    for _ in range(10):
        for i, side in enumerate((">", "<")):
            try:
                ends[i].do_handshake()
                done[i] = True
            except ssl.SSLWantReadError:
                pass
            out = outs[i].read()
            if out:
                flights.append((side, out))
                ins[1 - i].write(out)
        if all(done):
            break
    ends[0].write(b"GET / HTTP/1.1\r\n\r\n")
    flights.append((">", outs[0].read()))
    return flights


def record(kind, body, version=b"\x03\x01"):
    return bytes([kind]) + version + len(body).to_bytes(2, "big") + body


def message(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def extension(kind, body):
    return kind.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def u16s(values):
    data = b"".join(v.to_bytes(2, "big") for v in values)
    return len(data).to_bytes(2, "big") + data


CLIENT_RANDOM = bytes(range(0x40, 0x60))
SERVER_RANDOM = bytes(range(0xA0, 0xC0))


def client_hello(name=b"Leaf.Example.TEST"):
    """A TLS 1.2 hello with GREASE in the ciphers, the extensions and the
    groups, and a fixed random."""
    host = b"\x00" + len(name).to_bytes(2, "big") + name
    extensions = b"".join([
        extension(0x0A0A, b""),
        extension(0, len(host).to_bytes(2, "big") + host),
        extension(10, u16s([0x1A1A, 29, 23])),
        extension(11, b"\x01\x00"),
        extension(13, u16s([0x0403, 0x0804])),
        extension(16, b"\x00\x03\x02h2"),
    ])
    body = (b"\x03\x03" + CLIENT_RANDOM + b"\x00" + u16s([0x2A2A, 0xC02F, 0x002F]) + b"\x01\x00"
            + len(extensions).to_bytes(2, "big") + extensions)
    return message(1, body)


def server_hello():
    extensions = extension(0xFF01, b"\x00")
    body = (b"\x03\x03" + SERVER_RANDOM + b"\x00" + (0xC02F).to_bytes(2, "big") + b"\x00"
            + len(extensions).to_bytes(2, "big") + extensions)
    return record(22, message(2, body) + message(14, b""), b"\x03\x03")


def logged(packets):
    """What Suricata logs of each flow's handshake, by flow number."""
    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o777)
        with open(os.path.join(work, "case.pcap"), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for n, at, ip in packets:
                ns = (n * 10_000 * 1000 + round(at * 1000)) * 1_000_000
                secs, rest = divmod(ns, 1_000_000_000)
                data = applayer.header.frame(ip)
                f.write(struct.pack("<IIII", applayer.EPOCH + secs, rest // 1000, len(data), len(data)))
                f.write(data)
        with open(os.path.join(work, "case.rules"), "w", encoding="utf-8") as f:
            f.write('alert tls any any -> any any (msg:"log"; ja3.hash; content:"00000000000000000000000000000000"; sid:1;)\n')
            f.write('alert tls any any -> any any (msg:"log"; ja4.hash; content:"t"; sid:2;)\n')
        os.mkdir(os.path.join(work, "out"))
        os.chmod(os.path.join(work, "out"), 0o777)
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "--entrypoint", "suricata", applayer.IMAGE,
             "-r", "/w/case.pcap", "-S", "/w/case.rules", "-l", "/w/out", "-k", "none",
             "--runmode", "single"],
            capture_output=True, text=True, check=True,
        )
        out = {}
        for line in open(os.path.join(work, "out", "eve.json"), encoding="utf-8"):
            event = json.loads(line)
            if event.get("event_type") in ("tls", "alert") and "tls" in event:
                out.setdefault(int(event["src_ip"].split(".")[3]), event["tls"])
        return out


def conversations(work):
    tls12, tls13 = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3
    real = handshake(work, tls12, "leaf.example.test")
    hello = client_hello()
    cut = 40
    script = {
        1: (443, real),
        2: (443, handshake(work, tls13, "leaf.example.test")),
        3: (8443, handshake(work, tls12, None)),
        4: (443, [(">", record(22, hello)), ("<", server_hello())]),
        5: (443, [(">", record(22, hello)[:cut]), (">", record(22, hello)[cut:]), ("<", server_hello())]),
        6: (443, [(">", record(22, hello[:30]) + record(22, hello[30:])), ("<", server_hello())]),
        7: (443, [(">", record(22, hello)[:-10]), ("<", server_hello())]),
        8: (443, [(">", real[0][1]), ("<", real[1][1][:300]), ("<", real[1][1][300:])] + real[2:]),
        9: (443, handshake(work, tls12, "old.example.test", "old")),
    }
    packets = []
    for n, (port, flights) in script.items():
        applayer.tcp_conversation(packets, n, port, applayer.talk(flights))
    return packets, real


def colon(data):
    return " ".join(f"{b:02x}" for b in data)


def rules(log, real):
    first, crafted = log[1], log[4]
    server_random = real[1][1][11:43]
    return [
        ("tls", 'tls.sni; content:"leaf.example.test"; startswith; endswith;'),
        ("tls", 'tls_sni; content:"leaf.example.test"; startswith; endswith;'),
        ("tls", 'tls.sni; content:"Leaf.Example.TEST"; startswith; endswith;'),
        ("tls", 'tls.sni; content:"leaf.example.test"; nocase;'),
        ("tls", 'flow:to_client; tls.sni; content:"leaf";'),
        ("tls", 'flow:established,to_server; tls.sni; dotprefix; content:".example.test"; endswith;'),
        ("tls", "tls.sni; bsize:17;"),
        ("tcp", 'tls.sni; content:"leaf.example.test";'),
        ("udp", 'tls.sni; content:"leaf.example.test";'),
        ("http", 'tls.sni; content:"leaf.example.test";'),
        ("tcp-pkt", 'tls.sni; content:"leaf.example.test";'),
        ("tls", 'tls.sni; content:"leaf"; tls.cert_subject; content:"CN=leaf";'),
        ("tls", 'content:"|16 03|"; tls.sni; content:"Leaf";'),
        ("tls", f'content:"|{colon(CLIENT_RANDOM[:4])}|"; tls.sni; content:"Leaf";'),
        ("tls", f'tls.cert_subject; content:"{first["subject"]}"; startswith; endswith;'),
        ("tls", 'tls.cert_subject; content:"CN=leaf.example.test";'),
        ("tls", f'tls.cert_issuer; content:"{first["issuerdn"]}"; startswith; endswith;'),
        ("tls", 'tls.cert_issuer; content:"CN=Root CA";'),
        ("tls", f'tls.cert_serial; content:"{first["serial"]}"; startswith; endswith;'),
        ("tls", f'tls.cert_fingerprint; content:"{first["fingerprint"]}"; startswith; endswith;'),
        ("tls", 'tls.certs; content:"Middle CA";'),
        ("tls", 'tls.certs; content:"Root CA";'),
        ("tls", 'tls.certs; content:"old.example.test";'),
        ("tls", "tls.certs; bsize:>100;"),
        ("tls", 'tls.subjectaltname; content:"*.alt.test"; startswith; endswith;'),
        ("tls", 'tls.subjectaltname; content:"10.1.2.3";'),
        ("tls", 'tls.subjectaltname; content:"leaf.example.test"; startswith; endswith;'),
        ("tls", 'flow:to_server; tls.cert_subject; content:"CN";'),
        ("tls", 'tls.cert_subject; content:"Email=ops@example.test"; endswith;'),
        ("tls", f'ja3.hash; content:"{first["ja3"]["hash"]}";'),
        ("tls", f'ja3_hash; content:"{first["ja3"]["hash"]}";'),
        ("tls", f'ja3.string; content:"{first["ja3"]["string"]}"; startswith; endswith;'),
        ("tls", f'ja3s.hash; content:"{first["ja3s"]["hash"]}";'),
        ("tls", f'ja3s.string; content:"{first["ja3s"]["string"]}"; startswith; endswith;'),
        ("tls", f'ja4.hash; content:"{first["ja4"]}"; startswith; endswith;'),
        ("tls", f'ja3.hash; content:"{crafted["ja3"]["hash"]}";'),
        ("tls", f'ja3.string; content:"{crafted["ja3"]["string"]}"; startswith; endswith;'),
        ("tls", f'ja4.hash; content:"{crafted["ja4"]}"; startswith; endswith;'),
        ("tls", f'ja3s.hash; content:"{crafted["ja3s"]["hash"]}";'),
        ("tls", f'tls.random; content:"|{colon(CLIENT_RANDOM)}|"; startswith; endswith;'),
        ("tls", f'tls.random; content:"|{colon(SERVER_RANDOM)}|"; startswith; endswith;'),
        ("tls", f'tls.random_time; content:"|{colon(CLIENT_RANDOM[:4])}|"; startswith; endswith;'),
        ("tls", f'tls.random_bytes; content:"|{colon(CLIENT_RANDOM[4:])}|"; startswith; endswith;'),
        ("tls", f'flow:to_client; tls.random; content:"|{colon(SERVER_RANDOM[:8])}|";'),
        ("tls", f'flow:to_client; tls.random; content:"|{colon(server_random[:8])}|";'),
        ("tls", "tls.version:1.2;"),
        ("tls", "tls.version:1.3;"),
        ("tls", "ssl_version:tls1.2;"),
        ("tls", "ssl_version:tls1.3;"),
        ("tls", "ssl_version:!tls1.2;"),
        ("tls", "tls.cert_chain_len:2;"),
        ("tls", "tls.cert_chain_len:>2;"),
        ("tls", "tls_cert_notbefore:<2022-01-01;"),
        ("tls", "tls_cert_notafter:>2024-01-01;"),
        ("tls", "tls_cert_expired;"),
        ("tls", "tls_cert_valid;"),
        ("tls", f'tls.fingerprint:"{first["fingerprint"]}";'),
        ("tls", 'tls.subject:"CN=leaf.example.test";'),
        ("tls", 'tls.issuerdn:"CN=Middle CA";'),
        ("tls", 'tls.subject:!"CN=nope";'),
        ("tls", "ssl_state:client_hello;"),
        ("tls", "ssl_state:server_hello;"),
        ("tls", "ssl_state:!client_hello;"),
        ("tls", "ssl_state:client_hello|server_hello;"),
        ("tls", 'tls.alpn; content:"http/1.1"; startswith; endswith;'),
        ("tls", 'tls.alpn; content:"h2"; startswith; endswith;'),
        ("tls", "tls.version:1.2; tls.cert_chain_len:2;"),
        ("tls", 'flow:to_client; tls.cert_subject; content:"CN=old.example.test";'),
        ("tls", 'tls.sni; content:"leaf"; flowbits:set,hello; noalert;'),
        ("tls", 'flowbits:isset,hello; tls.cert_serial; content:"00:FE";'),
        ("tls", 'tls.sni; content:"old.example.test"; startswith; endswith;'),
        ("ip", 'tls.sni; content:"leaf.example.test";'),
        ("tls", f'flow:to_client; ja3.hash; content:"{first["ja3"]["hash"]}";'),
        ("tls", f'flow:to_server; ja3s.hash; content:"{first["ja3s"]["hash"]}";'),
        ("tls", 'flow:to_client; ja4.hash; content:"t";'),
        ("tls", f'flow:to_server; tls.random; content:"|{colon(CLIENT_RANDOM[:8])}|";'),
        ("tls", f'tls.random_time; content:"|{colon(SERVER_RANDOM[:4])}|"; startswith; endswith;'),
        ("tls", f'tls.random_bytes; content:"|{colon(SERVER_RANDOM[4:])}|"; startswith; endswith;'),
        ("tls", "ssl_version:sslv3;"),
        ("tls", "ssl_version:tls1.0;"),
        ("tls", "ssl_version:tls1.0,tls1.3;"),
        ("tls", "tls.version:1.0;"),
        ("tls", "tls.version:0x0303;"),
        ("tls", 'flow:to_server; tls.certs; content:"CN";'),
        ("tls", "flow:to_server; tls.cert_chain_len:0;"),
        ("tls", "tls.cert_chain_len:0;"),
        ("tls", 'tls.cert_subject; content:"cn=LEAF"; nocase;'),
        ("tls", 'tls.sni; pcre:"/^leaf\\.example\\.test$/";'),
        ("tls", 'content:"leaf.example.test"; tls.sni; content:"leaf";'),
        ("tls", 'flow:to_client; content:"Middle CA"; tls.cert_serial; content:"00:FE";'),
        ("tls", 'tls.sni; content:"example"; isdataat:!1,relative;'),
        ("tls", 'tls.sni; content:"example"; isdataat:5,relative;'),
        ("tls", "ssl_state:!server_hello;"),
        ("tls", 'tls.cert_issuer; content:"Middle"; tls.cert_subject; content:"Leaf";'),
        ("tls", 'tls.subjectaltname; content:"[10, 1, 2, 3]"; startswith; endswith;'),
        ("tls", 'tls.cert_serial; content:"42"; startswith; endswith;'),
        ("tls", 'flow:to_server; tls.subject:"CN";'),
        ("tls", 'flow:to_server; tls.issuerdn:"CN";'),
        ("tls", f'flow:to_server; tls.fingerprint:"{first["fingerprint"]}";'),
        ("tls", "flow:to_server; tls_cert_expired;"),
        ("tls", "flow:to_server; tls_cert_valid;"),
        ("tls", "flow:to_server; tls_cert_notbefore:>2000-01-01;"),
        ("tls", "flow:to_server; tls.version:1.2;"),
        ("tls", "flow:to_client; ssl_state:client_hello;"),
        ("tls", 'flow:to_server; tls.alpn; content:"http/1.1";'),
        ("tls", f'tls.sni; content:"leaf"; ja3s.hash; content:"{first["ja3s"]["hash"]}";'),
        ("tls", 'tls.sni; content:"leaf"; tls.cert_chain_len:2;'),
        ("tls", 'tls.cert_subject; content:"CN"; tls.cert_chain_len:2;'),
        ("tls", 'tls.sni; content:"leaf"; ssl_state:server_hello;'),
        ("tls", 'tls.sni; content:"leaf"; tls.version:1.2;'),
        ("tls", 'tls.sni; content:"leaf"; tls.subject:"CN";'),
        ("tls", 'tls.cert_subject; content:"CN"; tls_cert_valid;'),
        ("tls", "ssl_version:sslv2;"),
        ("tls", "tls.cert_chain_len:>0;"),
    ]


def main():
    with tempfile.TemporaryDirectory() as work:
        certificates(work)
        packets, real = conversations(work)
    log = logged(packets)
    text = [f'alert {proto} any any -> any any (msg:"tls {FIRST_SID + n}"; {options})'
            for n, (proto, options) in enumerate(rules(log, real))]
    applayer.verdicts("tls", "make-tls-verdicts.py", FIRST_SID, text, packets)


if __name__ == "__main__":
    main()
