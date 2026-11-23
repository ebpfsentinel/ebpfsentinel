"""Run the SSH rules below over crafted conversations through a real Suricata.

The conversations exchange identification strings as RFC 4253 section 4.2
writes them: client first or server first, split across segments, ended by a
line feed alone, with and without comments, on and off port 22, so what
alerts says what Suricata holds a connection's protocol version and software
version to be.

Writes ssh-verdicts.txt beside this script, in the format of
applayer-verdicts.txt. The test needs neither this script nor docker. Needs
docker.
"""

import os
from importlib import util

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST_SID = 14000

spec = util.spec_from_file_location("applayer", os.path.join(HERE, "make-applayer-verdicts.py"))
applayer = util.module_from_spec(spec)
spec.loader.exec_module(applayer)

RULES = [
    ("ssh", 'ssh.software; content:"OpenSSH_";'),
    ("ssh", 'flow:to_client; ssh.software; content:"OpenSSH_8";'),
    ("ssh", 'flow:to_server; ssh.software; content:"PuTTY";'),
    ("ssh", 'ssh.proto; content:"2.0";'),
    ("ssh", 'ssh_proto; content:"PUTTY";'),
    ("ssh", 'ssh.software; content:"SSH-2.0-";'),
    ("ssh", 'ssh.software; content:"Ubuntu";'),
    ("ssh", 'ssh.software; content:"OpenSSH_8.9p1"; isdataat:!1,relative;'),
    ("tcp", 'ssh.software; content:"OpenSSH";'),
    ("ssh", 'ssh.proto; content:"1.99";'),
    ("ssh", 'ssh.software; content:"Erlang/"; pcre:"/^5\\x2e1\\x2e[0-4]/R";'),
    ("ssh", 'flow:to_server; ssh_proto; content:"2.0";'),
    ("ssh", 'flow:to_client; ssh.software; content:"ConfD-";'),
    ("ssh", 'ssh.software; content:"OpenSSH_9.0"; isdataat:!1,relative;'),
    ("ssh", 'ssh.software; content:"\\r";'),
    ("ssh", 'ssh.proto; content:"2.0"; isdataat:!1,relative;'),
]


def rule_text(n, entry):
    proto, options = entry
    return f"alert {proto} any any -> any any (msg:\"ssh {FIRST_SID + n}\"; {options})"


PUTTY = b"SSH-2.0-PuTTY_Release_0.78\r\n"
UBUNTU = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
# The start of a binary packet: length, padding length, SSH_MSG_KEXINIT.
KEXINIT = b"\x00\x00\x01\x2c\x06\x14" + bytes(16) + b"\x00\x00\x00\x0acurve25519"


def conversations():
    out = []
    talk, tcp = applayer.talk, applayer.tcp_conversation
    # The server speaks first, as servers do, then the client.
    tcp(out, 1, 22, talk([("<", UBUNTU), (">", PUTTY), (">", KEXINIT), ("<", KEXINIT)]))
    # The client speaks first.
    tcp(out, 2, 22, talk([(">", PUTTY), ("<", UBUNTU), (">", KEXINIT)]))
    # The server's identification split across two segments.
    tcp(out, 3, 22, talk([("<", UBUNTU[:20]), ("<", UBUNTU[20:]), (">", PUTTY)]))
    # Ended by a line feed alone, no comments.
    tcp(out, 4, 22, talk([("<", b"SSH-2.0-OpenSSH_9.0\n"), (">", b"SSH-2.0-OpenSSH_9.0\n")]))
    # An older protocol version and an Erlang server.
    tcp(out, 5, 22, talk([("<", b"SSH-1.99-Erlang/5.1.4.7\r\n"), (">", PUTTY)]))
    # Off port 22.
    tcp(out, 6, 2222, talk([("<", UBUNTU), (">", PUTTY)]))
    # A brute force tool naming a fake version, and a ConfD server.
    tcp(out, 7, 22, talk([("<", b"SSH-2.0-ConfD-7.8\r\n"), (">", b"SSH-PUTTY-1\r\n")]))
    # The identification and the key exchange in one segment.
    tcp(out, 8, 22, talk([("<", UBUNTU + KEXINIT), (">", PUTTY + KEXINIT)]))
    # Other lines from the server before its identification.
    tcp(out, 9, 22, talk([(">", PUTTY), ("<", b"Welcome\r\n" + UBUNTU)]))
    return out


def main():
    rules = [rule_text(n, r) for n, r in enumerate(RULES)]
    applayer.verdicts("ssh", "make-ssh-verdicts.py", FIRST_SID, rules, conversations())


if __name__ == "__main__":
    main()
