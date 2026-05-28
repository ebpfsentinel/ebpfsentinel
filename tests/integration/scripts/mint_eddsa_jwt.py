#!/usr/bin/env python3
"""Mint an EdDSA-signed JWT from an Ed25519 private key.

Usage:
    mint_eddsa_jwt.py <private.pem> <kid> <sub> <iss> <aud>

Prints the compact-serialized token to stdout. The `kid` header lets the
agent select the matching JWKS entry; iss/aud must match the agent config.
"""

import sys
import time

import jwt


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        sys.stderr.write(
            "usage: mint_eddsa_jwt.py <private.pem> <kid> <sub> <iss> <aud>\n"
        )
        return 2

    private_pem_path, kid, sub, iss, aud = argv[1:6]

    with open(private_pem_path, "rb") as fh:
        private_pem = fh.read()

    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + 3600,
    }

    token = jwt.encode(
        claims,
        private_pem,
        algorithm="EdDSA",
        headers={"kid": kid},
    )
    sys.stdout.write(token if isinstance(token, str) else token.decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
