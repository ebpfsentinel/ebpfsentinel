#!/usr/bin/env python3
"""Generate an Ed25519 keypair and a matching single-key JWKS document.

Usage:
    build_eddsa_jwks.py <jwks_out.json> <private_out.pem> <kid>

Writes the private key as an unencrypted PKCS#8 PEM and emits a JWKS whose
sole entry is the corresponding Ed25519 public key in OKP form, ready to be
consumed by the agent's `DecodingKey::from_jwk` path.
"""

import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        sys.stderr.write(
            "usage: build_eddsa_jwks.py <jwks_out.json> <private_out.pem> <kid>\n"
        )
        return 2

    jwks_out, private_out, kid = argv[1], argv[2], argv[3]

    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(private_out, "wb") as fh:
        fh.write(private_pem)

    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": b64url(public_raw),
            }
        ]
    }
    with open(jwks_out, "w", encoding="utf-8") as fh:
        json.dump(jwks, fh)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
