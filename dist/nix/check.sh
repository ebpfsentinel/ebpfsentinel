#!/usr/bin/env bash
# Evaluate dist/nix/check.nix against a pinned nixpkgs.
#
# Uses `nix-instantiate` when it is on PATH, and the nixos/nix image
# otherwise, so a machine without Nix runs the same evaluation. The nixpkgs
# revision is the NixOS release the module is written for; moving it is a
# change to this file, reviewed like any other.
#
#   dist/nix/check.sh
set -euo pipefail

NIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "${NIX_DIR}")"

NIXPKGS_REV=c56a87d8e41ce69bd2af57eb35dcc117a9dfca33 # nixos-26.05
NIXPKGS_SHA256=06g8y8y9bysnpxrl6bfqmn63l8w2lx2yhj0618r34j5jfqy5vjpx
NIX_IMAGE="${NIX_IMAGE:-nixos/nix:2.35.4}"

EXPR="import /src/nix/check.nix {
  nixpkgs = builtins.fetchTarball {
    url = \"https://github.com/NixOS/nixpkgs/archive/${NIXPKGS_REV}.tar.gz\";
    sha256 = \"${NIXPKGS_SHA256}\";
  };
}"

run() {
  nix-instantiate --eval --strict --json --expr "$1" | tr ',' '\n' | tr -d '[]"'
  echo
}

if command -v nix-instantiate >/dev/null 2>&1; then
  run "${EXPR//\/src/${DIST_DIR}}"
else
  docker run --rm -v "${DIST_DIR}:/src:ro" "${NIX_IMAGE}" \
    nix-instantiate --eval --strict --json --expr "${EXPR}" | tr ',' '\n' | tr -d '[]"'
  echo
fi
