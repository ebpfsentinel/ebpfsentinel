#!/usr/bin/env bash
# Regenerate podman-db.sqlite: the db.sql a real Podman writes, never one
# typed by hand, so the reader is tested on the format Podman produces.
#
# Runs Podman in a throwaway privileged container, creates three containers
# whose names, labels and states the tests read, and copies root's db.sql out:
#
#   shop-front  created, labels app=shop tier=front
#   shop-back   running, label app=shop
#   batch       exited
#
# The ids change on every run: the script prints them, and the constants
# CREATED, RUNNING and EXITED in src/podman_store.rs take the new values.
# Needs docker; pulls quay.io/podman/stable and busybox, removes the Podman
# image afterwards.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${PODMAN_IMAGE:-quay.io/podman/stable}"
OUT="$(mktemp -d)"
trap 'rm -rf "${OUT}"; docker rmi -f "${IMAGE}" >/dev/null 2>&1 || true' EXIT

docker run --rm --privileged -v "${OUT}:/out" "${IMAGE}" sh -euc '
podman --version
podman pull -q docker.io/library/busybox:1.36 >/dev/null
podman create --name shop-front --label app=shop --label tier=front \
  docker.io/library/busybox:1.36 sleep 600 >/out/created.id
podman run -d --name shop-back --label app=shop \
  docker.io/library/busybox:1.36 sleep 600 >/out/running.id
podman run --name batch docker.io/library/busybox:1.36 true
podman inspect -f "{{.Id}}" batch >/out/exited.id
podman ps -a --format "{{.ID}} {{.Names}} {{.Status}}"
cp /var/lib/containers/storage/db.sql /out/db.sql
'

cp "${OUT}/db.sql" "${HERE}/podman-db.sqlite"
for state in created running exited; do
  printf '%s %s\n' "${state}" "$(cat "${OUT}/${state}.id")"
done
