#!/usr/bin/env bash
# Write the answers a real Docker Engine and a real rootful Podman service give
# to the two reads the warden projects: one container's inspect and the
# container list. Each file is the whole HTTP answer as it came off the
# socket, headers and transfer framing included, because that is what the
# warden's relay reads.
#
# The container carries a secret in its environment, one in its command line
# and a bind mount, so a test can show none of them reaches the agent.
#
#   crates/warden/tests/fixtures/make-runtime-answers.sh
#
# Needs a Docker Engine the caller may use. Podman is installed from Alpine's
# packages inside a privileged container, so the host needs no install.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/runtime-answers"
mkdir -p "$out"

name=ebpfsentinel-fixture
env_secret='FIXTURE_TOKEN=fixture-env-secret'
arg_secret='--password=fixture-arg-secret'
image=docker.io/library/alpine:3.22

bind_src="$(mktemp -d)"
cleanup() {
    docker rm -f "$name" "$name-podman" >/dev/null 2>&1 || true
    rmdir "$bind_src" 2>/dev/null || true
}
trap cleanup EXIT

# Docker.
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -e "$env_secret" -v "$bind_src:/data:ro" \
    -l tier=front -l team=payments "$image" sh -c 'sleep 600' fixture "$arg_secret" >/dev/null
id="$(docker inspect -f '{{.Id}}' "$name")"
docker_get() {
    curl -sS --raw -i --unix-socket /var/run/docker.sock "http://localhost$1"
}
docker_get "/v1.43/containers/$id/json" >"$out/docker-inspect.http"
docker_get "/v1.43/containers/json?filters=%7B%22name%22%3A%5B%22$name%22%5D%7D" \
    >"$out/docker-list.http"
docker rm -f "$name" >/dev/null

# Podman's rootful service, the same compatible paths.
docker run --rm --privileged --name "$name-podman" \
    -e env_secret="$env_secret" -e arg_secret="$arg_secret" -e image="$image" \
    -e name="$name" -e owner="$(id -u):$(id -g)" -v "$out:/out" "$image" sh -euc '
        apk add --no-cache podman curl iptables ip6tables >/dev/null
        mkdir -p /run/podman /srv/fixture /etc/containers
        printf "[storage]\ndriver = \"vfs\"\n" >/etc/containers/storage.conf
        podman system service -t 0 unix:///run/podman/podman.sock &
        for _ in $(seq 50); do [ -S /run/podman/podman.sock ] && break; sleep 0.2; done
        podman run -d --name "$name" -e "$env_secret" -v /srv/fixture:/data:ro \
            -l tier=front -l team=payments "$image" sh -c "sleep 600" fixture "$arg_secret" >/dev/null
        id="$(podman inspect -f "{{.Id}}" "$name")"
        get() { curl -sS --raw -i --unix-socket /run/podman/podman.sock "http://localhost$1"; }
        get "/v1.43/containers/$id/json" >/out/podman-inspect.http
        get "/v1.43/containers/json?filters=%7B%22name%22%3A%5B%22$name%22%5D%7D" >/out/podman-list.http
        podman rm -f -t 0 "$name" >/dev/null
        chown "$owner" /out/podman-inspect.http /out/podman-list.http
    '
echo "wrote $(ls "$out" | wc -l) answers to $out"
