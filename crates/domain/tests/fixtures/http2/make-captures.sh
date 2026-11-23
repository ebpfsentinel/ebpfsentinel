#!/usr/bin/env bash
# Regenerate the HTTP/2 client captures read by the domain tests.
#
# curl encodes the requests with nghttp2, so the header blocks carry what a
# real client sends: Huffman-coded strings and dynamic table references
# from the second request on. A small responder records every byte the
# client sends and answers each request with an empty 200, so curl reuses
# the connection for the next URL.
#
# Needs curl built with HTTP/2 (`curl -V` lists HTTP2) and python3.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${RESPONDER:-0}" 2>/dev/null || true; rm -rf "${WORK}"' EXIT

curl -V | head -1

cat >"${WORK}/responder.py" <<'PY'
import socket, struct, sys

out_path, port_path = sys.argv[1], sys.argv[2]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
open(port_path, "w").write(str(srv.getsockname()[1]))
conn, _ = srv.accept()
seen = bytearray()
buf = bytearray()
preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# Server SETTINGS, empty.
conn.sendall(struct.pack(">I", 0)[1:] + b"\x04\x00" + struct.pack(">I", 0))
while True:
    chunk = conn.recv(65536)
    if not chunk:
        break
    seen += chunk
    buf += chunk
    if buf.startswith(preface):
        del buf[: len(preface)]
    while len(buf) >= 9:
        length = int.from_bytes(buf[0:3], "big")
        if len(buf) < 9 + length:
            break
        kind, flags = buf[3], buf[4]
        stream = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
        del buf[: 9 + length]
        if kind == 0x4 and not flags & 0x1:
            # Acknowledge the client's SETTINGS.
            conn.sendall(b"\x00\x00\x00\x04\x01" + struct.pack(">I", 0))
        if kind in (0x0, 0x1) and flags & 0x1:
            # END_STREAM: answer ":status: 200" (static index 8), ending
            # the stream with END_HEADERS.
            conn.sendall(b"\x00\x00\x01\x01\x05" + struct.pack(">I", stream) + b"\x88")
open(out_path, "wb").write(bytes(seen))
PY

capture() {
  local name="$1"
  shift
  rm -f "${WORK}/port"
  python3 "${WORK}/responder.py" "${HERE}/${name}.bin" "${WORK}/port" &
  RESPONDER=$!
  while [ ! -s "${WORK}/port" ]; do sleep 0.05; done
  local port
  port="$(cat "${WORK}/port")"
  # shellcheck disable=SC2001
  curl -sS --http2-prior-knowledge -o /dev/null "${@//PORT/${port}}"
  wait "${RESPONDER}"
  printf '%s %s bytes\n' "${name}" "$(wc -c <"${HERE}/${name}.bin")"
}

# Two gRPC calls on one connection: the second reuses the authority, the
# content type and the user agent from the dynamic table.
capture curl-two-grpc-calls \
  -X POST -H 'content-type: application/grpc' -H 'te: trailers' \
  --data-binary 'hello' \
  'http://grpc.internal:PORT/admin.AdminService/DeleteUser' \
  --connect-to 'grpc.internal:PORT:127.0.0.1:PORT' \
  --next --http2-prior-knowledge -o /dev/null \
  -X POST -H 'content-type: application/grpc' -H 'te: trailers' \
  --data-binary 'hello' \
  'http://grpc.internal:PORT/helloworld.Greeter/SayHello' \
  --connect-to 'grpc.internal:PORT:127.0.0.1:PORT'

# Two plain GET requests on one connection.
capture curl-two-gets \
  'http://web.internal:PORT/api/v1/users?page=2' \
  --connect-to 'web.internal:PORT:127.0.0.1:PORT' \
  --next --http2-prior-knowledge -o /dev/null \
  'http://web.internal:PORT/admin/delete' \
  --connect-to 'web.internal:PORT:127.0.0.1:PORT'
