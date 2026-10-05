# The demo's traffic generator and its target, one small image for both.
#
#   target   - an HTTP and HTTPS server standing in for a protected service
#   attacker - sends the SYN flood
#   app      - a workload talking TLS through OpenSSL, which is what the DLP
#              probe hooks, and which can be pointed at an AI provider's name
#
# Built locally by `docker compose build`; nothing here is published.
FROM debian:trixie-slim

# hping3 is packaged by Debian and only in Alpine's testing branch.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 hping3 iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY target.py /usr/local/bin/target.py
COPY workload.py /usr/local/bin/workload.py
