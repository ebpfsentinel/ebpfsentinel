#!/usr/bin/env python3
"""Keeps the app container's OpenSSL mapped between two requests.

The DLP probe is a uprobe on SSL_write and SSL_read, attached per library file
by a watcher that looks every five seconds for processes mapping one. A curl
that lives for a tenth of a second is gone before it is seen, so this process
holds libssl open for the life of the container: the probe lands on the file
once, and every curl the scenarios run in this container, which maps the same
file, is inspected from its first byte.
"""

import ssl
import time

if __name__ == "__main__":
    print("app ready, %s mapped" % ssl.OPENSSL_VERSION, flush=True)
    while True:
        time.sleep(3600)
