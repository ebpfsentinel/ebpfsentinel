# Licensing

The agent is licensed under the GNU Affero General Public License v3.0, see
[LICENSE](LICENSE). This page is for whoever reviews that licence before
adopting it.

## What the agent reads without linking

Three mechanisms reach code under other licences, and none of them brings it
into this tree:

- **The uprobes on the cryptographic libraries.** To count encryption calls per
  process, the agent attaches a uprobe to `EVP_EncryptUpdate` in OpenSSL's
  `libcrypto`, `gcry_cipher_encrypt` in libgcrypt and two entry points of
  libsodium, in processes that have already loaded them. Attaching a uprobe is
  not linking: no header, no symbol table and no line of those projects' source
  enters this tree, the agent finds the symbol in the library file on the host,
  and it works the same against three libraries under three different licences.
  The DLP uprobes on TLS libraries work the same way.
- **The package databases.** The agent reads the dpkg status file, the apk
  installed database and the rpm database, which since rpm 4.16 is an SQLite
  file, to list installed packages. Reading a file format is not using an
  implementation: the SQLite file is walked by a reader written here, and no
  code, header or schema file of dpkg, apk, rpm or SQLite is copied or linked.
- **fanotify.** File changes and the write refusal's fallback reach the kernel
  through the `fanotify_init` and `fanotify_mark` system calls. That is the
  boundary the Linux kernel's syscall note places outside the kernel's licence,
  exactly as every other system call the agent makes.

What proves no licence entered the tree is that `cargo deny check` passes with
the allow-list in [deny.toml](deny.toml) unchanged, and the tree hygiene test in
`crates/xtask` fails if a lock file ever resolves a binding to any of these
libraries.
