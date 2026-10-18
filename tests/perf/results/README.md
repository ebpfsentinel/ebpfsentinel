# Measured results

What a run of a suite in `tests/perf/` actually produced, on a named host, on
a named day. A figure quoted anywhere else in this repository - the docs, the
website's feature matrix, a deck - comes from a file here, and a file here is
the output of the suite rather than a number somebody typed.

Nothing in this directory is a target. A guest with four vCPUs is not a
production node, and the suite says so in its own output: the bounds it
asserts are what the lane can hold, not what the product promises.

## `2026-10-18-attribution-overhead.json`

`07-attribution-overhead.bats`, run four times on a Vagrant guest, kernel
7.0.0-28-generic, 4 vCPU, agent `0.0.0-dev` running rootless with eBPF loaded
through the BPF token and the warden broker. The JSON is the fourth run; the
four runs together are what the figure is worth:

| run | connect baseline | connect with attribution | delta | exec baseline | exec with the process table | delta |
|---|---|---|---|---|---|---|
| 1 | 13045.2 ns | 12976.6 ns | -68.6 ns | 339007.6 ns | 366790.2 ns | +27782.6 ns |
| 2 | 12490.2 ns | 12913.4 ns | +423.2 ns | 326360.2 ns | 347024.0 ns | +20663.8 ns |
| 3 | 12752.0 ns | 12957.3 ns | +205.3 ns | 343816.1 ns | 368089.3 ns | +24273.2 ns |
| 4 | 12936.4 ns | 12853.7 ns | -82.7 ns | 364438.1 ns | 359156.9 ns | -5281.2 ns |

Each arm is 20000 connects or 3000 execs, three runs, median kept.

**What the connect() column means.** The delta changes sign between runs, so
on this lane the socket hooks cost less than the guest's own run-to-run
spread: the honest statement is below 500 ns per `connect()`, not a point
figure. The baseline itself is a loopback handshake against a Python
listener, around 12.9 us, so the hooks are a small fraction of a syscall that
is itself dominated by the accept side.

**What the execve() column means.** Three runs of four put the process table
between +20 us and +28 us per `execve()` on a 340 us baseline, and the fourth
came in below the baseline. The cost is real - the two tracepoints plus the
userspace read of `/proc` that follows them - and it is paid once per process
start, not per packet and not per connection.

**What the kernel refused.** `attribution_hooks_attached` is 6, not 7: this
host refuses `bpf_get_socket_cookie` to a `sock_ops` program under the
tokenized rootless load, so the socket-to-flow join did not attach and the
agent fell back to matching an established flow to its socket by five-tuple.
Every socket is still named. The figures above are therefore the cost of six
hooks on this host; a host that takes the seventh pays one more map write per
established connection.
