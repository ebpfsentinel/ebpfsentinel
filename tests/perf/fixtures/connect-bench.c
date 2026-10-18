/*
 * connect-bench - how long a connect() and an exec() cost on this node.
 *
 * The socket hooks run in the syscall of the task that opens the socket and
 * the process tracepoints run in the task that execs, so neither shows up in
 * a packet-rate measurement: a flood of packets on an established connection
 * never calls either one. What they cost is paid per connection and per
 * program start, which is what this driver times.
 *
 * Two modes, both reporting nanoseconds per operation on stdout as
 * "<ops> <nanoseconds_total> <ns_per_op>":
 *
 *   connect <iterations> <port>   connect() to a listener on loopback and
 *                                 close, serially, so each iteration pays one
 *                                 connect4 hook and one sock_ops record.
 *   exec    <iterations>          fork() and execve() a trivial binary,
 *                                 waiting for each child, so each iteration
 *                                 pays one sched_process_exec and one
 *                                 sched_process_exit.
 *
 * The listener is the caller's business: a connect to a closed port is
 * refused before the kernel establishes anything, which measures a different
 * path. Build with: cc -O2 -o connect-bench connect-bench.c
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int bench_connect(long iterations, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    long done = 0;
    long long start = now_ns();
    for (long i = 0; i < iterations; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            done++;
        }
        /* Close with a reset so the peer does not leave the port in
         * TIME_WAIT: a serial loop of 100k connects would otherwise run out
         * of ephemeral ports long before it finishes, and the measurement
         * would turn into a port-allocation benchmark. */
        struct linger lg = {.l_onoff = 1, .l_linger = 0};
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(fd);
    }
    long long elapsed = now_ns() - start;
    if (done == 0) {
        fprintf(stderr, "connect-bench: no connection succeeded on port %d\n", port);
        return 1;
    }
    printf("%ld %lld %.1f\n", done, elapsed, (double)elapsed / (double)done);
    return 0;
}

static int bench_exec(long iterations) {
    char *const argv[] = {(char *)"/bin/true", NULL};
    char *const envp[] = {NULL};

    long done = 0;
    long long start = now_ns();
    for (long i = 0; i < iterations; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            continue;
        }
        if (pid == 0) {
            execve("/bin/true", argv, envp);
            _exit(127);
        }
        int status = 0;
        if (waitpid(pid, &status, 0) == pid) {
            done++;
        }
    }
    long long elapsed = now_ns() - start;
    if (done == 0) {
        fprintf(stderr, "connect-bench: no child ran\n");
        return 1;
    }
    printf("%ld %lld %.1f\n", done, elapsed, (double)elapsed / (double)done);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: connect-bench connect <iterations> <port>\n");
        fprintf(stderr, "       connect-bench exec <iterations>\n");
        return 2;
    }
    long iterations = strtol(argv[2], NULL, 10);
    if (iterations <= 0) {
        fprintf(stderr, "connect-bench: iterations must be positive\n");
        return 2;
    }
    if (strcmp(argv[1], "connect") == 0) {
        if (argc < 4) {
            fprintf(stderr, "connect-bench: connect mode needs a port\n");
            return 2;
        }
        return bench_connect(iterations, (int)strtol(argv[3], NULL, 10));
    }
    if (strcmp(argv[1], "exec") == 0) {
        return bench_exec(iterations);
    }
    fprintf(stderr, "connect-bench: unknown mode %s\n", argv[1]);
    return 2;
}
