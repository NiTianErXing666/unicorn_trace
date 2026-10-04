/*
 * testtarget.c — functions that get executed inside the unicorn tracer.
 * This library is loaded normally by the app; the tracer picks raw
 * addresses of these exports (dlsym) and runs them under emulation.
 *
 * Compiled without PAC/BTI so the code is emulation-friendly.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <errno.h>
#include <android/log.h>

static inline long sys(long nr, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}
#define sys0(nr)                     sys(nr, 0, 0, 0, 0, 0, 0)
#define sys1(nr, a)                  sys(nr, (long)(a), 0, 0, 0, 0, 0)
#define sys3(nr, a, b, c)            sys(nr, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define sys6(nr, a, b, c, d, e, f)   sys(nr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ---- pure computation ---- */
long tt_add(long a, long b) { return a + b; }

long tt_mul(long a, long b) { return a * b; }

long tt_fib(int n) {
    if (n < 2) return n;
    long a = 0, b = 1;
    for (int i = 2; i <= n; i++) { long t = a + b; a = b; b = t; }
    return b;
}

/* ---- libc: malloc / string ---- */
char* tt_strdup_upper(const char* in) {
    if (!in) return NULL;
    size_t n = strlen(in);
    char* out = (char*)malloc(n + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) out[i] = (char)toupper((unsigned char)in[i]);
    out[n] = 0;
    return out;
}

long tt_sum_malloc(int n) {
    if (n <= 0) return 0;
    int* v = (int*)malloc((size_t)n * sizeof(int));
    if (!v) return -1;
    long sum = 0;
    for (int i = 0; i < n; i++) { v[i] = i * 3 + 1; sum += v[i]; }
    free(v);
    return sum;
}

long tt_snprintf_test(char* buf, int cap, long value) {
    int n = snprintf(buf, (size_t)cap, "value=%ld hex=0x%lx", value, value);
    return n + (long)strlen(buf);
}

/* global data (.data) + bss access inside emulation */
long g_data_array[64] = {1, 2, 3, 4, 5};
long g_bss_array[64];

long tt_data_test(int idx) {
    if (idx < 0 || idx >= 64) return -1;
    g_bss_array[idx] = g_data_array[idx] + 1000;
    return g_bss_array[idx];
}

/* ---- raw syscalls from inside emulation ---- */
long tt_syscall_getpid(void) {
    return sys0(__NR_getpid);
}

long tt_syscall_write(int fd, const void* buf, size_t n) {
    return sys3(__NR_write, fd, buf, n);
}

static long sys2_wrap(struct timespec* ts) {
    return sys(__NR_clock_gettime, CLOCK_MONOTONIC, (long)ts, 0, 0, 0, 0);
}

long tt_gettime(void* ts_out /*long[3]: [0..1]=timespec [2]=magic*/) {
    struct timespec ts = {0, 0};
    long r = sys2_wrap(&ts);
    memcpy(ts_out, &ts, sizeof(ts));
    ((long*)ts_out)[2] = 0xABCDEF;   /* marker written by emulated code */
    return r;
}

long tt_getrandom(void* buf, size_t n) {
    return sys(__NR_getrandom, (long)buf, (long)n, 0, 0, 0, 0);
}

long tt_open_read(const char* path, void* buf, size_t cap) {
    long fd = sys(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return fd;
    long n = sys(__NR_read, fd, (long)buf, (long)cap, 0, 0, 0);
    sys(__NR_close, fd, 0, 0, 0, 0, 0);
    return n;
}

/* ---- signals: raise via syscall, caught by a REAL handler ---- */
static volatile long g_segv_caught = 0;

static void tt_signal_handler(int sig, siginfo_t* info, void* ctx) {
    (void)info; (void)ctx;
    __android_log_print(ANDROID_LOG_INFO, "unitrace",
                        "    [handler enter] sig=%d", sig);
    g_segv_caught = g_segv_caught * 10 + sig;   /* runs natively, real stack */
    __android_log_print(ANDROID_LOG_INFO, "unitrace",
                        "    [handler exit] caught=%ld", (long)g_segv_caught);
}

/* variant that never delivers: tgkill with sig=0 (permission check only) */
long tt_signal_test_nodeliver(int sig) {
    g_segv_caught = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = tt_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    long r1 = sys(__NR_rt_sigaction, sig, (long)&sa, 0, 8, 0, 0);
    long r2 = sys(__NR_tgkill, sys0(__NR_getpid), sys(__NR_gettid, 0, 0, 0, 0, 0, 0), 0, 0, 0, 0);
    return (r1 << 32) | ((r2 & 0xFFFF) << 16) | (g_segv_caught & 0xFFFF);
}

long tt_signal_test(int sig) {
    g_segv_caught = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = tt_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    long r1 = sys(__NR_rt_sigaction, sig, (long)&sa, 0, 8, 0, 0);
    long r2 = sys(__NR_tgkill, sys0(__NR_getpid), sys(__NR_gettid, 0, 0, 0, 0, 0, 0), sig, 0, 0, 0);
    /* handler ran natively while we were inside the emulator */
    return (r1 << 32) | ((r2 & 0xFFFF) << 16) | (g_segv_caught & 0xFFFF);
}

/* ---- futex: atomics + syscall ---- */
long tt_futex_wake(void* word /*int**/) {
    int* w = (int*)word;
    __sync_synchronize();
    int old = __sync_lock_test_and_set(w, 2);
    long woken = sys(__NR_futex, (long)w, FUTEX_WAKE, 1, 0, 0, 0);
    return (old << 32) | (woken & 0xFFFFFFFF);
}

/* ---- pthread mutex (userspace fast path + futex if contended) ---- */
long tt_mutex_test(int n) {
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    long acc = 0;
    for (int i = 0; i < n; i++) {
        pthread_mutex_lock(&m);
        acc += i;
        pthread_mutex_unlock(&m);
    }
    pthread_mutex_destroy(&m);
    return acc;
}

/* ---- recursion ---- */
long tt_recsum(int n) { return n <= 0 ? 0 : n + tt_recsum(n - 1); }

/* ---- large stack frame / alloca-ish ---- */
long tt_stackframe_test(int depth) {
    volatile char pad[4096];
    pad[0] = (char)depth;
    pad[4095] = (char)(depth ^ 0x5A);
    if (depth <= 0) return pad[0] + pad[4095];
    return pad[0] + pad[4095] + tt_stackframe_test(depth - 1);
}

/* ---- errno path: failing syscall then read errno via libc ---- */
long tt_errno_test(void) {
    long fd = sys(__NR_openat, AT_FDCWD, (long)"/nonexistent/path/xyz", O_RDONLY, 0, 0, 0);
    long raw = fd;                    /* kernel convention: -ENOENT */
    errno = 0;
    int libc_fd = open("/nonexistent/path/xyz", O_RDONLY);  /* libc wrapper: errno path */
    long libcerr = errno;
    if (libc_fd >= 0) close(libc_fd);
    return (raw & 0xFFFF) | ((libcerr & 0xFFFF) << 16);
}

/* ---- memcpy / memset on a big block ---- */
long tt_memcpy_test(void* dst, const void* src, size_t n) {
    memcpy(dst, src, n);
    const unsigned char* d = (const unsigned char*)dst;
    unsigned long h = 1469598103934665603UL;
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= 1099511628211UL; }
    return (long)h;
}

/* ---- cpu fingerprint probes (executed inside the emulator) ---- */
uint64_t tt_read_ctr_el0(void) {
    uint64_t v = 0;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(v));
    return v;
}

uint64_t tt_read_dczid_el0(void) {
    uint64_t v = 0;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(v));
    return v;
}

/* SVE: on a non-SVE core this must trap (SIGILL) — same as the real host */
__attribute__((target("arch=armv8.2-a+sve")))
long tt_sve_probe(void) {
    long v = 0;
    __asm__ volatile("rdvl %0, #0" : "=r"(v));
    return v;
}

/* DotProd: present on the host's A76 — must execute under emulation */
__attribute__((target("arch=armv8.2-a+dotprod")))
long tt_dotprod_probe(void) {
    uint32_t a = 0x01020304, b = 0x05060708;
    uint32_t r = 0;
    __asm__ volatile(
        "dup v0.4s, %w2\n"
        "dup v1.4s, %w3\n"
        "udot v2.4s, v0.16b, v1.16b\n"
        "umov %w0, v2.s[0]\n"
        : "=r"(r) : "0"(r), "r"(a), "r"(b) : "v0", "v1", "v2");
    return (long)r;
}

/* LSE atomic: present on the host — must execute under emulation */
__attribute__((target("arch=armv8.2-a+lse")))
long tt_lse_probe(long* word, long add) {
    long old = 0;
    __asm__ volatile("ldaddal %2, %0, [%1]" : "=r"(old) : "r"(word), "r"(add) : "memory");
    return old;
}

/* ---- anti-timing-detection probes (executed in the emulator) ---- */
/* measure CNTVCT ticks for a fixed instruction loop: on real hardware this
 * is ~insns/IPC * (cntfrq/cpu_hz) ticks; under a naive emulator it is the
 * (much slower) wall time. With the virtual clock both match. */
long tt_time_probe_loop(long iters) {
    uint64_t t0, t1;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
    volatile long sink = 0;
    for (long i = 0; i < iters; i++) {
        sink += i;
        __asm__ volatile("" :: "r"(sink) : "memory");
    }
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
    (void)sink;
    return (long)(t1 - t0);
}

/* measure CLOCK_MONOTONIC ns for the same loop */
long tt_time_probe_clock(long iters) {
    struct timespec a = {0, 0}, b = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &a);
    volatile long sink = 0;
    for (long i = 0; i < iters; i++) {
        sink += i;
        __asm__ volatile("" :: "r"(sink) : "memory");
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    (void)sink;
    return (long)((b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec));
}

/* sleep then verify the clock advanced by roughly the sleep amount */
long tt_time_probe_sleep(long ms) {
    struct timespec a = {0, 0}, b = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &a);
    struct timespec req = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&req, 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (long)((b.tv_sec - a.tv_sec) * 1000000000L + (b.tv_nsec - a.tv_nsec));
}

/* ---- call-observation demo: direct internal calls carrying strings ---- */
__attribute__((noinline)) static long tt_callee_len(const char* s) {
    return (long)strlen(s);
}
__attribute__((noinline)) static const char* tt_callee_dup(const char* s) {
    return s;   /* pretend transformation; returns a string pointer */
}
long tt_call_demo(const char* s) {
    long n = tt_callee_len(s);
    const char* r = tt_callee_dup(s);
    return n + (r[0] != 0 ? 1 : 0);
}
