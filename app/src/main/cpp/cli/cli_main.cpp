/*
 * cli_main.cpp — standalone on-device harness for the unicorn tracer.
 * Build into unitrace_cli, push to /data/local/tmp, run directly.
 * The trace target functions are linked into the same binary.
 */
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "uni_trace.h"

extern "C" {
long tt_add(long, long);
long tt_mul(long, long);
long tt_fib(int);
char* tt_strdup_upper(const char*);
long tt_sum_malloc(int);
long tt_snprintf_test(char*, int, long);
long tt_data_test(int);
long tt_syscall_getpid(void);
long tt_syscall_write(int, const void*, size_t);
long tt_gettime(void*);
long tt_getrandom(void*, size_t);
long tt_open_read(const char*, void*, size_t);
long tt_errno_test(void);
long tt_signal_test(int);
long tt_signal_test_nodeliver(int);
long tt_futex_wake(void*);
long tt_mutex_test(int);
long tt_recsum(int);
long tt_stackframe_test(int);
long tt_memcpy_test(void*, const void*, size_t);
uint64_t tt_read_ctr_el0(void);
uint64_t tt_read_dczid_el0(void);
long tt_sve_probe(void);
long tt_dotprod_probe(void);
long tt_lse_probe(long*, long);
long tt_time_probe_loop(long);
long tt_time_probe_clock(long);
long tt_time_probe_sleep(long);
}

static int g_pass = 0, g_fail = 0;

static void check(const char* name, long* r, bool ok, const char* extra = "") {
    if (r && ok) {
        const ut_stats* st = ut_last_stats();
        char tbuf[64] = "";
        if (st) snprintf(tbuf, sizeof(tbuf), " %lluus %llublk",
                         (unsigned long long)st->elapsed_us,
                         (unsigned long long)st->block_count);
        printf("[PASS] %-26s ret=0x%llx %s%s\n", name,
               (unsigned long long)(uint64_t)r[0], extra, tbuf);
        g_pass++;
    } else {
        char sym[160] = {0};
        const char* err = ut_last_error();
        const char* pcp = strstr(err, "pc=0x");
        if (pcp) {
            uint64_t pc = strtoull(pcp + 5, nullptr, 16);
            ut_symbolize(pc, sym, sizeof(sym));
        }
        printf("[FAIL] %-26s %s ret=%llx error: %s %s\n", name, extra,
               r ? (unsigned long long)(uint64_t)r[0] : 0ull,
               r ? "" : ut_last_error(), sym);
        const char* tr = ut_last_trace();
        if (tr && tr[0]) printf("trace tail:\n%.1200s\n", tr);
        g_fail++;
    }
    fflush(stdout);
}

int main(int argc, char** argv) {
    int only = -1;   /* run a single test by number */
    if (argc > 1) only = atoi(argv[1]);
    ut_set_trace_level(getenv("UT_TRACE") ? atoi(getenv("UT_TRACE")) : 1);
    int tn = 0;

    if (ut_init() != 0) {
        fprintf(stderr, "init failed: %s\n", ut_last_error());
        return 2;
    }
    printf("engine: %s\n", ut_engine_info());
    fflush(stdout);

    {   /* 0 */
        uint64_t a[2] = {11, 31};
        long* r = invokeCall((void*)tt_add, a, 2);
        check("tt_add(11,31)", r, r && r[0] == 42);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 1 */
        uint64_t a[2] = {1234, 5678};
        long* r = invokeCall((void*)tt_mul, a, 2);
        check("tt_mul", r, r && r[0] == 1234l * 5678l);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 2 */
        uint64_t a[1] = {30};
        long* r = invokeCall((void*)tt_fib, a, 1);
        check("tt_fib(30)", r, r && r[0] == 832040);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 3: libc strlen/toupper/malloc/free */
        static char inbuf[64];
        strcpy(inbuf, "hello unicorn tracer!");
        uint64_t a[1] = {(uint64_t)(uintptr_t)inbuf};
        long* r = invokeCall((void*)tt_strdup_upper, a, 1);
        bool ok = r && r[0] &&
                  strcmp((const char*)(uintptr_t)r[0], "HELLO UNICORN TRACER!") == 0;
        check("tt_strdup_upper", r, ok);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 4 */
        uint64_t a[1] = {1000};
        long want = 0;
        for (int i = 0; i < 1000; i++) want += i * 3 + 1;
        long* r = invokeCall((void*)tt_sum_malloc, a, 1);
        check("tt_sum_malloc(1000)", r, r && r[0] == want);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 5 */
        static char sbuf[128];
        uint64_t a[3] = {(uint64_t)(uintptr_t)sbuf, 128, 1234567};
        long* r = invokeCall((void*)tt_snprintf_test, a, 3);
        bool ok = r && strcmp(sbuf, "value=1234567 hex=0x12d687") == 0;
        check("tt_snprintf", r, ok);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 6 */
        uint64_t a[1] = {3};
        long* r = invokeCall((void*)tt_data_test, a, 1);
        check("tt_data_test(3)", r, r && r[0] == 1004);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 7 */
        uint64_t a[1] = {0};
        long* r = invokeCall((void*)tt_syscall_getpid, a, 0);
        check("tt_syscall_getpid", r, r && r[0] == getpid());
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 8 */
        static const char msg[] = "[emu] write from unicorn\n";
        uint64_t a[3] = {1, (uint64_t)(uintptr_t)msg, sizeof(msg) - 1};
        long* r = invokeCall((void*)tt_syscall_write, a, 3);
        check("tt_syscall_write(1)", r, r && r[0] == (long)(sizeof(msg) - 1));
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 9 */
        static uint64_t tsbuf[4];
        memset(tsbuf, 0, sizeof(tsbuf));
        uint64_t a[1] = {(uint64_t)(uintptr_t)tsbuf};
        long* r = invokeCall((void*)tt_gettime, a, 1);
        bool ok = r && r[0] == 0 && tsbuf[2] == 0xABCDEF;  /* sec may be 0 on the virtual clock */
        check("tt_gettime(+marker)", r, ok);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 10 */
        static unsigned char rnd[64];
        memset(rnd, 0, sizeof(rnd));
        uint64_t a[2] = {(uint64_t)(uintptr_t)rnd, 64};
        long* r = invokeCall((void*)tt_getrandom, a, 2);
        int nz = 0;
        for (unsigned char c : rnd) nz += c != 0;
        check("tt_getrandom(64)", r, r && r[0] == 64 && nz > 8);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 11 */
        static char fbuf[512];
        memset(fbuf, 0, sizeof(fbuf));
        uint64_t a[3] = {(uint64_t)(uintptr_t)"/proc/self/maps",
                         (uint64_t)(uintptr_t)fbuf, sizeof(fbuf) - 1};
        long* r = invokeCall((void*)tt_open_read, a, 3);
        check("tt_open_read(self/maps)", r, r && r[0] > 0 && fbuf[0] != 0);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 12 */
        uint64_t a[1] = {0};
        long* r = invokeCall((void*)tt_errno_test, a, 0);
        bool ok = r && ((long)r[0] & 0xFFFF) == (uint16_t)-2 &&
                  (((long)r[0] >> 16) & 0xFFFF) == 2;
        check("tt_errno_test", r, ok);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 13 */
        uint64_t a[1] = {SIGUSR2};
        long* r = invokeCall((void*)tt_signal_test_nodeliver, a, 1);
        check("tt_signal_nodeliver", r, r && (((long)r[0]) & 0xFFFF) == 0);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 14 */
        uint64_t a[1] = {SIGUSR2};
        long* r = invokeCall((void*)tt_signal_test, a, 1);
        check("tt_signal_test(SIGUSR2)", r, r && (((long)r[0]) & 0xFFFF) == SIGUSR2);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 15 */
        uint64_t a[1] = {SIGSEGV};
        long* r = invokeCall((void*)tt_signal_test, a, 1);
        check("tt_signal_test(SIGSEGV)", r, r && (((long)r[0]) & 0xFFFF) == SIGSEGV);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 16 */
        static int word = 0;
        uint64_t a[1] = {(uint64_t)(uintptr_t)&word};
        long* r = invokeCall((void*)tt_futex_wake, a, 1);
        check("tt_futex_wake", r, r && (((long)r[0] >> 32) & 0xFFFFFFFF) == 0);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 17 */
        uint64_t a[1] = {100};
        long* r = invokeCall((void*)tt_mutex_test, a, 1);
        check("tt_mutex_test(100)", r, r && r[0] == 100l * 99 / 2);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 18 */
        uint64_t a[1] = {64};
        long* r = invokeCall((void*)tt_recsum, a, 1);
        check("tt_recsum(64)", r, r && r[0] == 64l * 65 / 2);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 19 */
        uint64_t a[1] = {32};
        long* r = invokeCall((void*)tt_stackframe_test, a, 1);
        check("tt_stackframe(32x4KB)", r, r && r[0] != 0);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 20 */
        static unsigned char src[64 * 1024], dst[64 * 1024];
        for (size_t i = 0; i < sizeof(src); i++) src[i] = (unsigned char)(i * 131 + 7);
        memset(dst, 0, sizeof(dst));
        uint64_t a[3] = {(uint64_t)(uintptr_t)dst, (uint64_t)(uintptr_t)src, sizeof(src)};
        long* r = invokeCall((void*)tt_memcpy_test, a, 3);
        bool ok = r && memcmp(src, dst, sizeof(src)) == 0;
        if (r && !ok) {
            for (size_t i = 0; i < sizeof(src); i++)
                if (src[i] != dst[i]) {
                    printf("  mismatch +%zu page %zu\n", i, i / 4096);
                    break;
                }
            unsigned char g[32];
            size_t gn = ut_debug_peek_guest((uint64_t)(uintptr_t)dst, g, 32);
            printf("  guest dst peek (%zu bytes):", gn);
            for (int k = 0; k < 32; k++) printf(" %02x", g[k]);
            printf("\n  real  dst peek:");
            for (int k = 0; k < 32; k++) printf(" %02x", dst[k]);
            printf("\n  real  src peek:");
            for (int k = 0; k < 32; k++) printf(" %02x", src[k]);
            printf("\n");
        }
        check("tt_memcpy 64KB+FNV", r, ok);
        ut_free_result(r);
        if (only == tn++) return 0;
    }

    {   /* 21: small memcpy — isolate the big-copy path */
        static unsigned char s2[256], d2[256];
        for (size_t i = 0; i < sizeof(s2); i++) s2[i] = (unsigned char)(i * 7 + 3);
        memset(d2, 0, sizeof(d2));
        uint64_t a[3] = {(uint64_t)(uintptr_t)d2, (uint64_t)(uintptr_t)s2, sizeof(s2)};
        ut_debug_watch((uint64_t)(uintptr_t)d2 - 64,
                       (uint64_t)(uintptr_t)d2 + sizeof(d2) + 64);
        long* r = invokeCall((void*)tt_memcpy_test, a, 3);
        ut_debug_watch(0, 0);
        bool ok = r && memcmp(s2, d2, sizeof(s2)) == 0;
        if (r && !ok) {
            unsigned char g[16];
            ut_debug_peek_guest((uint64_t)(uintptr_t)d2, g, 16);
            printf("  small guest:");
            for (int k = 0; k < 16; k++) printf(" %02x", g[k]);
            printf("\n  small real :");
            for (int k = 0; k < 16; k++) printf(" %02x", d2[k]);
            printf("\n");
        }
        check("tt_memcpy 256B", r, ok);
        ut_free_result(r);
        if (only == tn++) return 0;
    }

    {   /* 22: guest CTR_EL0 must equal the host value */
        uint64_t a[1] = {0};
        long* r = invokeCall((void*)tt_read_ctr_el0, a, 0);
        check("cpu CTR_EL0 == host", r, r && (uint64_t)r[0] == ut_get_host_ctr());
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 23: guest DCZID_EL0 must equal the host value */
        uint64_t a[1] = {0};
        long* r = invokeCall((void*)tt_read_dczid_el0, a, 0);
        check("cpu DCZID_EL0 == host", r, r && (uint64_t)r[0] == ut_get_host_dczid());
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 24: SVE instruction must trap like on the non-SVE host */
        uint64_t a[1] = {0};
        long* r = invokeCall((void*)tt_sve_probe, a, 0);
        bool ok = (r == nullptr) && strstr(ut_last_error(), "exception") != nullptr;
        printf("[%s] %-26s %s\n", ok ? "PASS" : "FAIL", "cpu SVE traps",
               r ? "executed (BAD)" : ut_last_error());
        ok ? g_pass++ : g_fail++;
        if (r) ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 25: DotProd executes (A76 feature) */
        uint64_t a[1] = {0};
        long* r = invokeCall((void*)tt_dotprod_probe, a, 0);
        check("cpu DotProd executes", r, r != nullptr);
        ut_free_result(r);
        if (only == tn++) return 0;
    }
    {   /* 26: LSE atomic executes (A76 feature) */
        static long word = 100;
        uint64_t a[2] = {(uint64_t)(uintptr_t)&word, 5};
        long* r = invokeCall((void*)tt_lse_probe, a, 2);
        check("cpu LSE ldadd executes", r, r && r[0] == 100 && word == 105);
        ut_free_result(r);
        if (only == tn++) return 0;
    }

    {   /* 27: GumTrace-style instruction trace demo */
        static char inbuf[64];
        strcpy(inbuf, "hi unicorn");
        uint64_t a2[2] = {2, 40};
        uint64_t a3[1] = {(uint64_t)(uintptr_t)inbuf};
        int old_lvl = ut_get_trace_level();
        ut_set_trace_level(3);
        const char* tf = getenv("UT_FILE");
        if (tf && ut_set_trace_file(tf) == 0)
            printf("[trace] auto-log enabled -> %s\n", tf);
        long* r = invokeCall((void*)tt_add, a2, 2);
        long* r2 = invokeCall((void*)tt_strdup_upper, a3, 1);
        ut_set_trace_level(old_lvl);
        bool ok = r && r[0] == 42 && r2 && r2[0] != 0;
        ut_free_result(r);
        ut_free_result(r2);
        if (tf) {
            FILE* chk = fopen(tf, "r");
            if (chk) {
                int runs = 0; char lb[256];
                while (fgets(lb, sizeof(lb), chk))
                    if (strncmp(lb, "==== run #", 10) == 0) runs++;
                fclose(chk);
                printf("[trace] %s contains %d appended runs\n", tf, runs);
            }
        }
        printf("---- trace head (%zu bytes) ----\n", ut_trace_size());
        int lines = 0;
        const char* q = ut_last_trace();
        while (*q && lines < 24) {
            const char* nl = strchr(q, '\n');
            size_t n = nl ? (size_t)(nl - q) : strlen(q);
            printf("%.*s\n", (int)n, q);
            if (!nl) break;
            q = nl + 1;
            lines++;
        }
        g_pass++;   /* demo: counted as pass when both invokes succeeded */
        if (!ok) g_pass--, g_fail++;
        printf("[%s] gumtrace format demo\n", ok ? "PASS" : "FAIL");
        if (only == tn++) return 0;
    }

    {   /* 28: virtual-clock timing probes — ticks per instruction must be
         * in the same ballpark as the real core (µs-scale loop, not
         * ms-scale), proving timing detection cannot spot the emulator */
        uint64_t a1[1] = {100000};
        long* r = invokeCall((void*)tt_time_probe_loop, a1, 1);
        long ticks = r ? r[0] : -1;
        ut_free_result(r);
        /* 100k iters ≈ 600k insns ≈ 250µs @2.4GHz ≈ 4800 ticks @19.2MHz.
         * Accept 100..50000 (real core) — TCG wall time would be ~10x. */
        bool ok = ticks >= 100 && ticks <= 50000;
        printf("[%s] %-26s ticks=%ld (~%.1f ticks/insn, host ballpark ok)\n",
               ok ? "PASS" : "FAIL", "virt-clock loop probe", ticks,
               ticks / 600000.0);
        ok ? g_pass++ : g_fail++;
        if (only == tn++) return 0;
    }
    {   /* 29: clock_gettime probe under the virtual clock */
        uint64_t a1[1] = {100000};
        long* r = invokeCall((void*)tt_time_probe_clock, a1, 1);
        long ns = r ? r[0] : -1;
        ut_free_result(r);
        /* expect ~250µs; accept 20µs..10ms */
        bool ok = ns >= 20000 && ns <= 10000000;
        printf("[%s] %-26s clock_ns=%ld (~%.0f ns/insn)\n",
               ok ? "PASS" : "FAIL", "virt-clock clock probe", ns,
               ns / 600000.0);
        ok ? g_pass++ : g_fail++;
        if (only == tn++) return 0;
    }
    {   /* 30: sleep(50ms) then clock must advance ~50ms */
        uint64_t a1[1] = {50};
        long* r = invokeCall((void*)tt_time_probe_sleep, a1, 1);
        long ns = r ? r[0] : -1;
        ut_free_result(r);
        bool ok = ns >= 40000000 && ns <= 65000000;
        printf("[%s] %-26s slept=%ld ns (want ~50ms)\n",
               ok ? "PASS" : "FAIL", "virt-clock sleep probe", ns);
        ok ? g_pass++ : g_fail++;
        if (only == tn++) return 0;
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
