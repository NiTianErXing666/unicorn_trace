#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>
#include <unistd.h>

#include <android/log.h>

#include "uni_trace.h"

#define TAG "unitrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* low level JNI surface                                               */
/* ------------------------------------------------------------------ */
extern "C" JNIEXPORT jint JNICALL
Java_com_example_testtrace_MainActivity_nativeInit(JNIEnv*, jobject) {
    int r = ut_init();
    LOGI("init: %s", ut_engine_info());
    return r;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_testtrace_MainActivity_nativeSetTraceLevel(JNIEnv*, jobject, jint level) {
    ut_set_trace_level(level);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_example_testtrace_MainActivity_nativeFindSymbol(JNIEnv* env, jobject,
                                                         jstring lib, jstring sym) {
    const char* l = env->GetStringUTFChars(lib, nullptr);
    const char* s = env->GetStringUTFChars(sym, nullptr);
    void* handle = dlopen(l, RTLD_NOLOAD | RTLD_NOW);
    jlong addr = 0;
    if (handle) {
        void* p = dlsym(handle, s);
        if (p) addr = (jlong)(uintptr_t)p;
    }
    if (!addr) {
        void* p = dlsym(RTLD_DEFAULT, s);
        if (p) addr = (jlong)(uintptr_t)p;
    }
    if (handle) dlclose(handle);
    env->ReleaseStringUTFChars(lib, l);
    env->ReleaseStringUTFChars(sym, s);
    return addr;
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_example_testtrace_MainActivity_nativeInvoke(JNIEnv* env, jobject,
                                                     jlong address, jlongArray jargs) {
    jsize n = jargs ? env->GetArrayLength(jargs) : 0;
    uint64_t out[8] = {0};
    uint64_t args[8] = {0};
    if (jargs && n > 0) {
        jlong tmp[8] = {0};
        env->GetLongArrayRegion(jargs, 0, n > 8 ? 8 : n, tmp);
        for (int i = 0; i < 8; i++) args[i] = (uint64_t)tmp[i];
    }
    long* r = invokeCallRegs((void*)(uintptr_t)address, args, (int)n, out);
    jlongArray ja = env->NewLongArray(8);
    jlong cv[8];
    for (int i = 0; i < 8; i++) cv[i] = r ? (jlong)r[i] : (jlong)out[i];
    env->SetLongArrayRegion(ja, 0, 8, cv);
    ut_free_result(r);
    return ja;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_testtrace_MainActivity_nativeGetTrace(JNIEnv* env, jobject) {
    return env->NewStringUTF(ut_last_trace());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_testtrace_MainActivity_nativeGetError(JNIEnv* env, jobject) {
    return env->NewStringUTF(ut_last_error());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_testtrace_MainActivity_nativeInfo(JNIEnv* env, jobject) {
    return env->NewStringUTF(ut_engine_info());
}

/* configure automatic per-run trace logging to a file (null disables) */
extern "C" JNIEXPORT void JNICALL
Java_com_example_testtrace_MainActivity_nativeSetCallTrace(JNIEnv*, jobject,
                                                           jint enable) {
    ut_set_call_trace(enable);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_testtrace_MainActivity_nativeSetTraceFile(JNIEnv* env, jobject,
                                                           jstring path) {
    if (!path) return ut_set_trace_file(nullptr);
    const char* p = env->GetStringUTFChars(path, nullptr);
    int r = ut_set_trace_file(p);
    env->ReleaseStringUTFChars(path, p);
    return r;
}

/* ------------------------------------------------------------------ */
/* test battery: runs target functions inside the emulator             */
/* ------------------------------------------------------------------ */
static uint64_t sym(const char* name) {
    static void* target_handle = (void*)1;
    if (target_handle == (void*)1) {
        target_handle = dlopen("libtesttarget.so", RTLD_NOW | RTLD_LOCAL);
        if (!target_handle) {
            LOGI("dlopen libtesttarget.so failed: %s", dlerror());
        }
    }
    if (!target_handle) return 0;
    void* p = dlsym(target_handle, name);
    return (uint64_t)(uintptr_t)p;
}

struct TestOut {
    std::string report;
    int passed = 0, failed = 0;
};

typedef bool (*verify_fn)(uint64_t ret, void* ctx);

static bool v_eq(uint64_t ret, void* ctx) { return ret == (uint64_t)(uintptr_t)ctx; }
static bool v_nonzero(uint64_t ret, void*) { return ret != 0; }

static void run_one(TestOut& t, const char* name, uint64_t fn,
                    const uint64_t* args, int nargs,
                    verify_fn verify, void* ctx) {
    char line[512];
    if (!fn) {
        snprintf(line, sizeof(line), "[FAIL] %-26s symbol not found\n", name);
        t.report += line; t.failed++;
        return;
    }
    LOGI(">>> start %s (0x%llx)", name, (unsigned long long)fn);
    uint64_t out[8] = {0};
    long* r = invokeCallRegs((void*)(uintptr_t)fn, (void*)args, nargs, out);
    LOGI("<<< done  %s", name);
    const ut_stats* st = ut_last_stats();
    if (!r) {
        char sbuf[160];
        ut_symbolize(fn, sbuf, sizeof(sbuf));
        snprintf(line, sizeof(line), "[FAIL] %-26s %s\n         error: %s\n",
                 name, sbuf, ut_last_error());
        t.report += line; t.failed++;
        return;
    }
    bool ok = verify ? verify((uint64_t)r[0], ctx) : true;
    snprintf(line, sizeof(line),
             "[%s] %-26s ret=0x%llx (%lld)  %lluus %llublk %llusysc %llupg\n",
             ok ? "PASS" : "FAIL", name,
             (unsigned long long)(uint64_t)r[0], (long long)r[0],
             (unsigned long long)(st ? st->elapsed_us : 0),
             (unsigned long long)(st ? st->block_count : 0),
             (unsigned long long)(st ? st->syscall_count : 0),
             (unsigned long long)(st ? st->mirrored_pages : 0));
    t.report += line;
    if (ok) t.passed++; else t.failed++;
    ut_free_result(r);
}

struct SizeCtx { size_t n; };

static void battery(TestOut& t) {
    /* ---- pure math ---- */
    {
        uint64_t a[2] = {11, 31};
        run_one(t, "tt_add(11,31)", sym("tt_add"), a, 2, v_eq, (void*)(uintptr_t)42);
    }
    {
        uint64_t a[2] = {1234, 5678};
        run_one(t, "tt_mul", sym("tt_mul"), a, 2, v_eq, (void*)(uintptr_t)(1234l * 5678l));
    }
    {
        uint64_t a[1] = {30};
        run_one(t, "tt_fib(30)", sym("tt_fib"), a, 1, v_eq, (void*)(uintptr_t)832040);
    }

    /* ---- libc: string / malloc / snprintf / globals ---- */
    {
        static const char in[] = "hello unicorn tracer!";
        uint64_t a[1] = {(uint64_t)(uintptr_t)in};
        ut_debug_watch(ut_get_brk_base(), ut_get_brk_base() + 0x2000);
        run_one(t, "tt_strdup_upper", sym("tt_strdup_upper"), a, 1,
                [](uint64_t ret, void*) -> bool {
                    const char* s = (const char*)(uintptr_t)ret;
                    if (!s) return false;
                    bool ok = strcmp(s, "HELLO UNICORN TRACER!") == 0;
                    if (!ok) {
                        char dump[128] = {0};
                        int o = 0;
                        for (int k = 0; k < 22; k++) o += snprintf(dump + o, 5, "%02x ", (unsigned char)s[k]);
                        unsigned char g[24] = {0};
                        ut_debug_peek_guest((uint64_t)(uintptr_t)s, g, 22);
                        char gd[128] = {0};
                        o = 0;
                        for (int k = 0; k < 22; k++) o += snprintf(gd + o, 5, "%02x ", g[k]);
                        LOGI("strdup real: %s | guest: %s", dump, gd);
                    }
                    return ok;
                }, nullptr);
        ut_debug_watch(0, 0);
    }
    {
        uint64_t a[1] = {1000};
        long want = 0; for (int i = 0; i < 1000; i++) want += i * 3 + 1;
        run_one(t, "tt_sum_malloc(1000)", sym("tt_sum_malloc"), a, 1, v_eq, (void*)(uintptr_t)want);
    }
    {
        static char sbuf[128];
        memset(sbuf, 0, sizeof(sbuf));
        uint64_t a[3] = {(uint64_t)(uintptr_t)sbuf, 128, 1234567};
        run_one(t, "tt_snprintf", sym("tt_snprintf_test"), a, 3,
                [](uint64_t, void* ctx) -> bool {
                    return strcmp((char*)ctx, "value=1234567 hex=0x12d687") == 0;
                }, sbuf);
    }
    {
        uint64_t a[1] = {3};
        run_one(t, "tt_data_test(3)", sym("tt_data_test"), a, 1, v_eq, (void*)(uintptr_t)1004);
    }

    /* ---- raw syscalls from inside the emulator ---- */
    {
        uint64_t a[1] = {0};
        run_one(t, "tt_syscall_getpid", sym("tt_syscall_getpid"), a, 0,
                v_eq, (void*)(uintptr_t)getpid());
    }
    {
        static const char msg[] = "[emu] write(2) from inside unicorn\n";
        static SizeCtx c{sizeof(msg) - 1};
        uint64_t a[3] = {2, (uint64_t)(uintptr_t)msg, sizeof(msg) - 1};
        run_one(t, "tt_syscall_write(2)", sym("tt_syscall_write"), a, 3,
                [](uint64_t ret, void* ctx) -> bool {
                    return ret == ((SizeCtx*)ctx)->n;
                }, &c);
    }
    {
        static uint64_t tsbuf[4];   /* [0..1]=timespec [2]=marker */
        memset(tsbuf, 0, sizeof(tsbuf));
        uint64_t a[1] = {(uint64_t)(uintptr_t)tsbuf};
        run_one(t, "tt_gettime(+marker)", sym("tt_gettime"), a, 1,
                [](uint64_t ret, void* ctx) -> bool {
                    uint64_t* b = (uint64_t*)ctx;
                    /* seconds may be 0 on the virtual clock; ns + marker decide */
                    return ret == 0 && (b[1] != 0 || b[0] != 0) && b[2] == 0xABCDEF;
                }, tsbuf);
    }
    {
        static unsigned char rnd[64];
        memset(rnd, 0, sizeof(rnd));
        uint64_t a[2] = {(uint64_t)(uintptr_t)rnd, sizeof(rnd)};
        run_one(t, "tt_getrandom(64)", sym("tt_getrandom"), a, 2,
                [](uint64_t ret, void* ctx) -> bool {
                    unsigned char* b = (unsigned char*)ctx;
                    if (ret != 64) return false;
                    int nz = 0;
                    for (int i = 0; i < 64; i++) nz += (b[i] != 0);
                    return nz > 8;
                }, rnd);
    }
    {
        static char fbuf[512];
        memset(fbuf, 0, sizeof(fbuf));
        uint64_t a[3] = {(uint64_t)(uintptr_t)"/proc/self/maps",
                         (uint64_t)(uintptr_t)fbuf, sizeof(fbuf) - 1};
        run_one(t, "tt_open_read(self/maps)", sym("tt_open_read"), a, 3,
                [](uint64_t ret, void* ctx) -> bool {
                    return ret > 0 && ((char*)ctx)[0] != 0;
                }, fbuf);
    }
    {
        uint64_t a[1] = {0};
        run_one(t, "tt_errno_test", sym("tt_errno_test"), a, 0,
                [](uint64_t ret, void*) -> bool {
                    long raw = (long)(int16_t)(uint16_t)ret;
                    long libcerr = ((long)ret >> 16) & 0xFFFF;
                    return raw == -2 && libcerr == 2;   /* -ENOENT / errno ENOENT */
                }, nullptr);
    }

    /* ---- signals: real handler runs natively during emulation ---- */
    {
        uint64_t a[1] = {(uint64_t)SIGUSR2};
        run_one(t, "tt_signal_nodeliver", sym("tt_signal_test_nodeliver"), a, 1,
                [](uint64_t ret, void*) -> bool {
                    long caught = (long)ret & 0xFFFF;
                    return caught == 0;   /* handler must NOT run */
                }, nullptr);
    }
    {
        uint64_t a[1] = {(uint64_t)SIGUSR2};
        run_one(t, "tt_signal_test(SIGUSR2)", sym("tt_signal_test"), a, 1,
                [](uint64_t ret, void*) -> bool {
                    long r1 = (long)(int32_t)((uint32_t)(((uint64_t)ret) >> 32));
                    long r2 = ((long)ret >> 16) & 0xFFFF;
                    long caught = (long)ret & 0xFFFF;
                    return r1 == 0 && r2 == 0 && caught == SIGUSR2;
                }, nullptr);
    }
    {
        uint64_t a[1] = {(uint64_t)SIGSEGV};
        run_one(t, "tt_signal_test(SIGSEGV)", sym("tt_signal_test"), a, 1,
                [](uint64_t ret, void*) -> bool {
                    return (((long)ret) & 0xFFFF) == SIGSEGV;
                }, nullptr);
    }

    /* ---- futex + pthread mutex ---- */
    {
        static int word = 0;
        uint64_t a[1] = {(uint64_t)(uintptr_t)&word};
        run_one(t, "tt_futex_wake", sym("tt_futex_wake"), a, 1,
                [](uint64_t ret, void*) -> bool {
                    long old = ((long)ret >> 32) & 0xFFFFFFFF;
                    return old == 0;   /* nobody was waiting */
                }, nullptr);
    }
    {
        uint64_t a[1] = {100};
        run_one(t, "tt_mutex_test(100)", sym("tt_mutex_test"), a, 1,
                v_eq, (void*)(uintptr_t)(100l * 99 / 2));
    }

    /* ---- stack / recursion ---- */
    {
        uint64_t a[1] = {64};
        run_one(t, "tt_recsum(64)", sym("tt_recsum"), a, 1,
                v_eq, (void*)(uintptr_t)(64l * 65 / 2));
    }
    {
        uint64_t a[1] = {32};   /* 32 * 4KB frames = 128KB emulated stack */
        run_one(t, "tt_stackframe(32x4KB)", sym("tt_stackframe_test"), a, 1,
                v_nonzero, nullptr);
    }

    /* ---- memcpy hash over 64KB (write-through stress) ---- */
    {
        static unsigned char src[64 * 1024], dst[64 * 1024];
        for (size_t i = 0; i < sizeof(src); i++) src[i] = (unsigned char)(i * 131 + 7);
        memset(dst, 0, sizeof(dst));
        uint64_t a[3] = {(uint64_t)(uintptr_t)dst, (uint64_t)(uintptr_t)src, sizeof(src)};
        run_one(t, "tt_memcpy 64KB+FNV", sym("tt_memcpy_test"), a, 3,
                [](uint64_t, void*) -> bool {
                    if (memcmp(src, dst, sizeof(src)) == 0) return true;
                    for (size_t i = 0; i < sizeof(src); i++)
                        if (src[i] != dst[i]) {
                            LOGI("memcpy mismatch at +%zu (page %zu dst=%p src=%p)",
                                 i, i / 4096, (void*)dst, (void*)src);
                            break;
                        }
                    char dump[80] = {0};
                    for (int k = 0; k < 15; k++)
                        snprintf(dump + k * 3, 4, "%02x ", dst[k]);
                    LOGI("dst head: %s", dump);
                    return false;
                }, nullptr);
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_testtrace_MainActivity_nativeRunTests(JNIEnv* env, jobject) {
    ut_init();
    TestOut t;
    battery(t);
    /* ---- cpu fingerprint simulation ---- */
    {
        uint64_t a[1] = {0};
        run_one(t, "cpu CTR_EL0 == host", sym("tt_read_ctr_el0"), a, 0,
                [](uint64_t ret, void*) -> bool {
                    return ret == ut_get_host_ctr();
                }, nullptr);
    }
    {
        uint64_t a[1] = {0};
        run_one(t, "cpu DCZID_EL0 == host", sym("tt_read_dczid_el0"), a, 0,
                [](uint64_t ret, void*) -> bool {
                    return ret == ut_get_host_dczid();
                }, nullptr);
    }
    {
        /* SVE must trap like on the non-SVE host: invokeCall is expected to
         * fail with an exception — assert exactly that */
        uint64_t a[1] = {0};
        long* r = invokeCallRegs((void*)(uintptr_t)sym("tt_sve_probe"), a, 0, nullptr);
        bool ok = !r && strstr(ut_last_error(), "exception") != nullptr;
        char line[512];
        snprintf(line, sizeof(line), "[%s] %-26s %s\n", ok ? "PASS" : "FAIL",
                 "cpu SVE traps", r ? "executed (BAD)" : ut_last_error());
        t.report += line;
        if (ok) t.passed++; else t.failed++;
        ut_free_result(r);
    }
    {
        uint64_t a[1] = {0};
        run_one(t, "cpu DotProd executes", sym("tt_dotprod_probe"), a, 0,
                v_nonzero, nullptr);
    }
    {
        static long word = 100;
        uint64_t a[2] = {(uint64_t)(uintptr_t)&word, 5};
        run_one(t, "cpu LSE ldadd executes", sym("tt_lse_probe"), a, 2,
                [](uint64_t ret, void*) -> bool {
                    return ret == 100 && word == 105;
                }, nullptr);
    }

    char head[256];
    snprintf(head, sizeof(head),
             "== test battery ==\nengine: %s\n%d passed, %d failed\n",
             ut_engine_info(), t.passed, t.failed);
    std::string full = head + t.report;
    /* log line by line: logcat truncates single long messages */
    const char* p = full.c_str();
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        LOGI("%.*s", (int)n, p);
        p += n + (nl ? 1 : 0);
    }
    return env->NewStringUTF(full.c_str());
}
