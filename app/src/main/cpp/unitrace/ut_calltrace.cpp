/*
 * ut_calltrace.cpp — lightweight BL/BLR call observation.
 *
 * A "convenient observation mode": instead of tracing every instruction,
 * record only function calls —
 *
 *   call libc.so!strlen(0x7f... "hello", 0x0, 0x0, 0x0)
 *   ret  0x6 "hello"
 *
 * Arguments and return values that point at printable C strings are shown
 * inline. Enabled via ut_set_call_trace(1); independent of trace_level and
 * much cheaper than full instruction tracing: the per-instruction hook is a
 * single hash lookup on non-call instructions, and call sites are found by
 * scanning each basic block once (results cached per pc).
 */
#include "ut_internal.h"
#include "uni_trace.h"

#include <android/log.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unordered_map>
#include <vector>

#define TAG "unitrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

namespace {

constexpr uint8_t SITE_BL   = 1;   /* direct bl: target = branch_imm   */
constexpr uint8_t SITE_BLR  = 2;   /* indirect blr: target = reg       */
constexpr uint8_t SITE_RET  = 4;   /* ret (incl. ret x16/x17 variants) */

struct State {
    bool enabled = false;
    std::unordered_map<uint64_t, uint8_t> sites;   /* pc -> SITE_* flags */
    std::vector<uint64_t> lrs;                     /* pushed call-return addrs */
    std::string buf;
    bool cap_warned = false;
    size_t cap = 8u << 20;                        /* 8MB observation log cap */
} g_obs;

/* argument registers (capstone ARM64_REG_X0..X7 = 218..225, X30 = 3) */
enum { UT_CS_X0 = 218, UT_CS_LR = 3 };
const unsigned kArgCs[] = { 218, 219, 220, 221, 222, 223, 224, 225 };

void emit(const char* fmt, ...) {
    if (g_obs.buf.size() >= g_obs.cap) {
        if (!g_obs.cap_warned) {
            g_obs.cap_warned = true;
            LOGI("call-obs buffer capped at %zu bytes", g_obs.cap);
        }
        return;
    }
    char tmp[400];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    g_obs.buf.append(tmp, (size_t)(n < (int)sizeof(tmp) ? n : (int)sizeof(tmp) - 1));
    g_obs.buf.push_back('\n');
    LOGI("  %s", tmp);
}

/* format one argument: plain hex, plus inline quoted string when the value
 * is a readable printable C-string pointer */
void fmt_arg(uc_engine* uc, uint64_t v, char* out, size_t cap) {
    char sv[96];
    if (ut_probe_cstring(uc, v, sv, sizeof(sv)))
        snprintf(out, cap, "0x%llx \"%s\"", (unsigned long long)v, sv);
    else
        snprintf(out, cap, "0x%llx", (unsigned long long)v);
}

void on_call(uc_engine* uc, const struct CachedInsn* ci, uint64_t pc) {
    uint64_t target = ci->is_bl ? (uint64_t)ci->branch_imm : 0;
    if (ci->is_blr)
        target = ut_read_cs_reg(uc, ci->branch_reg);
    uint64_t real = ut_follow_plt(uc, target);
    const char* sym = ut_sym_cached(real);

    char a[4][64];
    for (int i = 0; i < 4; i++)
        fmt_arg(uc, ut_read_cs_reg(uc, kArgCs[i]), a[i], sizeof(a[i]));
    emit("call %s(0x%llx | %s, %s, %s, %s) from 0x%llx",
         sym, (unsigned long long)real, a[0], a[1], a[2], a[3],
         (unsigned long long)pc);
}

void on_ret(uc_engine* uc) {
    uint64_t x0 = ut_read_cs_reg(uc, UT_CS_X0);
    char rv[96];
    if (ut_probe_cstring(uc, x0, rv, sizeof(rv)))
        emit("ret  0x%llx \"%s\"", (unsigned long long)x0, rv);
    else
        emit("ret  0x%llx", (unsigned long long)x0);
}

} // namespace

extern "C" void ut_callobs_on_block(uc_engine* uc, uint64_t addr, uint32_t size) {
    if (!g_obs.enabled) return;
    /* scan the block once for call/ret sites (per-pc cached) */
    for (uint64_t p = addr; p < addr + size; p += 4) {
        auto it = g_obs.sites.find(p);
        if (it != g_obs.sites.end()) continue;            /* already known */
        const struct CachedInsn* ci = ut_disasm_insn(uc, p);
        if (!ci) return;                                   /* unreadable tail */
        uint8_t f = 0;
        if (ci->is_bl) f |= SITE_BL;
        if (ci->is_blr) f |= SITE_BLR;
        if (ci->is_ret) f |= SITE_RET;
        if (f) g_obs.sites.emplace(p, f);
    }
}

extern "C" void ut_callobs_on_insn(uc_engine* uc, uint64_t pc) {
    /* fast path: one hash lookup, return on miss */
    auto it = g_obs.sites.find(pc);
    if (it == g_obs.sites.end()) return;
    uint8_t f = it->second;
    if (f & (SITE_BL | SITE_BLR)) {
        const struct CachedInsn* ci = ut_disasm_insn(uc, pc);
        if (!ci) return;
        on_call(uc, ci, pc);
        /* lr = return address (pushed for ret bookkeeping/debugging) */
        g_obs.lrs.push_back(ut_read_cs_reg(uc, UT_CS_LR));
    }
    if (f & SITE_RET) {
        on_ret(uc);
        if (!g_obs.lrs.empty()) g_obs.lrs.pop_back();
    }
}

extern "C" void ut_callobs_reset(void) {
    g_obs.buf.clear();
    g_obs.lrs.clear();
    g_obs.cap_warned = false;
    /* sites survive across runs: code bytes are stable */
}

extern "C" const char* ut_callobs_text(void) { return g_obs.buf.c_str(); }
extern "C" int ut_callobs_enabled(void) { return g_obs.enabled ? 1 : 0; }

extern "C" void ut_set_call_trace(int enable) {
    g_obs.enabled = enable != 0;
    ut_engine_set_call_obs(enable);   /* arm the per-insn hook in the engine */
    g_obs.sites.clear();   /* re-scan under the new mode */
    g_obs.lrs.clear();
    /* note: buf is kept on disable so the last run's log stays readable */
    if (g_obs.enabled) LOGI("call observation enabled (bl/blr only)");
}
