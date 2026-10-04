/*
 * ut_internal.h — internal contracts between the engine core
 * (uni_trace.cpp) and the observation modules (ut_calltrace.cpp, future
 * ut_tracer.cpp ...). NOT part of the public API (see uni_trace.h).
 *
 * Split rationale: uni_trace.cpp holds the battle-tested engine core
 * (mirror / syscall forwarding / hooks). New observation features live in
 * their own translation units against the narrow surface below, so the
 * core does not keep growing.
 */
#ifndef UT_INTERNAL_H
#define UT_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- one disassembled instruction (cached per guest pc) -------------
 * filled by the engine's capstone layer; flags prepared at disasm time. */
struct CachedInsn {
    char text[200];                 /* "ldr x0, [x1, #0x10]" */
    uint16_t regs_read[24];         /* capstone cs_regs layout */
    uint8_t n_read;
    struct Wr { char name[8]; int uc; bool simd; } wr[8];
    uint8_t n_written;
    uint8_t groups[8];
    uint8_t n_groups;
    int64_t branch_imm;             /* b/bl target when direct */
    uint16_t branch_reg;            /* cs reg id for br/blr when indirect */
    bool is_bl, is_blr, is_ret, is_b;
};

/* capstone handle (lazily initialized by the engine) */
uintptr_t ut_cs_handle(void);

/* disassemble (cache) one guest instruction; null if bytes unreadable */
const struct CachedInsn* ut_disasm_insn(uc_engine* uc, uint64_t pc);

/* value of a capstone (cs) register id in the guest, e.g. ARM64_REG_X0 */
uint64_t ut_read_cs_reg(uc_engine* uc, unsigned cs_reg);

/* PLT stub -> real target (resolves adrp/ldr GOT hops; stubs cached) */
uint64_t ut_follow_plt(uc_engine* uc, uint64_t target);

/* cached symbolization "module!symbol+off" / "module+off" */
const char* ut_sym_cached(uint64_t pc);

/* try to read a printable C string from guest memory */
bool ut_probe_cstring(uc_engine* uc, uint64_t addr, char* out, size_t cap);

/* ---- BL-call observation (ut_calltrace.cpp) -------------------------
 * When enabled (ut_set_call_trace), the engine forwards every executed
 * basic block here for call-site scanning, and registers the per-instruction
 * hook below. All functions are cheap no-ops when disabled. */
void ut_callobs_on_block(uc_engine* uc, uint64_t addr, uint32_t size);
void ut_callobs_on_insn(uc_engine* uc, uint64_t pc);
void ut_callobs_reset(void);                 /* per-run state */
/* engine-side flag: registers the per-insn hook for the next runs */
void ut_engine_set_call_obs(int enable);
const char* ut_callobs_text(void);           /* observation log (may be "") */
int  ut_callobs_enabled(void);

#ifdef __cplusplus
}
#endif

#endif /* UT_INTERNAL_H */
