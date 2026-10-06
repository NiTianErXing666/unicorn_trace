/*
 * uni_trace.h — unicorn-based arm64 tracer for Android.
 *
 * Executes a real native function (from any library loaded in this process)
 * inside a unicorn engine. Everything the emulated code needs is satisfied
 * by the real system:
 *   - unmapped memory access  -> the page is lazily mirrored from the real
 *     process address space (same virtual addresses) and execution continues
 *   - SVC (syscall)           -> arguments are forwarded 1:1 to the real
 *     kernel via syscall(); buffer arguments are synced unicorn<->real around
 *     the call so both views stay coherent
 *   - signals                 -> signal syscalls (rt_sigaction/rt_sigprocmask/
 *     kill/tgkill/tkill ...) are forwarded to the real kernel, and any signal
 *     delivered to the emulator thread runs its *real* handler natively
 *
 * Core API (exact signature requested):
 *   long* invokeCall(void* address, void* args, int args_length);
 *     - address     function to execute (real address in this process)
 *     - args        array of 64-bit values placed in x0..x7 (max 8)
 *     - args_length number of args
 *     - returns     malloc'd long[] ; ret[0] = x0 (return value).
 *                   Caller frees with free(). On hard failure returns NULL
 *                   and ut_last_error() describes the problem.
 */
#ifndef UNI_TRACE_H
#define UNI_TRACE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* trace verbosity: 0 off, 1 syscalls, 2 +basic blocks, 3 +every instruction */
void ut_set_trace_level(int level);
int  ut_get_trace_level(void);

/* create engine (idempotent). returns 0 on success */
int  ut_init(void);

/* run a function. see header top comment. */
long* invokeCall(void* address, void* args, int args_length);

/* same as invokeCall but also reports all return regs; out_regs must have
 * room for 8 entries (x0..x7) and receives the register file at return. */
long* invokeCallRegs(void* address, void* args, int args_length,
                     uint64_t* out_regs /*[8]*/);

/* error string of the last invokeCall on this thread's engine */
const char* ut_last_error(void);

/* human readable trace log of the last invokeCall (ring buffer snapshot).
 * pointer stays valid until next invokeCall. */
const char* ut_last_trace(void);

/* stats of the last invokeCall */
struct ut_stats {
    uint64_t instr_count;
    uint64_t block_count;
    uint64_t syscall_count;
    uint64_t mirrored_pages;
    uint64_t elapsed_us;
    int      exit_reason;   /* 0=returned, 1=exit/exit_group, 2=error */
    int      exit_code;     /* valid when exit_reason==1 */
};
const struct ut_stats* ut_last_stats(void);

/* free a result returned by invokeCall */
void ut_free_result(long* result);

/* ---- CPU fingerprint simulation ------------------------------------
 * "host" (default): mirror the REAL device cpu — CTR_EL0 / DCZID_EL0 are
 *   read from the host core via mrs, MIDR is reconstructed from
 *   /proc/cpuinfo, and SVE availability is gated to match a
 *   non-SVE production core (SVE instructions trap at EL0 exactly like on
 *   the real hardware, while NEON/LSE/CRC/DotProd keep working).
 * "off": raw unicorn qemu defaults.
 * Returns 0 on success. Takes effect at ut_init(). */
int ut_set_cpu_profile(const char* name);

/* host cpu values used by the "host" profile (for tests/verification) */
uint64_t ut_get_host_ctr(void);
uint64_t ut_get_host_dczid(void);
uint64_t ut_get_host_midr(void);

/* symbolize an address in the real process: writes "module!symbol+off"
 * into buf. returns buf. */
const char* ut_symbolize(uint64_t addr, char* buf, size_t bufsz);

/* expose engine readiness / basic info as text */
const char* ut_engine_info(void);

/* debug: read guest memory through the engine (returns bytes read) */
size_t ut_debug_peek_guest(uint64_t addr, void* buf, size_t len);

/* ---- GumTrace-style instruction trace --------------------------------
 * At trace level 3 the engine records every executed instruction:
 *   [module] 0xABS!0xOFF <mnemonic> <operands>; x1=0x.. mem_r=0x.. mem_w=0x..
 *   -> x0=0x..                       (register write-back)
 *   call func: name(0x.., 0x..)      (bl/blr into a symbolized target)
 *   args0: hello                     (string-lookable arguments)
 *   ret: 0x..                        (on return)
 *   svc write(0x1, 0x.., ..) = 0x23
 * ut_trace_to_file() writes the full buffer of the last invokeCall and
 * returns the number of bytes written. */
long ut_trace_to_file(const char* path);
size_t ut_trace_size(void);

/* ---- anti timing-detection: virtual clock ----------------------------
 * While enabled (default) the guest's time sources are virtualized:
 *   - MRS CNTVCT_EL0 / CNTPCT_EL0 advance per executed instruction
 *     (IPC≈1 at cpu_hz), not per TCG wall time
 *   - clock_gettime / gettimeofday are answered from the same clock
 *   - syscalls that really block (nanosleep, futex wait) fold their wall
 *     time into the virtual clock, so "sleep then check" stays consistent
 * Result: a loop measured inside the emulator reports the same
 * ticks-per-instruction as on the real core, regardless of how slow the
 * emulation actually runs. cpu_hz=0 keeps the current value. */
void ut_set_time_simulation(int enable, uint64_t cpu_hz);

/* ---- trace file -------------------------------------------------------
 * Configure a log file for automatic trace capture: after EVERY invokeCall
 * the run's trace (GumTrace-style instruction log at level 3, or the
 * syscall/block summary at lower levels) is appended with a run header.
 * The file is created (truncated) when this is set; subsequent runs keep
 * appending to it.
 * path == NULL disables. Returns 0 on success, -1 if the file cannot be
 * opened. Takes effect for all subsequent invokeCall runs. */
int ut_set_trace_file(const char* path);

/* ---- BL-call observation ---------------------------------------------
 * A lightweight observation mode (independent of trace_level): records
 * only function calls and returns:
 *
 *   call libc.so!strlen(0x7f.. "hello", 0x0, 0x0, 0x0) from 0x..
 *   ret  0x6 "hello"
 *
 * Arguments / return values that point at printable C strings are shown
 * inline in quotes. Output comes back via ut_last_trace() and is included
 * in ut_set_trace_file() logs. Much cheaper than level-3 tracing. */
void ut_set_call_trace(int enable);

/* ---- Tenet trace export ----------------------------------------------
 * While enabled, level-3 instruction tracing ALSO writes a Tenet-format
 * delta trace (one line per instruction) to the given file:
 *
 *   PC=0x5c94b92bd8,X8=0x5c94e07ea4,MR=0x7477820fd8:08e0a7...,MW=...
 *
 * Import into IDA with the Tenet plugin (NiTianErXing666/Tenet-IDA9.2)
 * for replay analysis. Each ut_set_tenet_file() call resets the file;
 * every subsequent invokeCall run appends to the same stream.
 * path == NULL disables. Returns -1 on open failure. */
int ut_set_tenet_file(const char* path);

/* debug/tests: force a /proc/self/maps snapshot refresh */
void ut_refresh_maps(void);
void ut_debug_watch(uint64_t lo, uint64_t hi);
uint64_t ut_get_brk_base(void);

#ifdef __cplusplus
}
#endif

#endif /* UNI_TRACE_H */
