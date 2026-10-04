/*
 * uni_trace.cpp — unicorn arm64 tracer with full system-call forwarding.
 *
 * Design:
 *  - one unicorn aarch64 engine per process, lazily initialized.
 *  - the real process address space is mirrored into unicorn on demand:
 *    when the emulated code touches an unmapped address we look it up in
 *    /proc/self/maps, map the page range into unicorn (RWX, same virtual
 *    address) and copy the real content in. Code from any loaded library
 *    (libc, ld, the target lib itself) therefore "just works".
 *  - SVC: every syscall is forwarded to the real kernel on the emulator
 *    thread with identical arguments (same numeric addresses → same real
 *    memory). Buffer arguments are synced unicorn->real before and
 *    real->unicorn after the syscall for the syscalls that shuffle user
 *    memory. Result is written back in raw-kernel convention (-errno).
 *  - signals: signal syscalls are forwarded; signals actually raised on
 *    the emulator thread (e.g. by tgkill) run their real native handler.
 *    Faults that happen *inside* unicorn (unmapped access to a region that
 *    is PROT_NONE or absent in the real process) are reported as an
 *    emulated SIGSEGV and stop emulation.
 */
#include "uni_trace.h"
#include "ut_internal.h"

#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>
#include <capstone/capstone.h>
#include <capstone/arm64.h>

#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#define TAG "unitrace"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* return address marker: when the traced function returns, PC lands here
 * and uc_emu_start() (with until=) stops cleanly. Never mapped. */
static uint64_t g_magic_return = 0xC0FFEE000000ULL;

static const size_t kStackBytes = 8u << 20;   /* emulated stack */
static const size_t kMaxSyncBytes = 32u << 20;

/* ------------------------------------------------------------------ */
/* /proc/self/maps cache                                               */
/* ------------------------------------------------------------------ */
struct Region {
    uint64_t start, end;   /* page aligned, [start, end) */
    int prot;              /* PROT_* */
    char path[96];
};

struct BlockEnt { uint64_t pc, size; };
struct SysEnt { uint64_t nr; uint64_t a0, a1, a2; int64_t ret; };

struct Engine {
    uc_engine* uc = nullptr;
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    bool init_ok = false;
    char init_err[256] = {0};

    size_t page = 4096;
    uint64_t stack_base = 0;    /* real mmap'd emulated stack */

    /* dedicated guest heap (brk) range: mapped in BOTH the real process and
     * unicorn at the same addresses. The guest allocator lives here, fully
     * isolated from the host engine's own malloc heap (which shares the
     * normal [heap] and would otherwise be corrupted by write-back). */
    uint64_t brk_base = 0, brk_end = 0, brk_cur = 0;

    /* real maps snapshot */
    std::vector<Region> regions;
    size_t regions_serial = 0;

    /* every range we have mapped inside unicorn */
    std::vector<std::pair<uint64_t, uint64_t>> uc_maps;

    /* page-attribute cache: see hook_write_mark. Keys are raw page numbers
     * (tag bits included, so tagged aliases stay distinct); a maps refresh
     * bumps maps_gen and the table is lazily cleared on next use. */
    std::unordered_map<uint64_t, uint32_t> page_attr;
    uint32_t maps_gen = 0;
    uint32_t page_attr_gen = 0;

    void page_attr_invalidate() {
        if (page_attr_gen != maps_gen) {
            page_attr.clear();
            page_attr_gen = maps_gen;
        }
    }
    std::vector<char> sync_buf;   /* reused by the sync helpers */

    /* real [heap] region(s): the HOST engine's own allocations live there;
     * guest write-back into these pages is always skipped (guest keeps a
     * private view) — otherwise emulated stores corrupt the tracer itself */
    std::vector<std::pair<uint64_t, uint64_t>> host_heap;

    bool in_host_heap(uint64_t a) const {
        for (auto& p : host_heap)
            if (a >= p.first && a < p.second) return true;
        return false;
    }

    /* pointer tags seen so far (scudo tags malloc results); alias views of
     * the same real page are kept in lockstep through this set */
    std::vector<uint64_t> observed_tags;
    void note_tag(uint64_t addr) {
        uint64_t t = addr & ~0x0000FFFFFFFFFFFFULL;
        if (!t) return;
        for (uint64_t x : observed_tags) if (x == t) return;
        observed_tags.push_back(t);
        if (observed_tags.size() > 8) observed_tags.erase(observed_tags.begin());
    }

    /* addresses of scudo's `orr Xd,Xn,Xm,lsl #56` pointer-tag instructions
     * inside libc; NOPed in the GUEST mirror so guest pointers stay
     * untagged (the real libc is never modified) */
    std::vector<uint64_t> tag_insn_addrs;
    uint64_t libc_base = 0, libc_end = 0;

    /* guest allocator replacement: scudo running inside the emulator is a
     * consistency hazard (tagged pointers, checksummed chunk headers), so
     * every mirrored pointer to real malloc/calloc/realloc/free is
     * redirected to a tiny SVC trampoline, served by the engine from the
     * dedicated brk range (mapped in both views, kept coherent by the
     * write-through). */
    uint64_t tramp_page = 0;
    uint64_t tramp_malloc = 0, tramp_calloc = 0, tramp_realloc = 0, tramp_free = 0;
    uint64_t bump_cur = 0;                       /* inside brk range */
    std::map<uint64_t, uint64_t> alloc_sizes;    /* ptr -> size */

    /* guest trampoline page: real mmap'd, mirrored into unicorn */
    void setup_guest_allocator();
    uint64_t real_malloc = 0, real_calloc = 0, real_realloc = 0, real_free = 0;
    std::unordered_set<uint64_t> redirected_slots;   /* guest addrs of GOT slots we rewrote */

    /* trace */
    int trace_level = 1;
    std::vector<BlockEnt> blocks;
    std::vector<SysEnt> syscalls;
    bool trace_syslog = false;
    std::unordered_set<uint64_t> dirty_pages;

    /* last run */
    char last_error[256] = {0};
    char fault_desc[256] = {0};
    std::string last_trace;
    struct ut_stats stats = {};

    /* symbolization cache */
    std::unordered_map<uint64_t, std::string> sym_cache;

    /* set by hook to abort emulation */
    bool emu_stop = false;
    bool cpu_profile_applied = false;
    std::vector<uc_hook> tracer_hooks;

    /* BL-call observation (ut_calltrace.cpp) */
    bool call_obs = false;
    uint64_t mirror_pages_run = 0;   /* runaway guard, reset per run */

    /* automatic trace log file (ut_set_trace_file) */
    FILE* trace_fp = nullptr;
    char trace_path[512] = {0};
    uint64_t trace_run_seq = 0;

    /* anti timing-detection virtual clock */
    bool time_sim = true;
    uint64_t virt_ns = 0;             /* virtual ns since engine init */
    uint64_t cpu_hz = 2400000000ull;  /* simulated core frequency */
    /* fixed-point reciprocals, refreshed once when cpu_hz changes — the
     * per-block hot path must not do 64-bit divisions */
    uint64_t rcp_ns_per_insn = 0;     /* (2^32 * 1e9) / cpu_hz */
    uint64_t rcp_ticks_per_ns = 0;    /* (2^32 * cntfrq) / 1e9 */
    uint64_t cntfrq_hz = 19200000;    /* host counter frequency */
};

static Engine* g_eng = nullptr;
uint64_t g_ut_watch_lo = 0, g_ut_watch_hi = 0, g_ut_watch_count = 0;

/* bionic malloc tags pointers with a top-byte tag (MTE/TBI); qemu honors
 * TBI inside the guest, but the real address space needs the tag removed */
static inline uint64_t untag(uint64_t a) { return a & 0x0000FFFFFFFFFFFFULL; }

/* page_attr flags (write-back hot path cache) */
#define PG_WRITABLE 1u
#define PG_PRIVATE 2u
#define PG_MAPPED 4u

/* engine-served guest allocator syscalls (see setup_guest_allocator) */
#define UT_NR_MALLOC  0x7101
#define UT_NR_CALLOC  0x7102
#define UT_NR_REALLOC 0x7103
#define UT_NR_FREE    0x7104
struct Engine;
static bool guest_alloc_syscall(uc_engine* uc, Engine* e, uint64_t nr,
                                uint64_t a0, uint64_t a1, uint64_t* out);
static void restore_real_ptrs_in(Engine* e, uint64_t pg, char* buf, size_t len);
static void reapply_redirects(Engine* e);

static uint64_t now_us() {
    using namespace std::chrono;
    return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

/* ------------------------------------------------------------------ */
/* maps parsing                                                        */
/* ------------------------------------------------------------------ */
static void parse_maps(Engine* e) {
    e->regions.clear();
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* "%lx-%lx %4s %*x %*x:%*x %*x %s" */
        uint64_t s = 0, d = 0;
        char perms[8] = {0};
        char path[96] = {0};
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %95[^\n]",
                       (unsigned long*)&s, (unsigned long*)&d, perms, path);
        if (n < 3) continue;
        Region r;
        memset(&r, 0, sizeof(r));   /* anon regions have no name: no stale garbage */
        r.start = s; r.end = d;
        r.prot = 0;
        if (strchr(perms, 'r')) r.prot |= PROT_READ;
        if (strchr(perms, 'w')) r.prot |= PROT_WRITE;
        if (strchr(perms, 'x')) r.prot |= PROT_EXEC;
        if (n >= 4) { strncpy(r.path, path, sizeof(r.path) - 1); }
        e->regions.push_back(r);
    }
    fclose(f);
    std::sort(e->regions.begin(), e->regions.end(),
              [](const Region& a, const Region& b) { return a.start < b.start; });
    e->host_heap.clear();
    for (auto& r : e->regions)
        if (strstr(r.path, "[heap]"))
            e->host_heap.emplace_back(r.start, r.end);
}


/* system library pages (libc etc.): the guest gets a PRIVATE view —
 * guest writes are never propagated to the real process, otherwise the
 * guest's mutated libc state (its allocator bookkeeping) corrupts the
 * host's live libc */
static bool is_system_region(const Region* r) {
    if (!r || !r->path[0]) return false;
    return strncmp(r->path, "/apex/", 6) == 0 ||
           strncmp(r->path, "/system/", 8) == 0;
}

static const Region* find_region(Engine* e, uint64_t addr);
static bool page_is_guest_private(Engine* e, uint64_t addr);

static const Region* find_region(Engine* e, uint64_t addr) {
    /* binary search: first region with start > addr, step back */
    auto it = std::upper_bound(e->regions.begin(), e->regions.end(), addr,
        [](uint64_t v, const Region& r) { return v < r.start; });
    if (it == e->regions.begin()) return nullptr;
    --it;
    if (addr >= it->start && addr < it->end) return &*it;
    return nullptr;
}

static bool page_is_guest_private(Engine* e, uint64_t addr) {
    return is_system_region(find_region(e, addr));
}

static bool real_addr_mapped(Engine* e, uint64_t addr, int* prot = nullptr) {
    const Region* r = find_region(e, addr);
    if (!r) {
        /* maybe a fresh mapping appeared (brk/mmap during the run) */
        parse_maps(e);
        r = find_region(e, addr);
    }
    if (r && prot) *prot = r->prot;
    return r != nullptr;
}

/* ------------------------------------------------------------------ */
/* unicorn mapping bookkeeping                                         */
/* ------------------------------------------------------------------ */
static bool uc_has(Engine* e, uint64_t addr) {
    for (auto& p : e->uc_maps)
        if (addr >= p.first && addr < p.second) return true;
    return false;
}

static void uc_add_map_rec(Engine* e, uint64_t s, uint64_t ed) {
    e->uc_maps.emplace_back(s, ed);
}

/* map [start,end) into unicorn RWX and copy real content if readable.
 * `start` may carry a pointer tag (bits 56-63, set by scudo malloc):
 * the alias is mapped AT the tagged address, content comes from the
 * untagged real address, and the caller keeps using the tagged pointer. */
static bool mirror_into_uc(Engine* e, uint64_t start, uint64_t end, int real_prot) {
    uint64_t cstart;
    start &= ~(uint64_t)(e->page - 1);
    end = (end + e->page - 1) & ~(uint64_t)(e->page - 1);
    if (start >= end) return false;

    /* never map over the magic return page */
    if (g_magic_return >= start && g_magic_return < end) {
        end = g_magic_return & ~(uint64_t)(e->page - 1);
        if (start >= end) return false;
    }

    /* clip against already-mapped ranges to avoid overlap errors */
    for (auto& p : e->uc_maps) {
        if (start < p.second && p.first < end) {
            if (p.first <= start && end <= p.second) return true; /* covered */
            if (p.first > start) end = std::min(end, p.first);
            else start = std::max(start, p.second);
        }
    }
    if (start >= end) return true;

    /* recompute the content source AFTER clipping: the real (untagged)
     * address matching the final unicorn mapping start */
    cstart = untag(start);

    uc_err err = uc_mem_map(e->uc, start, end - start, UC_PROT_ALL);
    if (e->trace_level >= 2)
        LOGI("  mirror: map [0x%llx,0x%llx) from real [0x%llx,0x%llx) prot=%d -> %s",
             (unsigned long long)start, (unsigned long long)end,
             (unsigned long long)cstart, (unsigned long long)(cstart + (end - start)),
             real_prot, err ? uc_strerror(err) : "ok");
    if (err) {
        LOGW("mirror: uc_mem_map(0x%llx..0x%llx, prot=%d) failed: %s",
             (unsigned long long)start, (unsigned long long)end, real_prot, uc_strerror(err));
        snprintf(e->fault_desc, sizeof(e->fault_desc),
                 "uc_mem_map(0x%llx..0x%llx) failed: %s",
                 (unsigned long long)start, (unsigned long long)end, uc_strerror(err));
        return false;
    }
    if (real_prot & PROT_READ) {
        /* copy content in chunks. If a twin alias of the page (same real
         * page, different pointer tag) is already mapped, inherit ITS
         * content — alias views of one real page must never diverge */
        const uint64_t tag = start & ~0x0000FFFFFFFFFFFFULL;
        const size_t CH = 256 * 1024;
        std::vector<char> tmp(CH);
        for (uint64_t off = 0; off < end - start; off += CH) {
            size_t n = std::min<uint64_t>(CH, end - start - off);
            uint64_t dst = start + off;
            uint64_t base = untag(dst);
            /* clip the real read to mapped memory */
            {
                uint64_t oklen = 0;
                while (oklen < n && real_addr_mapped(e, base + oklen)) oklen += e->page;
                if (oklen < n) n = (size_t)oklen;
                if (n == 0) break;
            }
            uint64_t src = 0;   /* twin guest page to inherit from */
            if (tag) {
                if (uc_has(e, base)) src = base;
            } else {
                for (uint64_t t : e->observed_tags) {
                    if (uc_has(e, base | t)) { src = base | t; break; }
                }
            }
            if (src) {
                if (uc_mem_read(e->uc, src, tmp.data(), n) != UC_ERR_OK)
                    memcpy(tmp.data(), (const void*)(uintptr_t)(cstart + off), n);
            } else {
                memcpy(tmp.data(), (const void*)(uintptr_t)(cstart + off), n);
            }
            /* NOP scudo's pointer-tag instructions in the guest copy only */
            if (!e->tag_insn_addrs.empty()) {
                for (uint64_t pa : e->tag_insn_addrs) {
                    if (pa >= dst && pa + 4 <= dst + n) {
                        uint32_t nop = 0xD503201Fu;
                        memcpy(tmp.data() + (pa - dst), &nop, 4);
                    }
                }
            }
            /* redirect allocator pointers to the guest trampolines */
            if (e->real_malloc) {
                for (size_t o = 0; o + 8 <= n; o += 8) {
                    uint64_t v;
                    memcpy(&v, tmp.data() + o, 8);
                    uint64_t r = 0;
                    if (v == e->real_malloc) r = e->tramp_malloc;
                    else if (v == e->real_calloc) r = e->tramp_calloc;
                    else if (v == e->real_realloc) r = e->tramp_realloc;
                    else if (v == e->real_free) r = e->tramp_free;
                    if (r) {
                        memcpy(tmp.data() + o, &r, 8);
                        /* remember that this slot was redirected so future
                         * sync_out() restores from real stay consistent */
                        e->redirected_slots.insert(dst + o);
                    }
                }
            }
            uc_mem_write(e->uc, dst, tmp.data(), n);
        }
    }
    uc_add_map_rec(e, start, end);
    e->stats.mirrored_pages += (end - start) / e->page;
    e->mirror_pages_run += (end - start) / e->page;
    if (e->mirror_pages_run > 20000) {
        /* runaway guard: a wild guest pointer walking the address space
         * would otherwise mirror forever; fail the run with a clear cause */
        snprintf(e->fault_desc, sizeof(e->fault_desc),
                 "mirror runaway: %llu pages this run (possible wild pointer)",
                 (unsigned long long)e->mirror_pages_run);
        e->emu_stop = true;
        uc_emu_stop(e->uc);
        return false;
    }
    /* record with the ACTUAL mapped address (tag included): tagged aliases
     * are distinct unicorn mappings and must not be reported as covered */
    for (uint64_t a = start; a < end; a += e->page)
        e->page_attr[a >> 12] |= PG_MAPPED;
    return true;
}

/* ------------------------------------------------------------------ */
/* unicorn <-> real sync helpers                                       */
/* ------------------------------------------------------------------ */
static bool uc_read_safe(uc_engine* uc, uint64_t addr, void* buf, size_t len) {
    return uc_mem_read(uc, addr, buf, len) == UC_ERR_OK;
}

/* unicorn -> real (real must already hold this memory).
 * tagged alias preferred: that is where the guest actually wrote */
static void sync_in(Engine* e, uint64_t addr, uint64_t len) {
    uint64_t raw = addr;
    addr = untag(addr);
    if (!addr || !len || len > kMaxSyncBytes) return;
    if (e->in_host_heap(addr)) return;   /* host heap: keep private */
    std::vector<char>& tmp = e->sync_buf;
    tmp.resize(len);
    uint64_t src = uc_has(e, raw) ? raw : (uc_has(e, addr) ? addr : 0);
    if (!src) return;   /* not in uc: real already has it */
    if (uc_mem_read(e->uc, src, tmp.data(), len) != UC_ERR_OK) return;
    int prot = 0;
    if (!real_addr_mapped(e, addr, &prot) || !(prot & PROT_WRITE)) return;
    memcpy((void*)(uintptr_t)addr, tmp.data(), len);
}

/* real -> unicorn (both the plain view and any tagged alias) */
static void sync_out(Engine* e, uint64_t addr, uint64_t len) {
    uint64_t raw = addr;
    addr = untag(addr);
    if (!addr || !len || len > kMaxSyncBytes) return;
    int prot = 0;
    if (!real_addr_mapped(e, addr, &prot) || !(prot & PROT_READ)) return;
    const void* srcp = (const void*)(uintptr_t)addr;
    if (uc_has(e, addr)) uc_mem_write(e->uc, addr, srcp, len);
    if (raw != addr && uc_has(e, raw)) uc_mem_write(e->uc, raw, srcp, len);
}

/* length of a NUL-terminated string living in unicorn memory */
static uint64_t uc_strlen(uc_engine* uc, uint64_t addr, uint64_t cap) {
    char buf[256];
    uint64_t len = 0;
    while (len < cap) {
        size_t n = std::min<uint64_t>(sizeof(buf), cap - len);
        if (uc_mem_read(uc, addr + len, buf, n) != UC_ERR_OK) break;
        void* z = memchr(buf, 0, n);
        if (z) return len + ((char*)z - buf);
        len += n;
    }
    return len; /* cap */
}

static void sync_in_str(Engine* e, uint64_t addr, uint64_t cap = 4096) {
    if (!addr) return;
    uint64_t len = uc_strlen(e->uc, addr, cap);
    sync_in(e, addr, len + 1);
}

/* sync an iovec array {base,len}^n in the given direction (in then optionally out) */
static void sync_iov(Engine* e, uint64_t iov, uint64_t cnt, bool out_bases) {
    if (!iov || !cnt || cnt > 1024) return;
    sync_in(e, iov, cnt * 16);
    std::vector<char>& tmp = e->sync_buf;
    tmp.resize(cnt * 16);
    if (uc_mem_read(e->uc, iov, tmp.data(), tmp.size()) != UC_ERR_OK) return;
    struct iov64 { uint64_t base, len; };
    iov64* v = (iov64*)tmp.data();
    for (uint64_t i = 0; i < cnt; i++) {
        if (!v[i].base || !v[i].len || v[i].len > kMaxSyncBytes) continue;
        if (out_bases) sync_out(e, v[i].base, v[i].len);
        else sync_in(e, v[i].base, v[i].len);
    }
}

/* msghdr-based socket calls */
static void sync_msghdr(Engine* e, uint64_t mh, bool is_send) {
    if (!mh) return;
    struct msghdr_kernel {
        uint64_t name; uint32_t namelen; uint32_t pad1;
        uint64_t iov; uint64_t iovlen;
        uint64_t control; uint64_t controllen;
        int32_t flags; uint32_t pad2;
    } m;
    if (!uc_read_safe(e->uc, mh, &m, sizeof(m))) return;
    sync_in(e, mh, sizeof(m));
    if (is_send) {
        if (m.name && m.namelen) sync_in(e, m.name, m.namelen);
        if (m.control && m.controllen) sync_in(e, m.control, m.controllen);
        sync_iov(e, m.iov, m.iovlen, false);
    } else {
        /* recv: after the call everything may be written back */
        sync_iov(e, m.iov, m.iovlen, true);
        if (m.name) sync_out(e, m.name, 64);
        if (m.control) sync_out(e, m.control, m.controllen ? std::min<uint64_t>(m.controllen, 4096) : 0);
        sync_out(e, mh, sizeof(m));
    }
}

/* ------------------------------------------------------------------ */
/* register access shorthands                                          */
/* ------------------------------------------------------------------ */
static inline uint64_t reg_read(uc_engine* uc, int reg) {
    uint64_t v = 0; uc_reg_read(uc, reg, &v); return v;
}
static inline void reg_write(uc_engine* uc, int reg, uint64_t v) {
    uc_reg_write(uc, reg, &v);
}

/* qemu patch hooks for the virtual counter (see gt_virt_cnt_read patch) */
extern "C" {
extern uint64_t g_ut_virt_counter_enabled;
extern uint64_t g_ut_virt_counter;
}

/* ------------------------------------------------------------------ */
/* anti timing-detection virtual clock                                */
/* ------------------------------------------------------------------ */
static uint64_t wall_ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t virt_ticks(Engine* e) {
    /* ticks = virt_ns * cntfrq / 1e9 via the fixed-point reciprocal */
    return (uint64_t)((__uint128_t)e->virt_ns * e->rcp_ticks_per_ns >> 32);
}

static void virt_advance_insns(Engine* e, uint64_t n_insns) {
    if (!e->time_sim) return;
    /* simulate IPC≈1: ns = insns * 1e9 / cpu_hz via the reciprocal */
    e->virt_ns += (uint64_t)((__uint128_t)n_insns * e->rcp_ns_per_insn >> 32);
}

static void virt_recompute_rcp(Engine* e) {
    e->rcp_ns_per_insn = (uint64_t)(((__uint128_t)1000000000ull << 32) / e->cpu_hz);
    e->rcp_ticks_per_ns = (uint64_t)(((__uint128_t)e->cntfrq_hz << 32) / 1000000000ull);
}

static void virt_advance_wall(Engine* e, uint64_t real_ns) {
    /* real time spent blocked in syscalls (sleep/futex) counts 1:1 so that
     * "sleep then check the clock" still works */
    if (!e->time_sim) return;
    e->virt_ns += real_ns;
}

/* publish the counter to the patched gt_virt_cnt_read */
static void virt_publish(Engine* e) {
    if (!e->time_sim) return;
    g_ut_virt_counter = virt_ticks(e);
    g_ut_virt_counter_enabled = 1;
}

void ut_set_time_simulation(int enable, uint64_t cpu_hz) {
    if (!g_eng) return;
    g_eng->time_sim = enable;
    if (cpu_hz) g_eng->cpu_hz = cpu_hz;
    virt_recompute_rcp(g_eng);
    g_ut_virt_counter_enabled = enable ? 1 : 0;
}

/* fabricate a timespec from the virtual clock */
static void virt_timespec(Engine* e, uint64_t addr, uint64_t extra_ns) {
    if (!addr) return;
    uint64_t ns = e->virt_ns + extra_ns;
    uint64_t v[2] = { ns / 1000000000ull, ns % 1000000000ull };
    uc_mem_write(e->uc, addr, v, 16);
}

/* ------------------------------------------------------------------ */
/* SVC: forward to the real kernel                                     */
/* ------------------------------------------------------------------ */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* sigreturn trampoline handed to the kernel as sa_restorer for handlers
 * installed from inside the emulator (bionic's wrapper would normally
 * provide this; raw syscalls bypass it). */
__attribute__((naked)) static void ut_sigreturn_tramp(void) {
    __asm__ volatile("mov x8, #139\n\tsvc #0\n");
}

/* kernel-view sigaction for arm64 */
struct k_sigaction {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

/* translate bionic userspace sigaction -> kernel layout */
static bool sigaction_to_kernel(uc_engine* uc, uint64_t guest_addr,
                                struct k_sigaction* out) {
    struct sigaction g;
    memset(&g, 0, sizeof(g));
    if (!uc_read_safe(uc, guest_addr, &g, sizeof(g))) return false;
    memset(out, 0, sizeof(*out));
    out->handler = (uint64_t)(uintptr_t)g.sa_handler;
    out->flags = (uint64_t)(unsigned)g.sa_flags | SA_RESTORER;
    out->restorer = (uint64_t)(uintptr_t)&ut_sigreturn_tramp;
    memcpy(&out->mask, &g.sa_mask, 8);   /* kernel sigsetsize is 8 */
    return true;
}

static void sigaction_from_kernel(uc_engine* uc, uint64_t guest_addr,
                                  const struct k_sigaction* k) {
    struct sigaction g;
    if (!uc_read_safe(uc, guest_addr, &g, sizeof(g))) return;
    g.sa_handler = (void (*)(int))(uintptr_t)k->handler;
    g.sa_flags = (int)(k->flags & ~((uint64_t)SA_RESTORER));
    g.sa_restorer = nullptr;
    memcpy(&g.sa_mask, &k->mask, 8);
    uc_mem_write(uc, guest_addr, &g, sizeof(g));
}

static const char* sys_name(uint64_t nr);
static void refresh_all_mirror(Engine* e);
static std::unordered_map<uint64_t, uint64_t> g_plt_cache;   /* plt stub -> target */
static const char* sym_cached(Engine* e, uint64_t pc);
static void tracer_svc(uint64_t nr, const uint64_t a[6], long ret,
                       const char* path_str);
static bool tracer_guest_str(uc_engine* uc, uint64_t addr, char* out, size_t outsz);
static void virt_timespec(Engine* e, uint64_t addr, uint64_t extra_ns);
static void trace_file_dump_run(Engine* e, uint64_t fn_addr);

static long raw_syscall6(long nr, uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    /* user pointers may carry a top-byte tag; real kernel pointers may not
     * (value args on arm64 never use bits above 47, so masking is safe) */
    a0 = untag(a0); a1 = untag(a1); a2 = untag(a2);
    a3 = untag(a3); a4 = untag(a4); a5 = untag(a5);
    long ret = (long)syscall(nr, a0, a1, a2, a3, a4, a5);
    if (ret == -1) ret = -errno;   /* raw kernel convention for the guest */
    return ret;
}

static void sys_record(Engine* e, uint64_t nr, uint64_t a0, uint64_t a1,
                       uint64_t a2, int64_t ret) {
    if (e->syscalls.size() < 4096) e->syscalls.push_back({nr, a0, a1, a2, ret});
}

static void hook_intr(uc_engine* uc, uint32_t intno, void* ud) {
    Engine* e = (Engine*)ud;
    if (intno != 2) {   /* arm64: EC 0x15 (SVC) arrives as intno 2 */
        uint64_t pc = reg_read(uc, UC_ARM64_REG_PC);
        uint32_t op = 0;
        uc_mem_read(uc, pc, &op, 4);
        char sym[160];
        ut_symbolize(pc, sym, sizeof(sym));
        snprintf(e->fault_desc, sizeof(e->fault_desc),
                 "exception intno=%u (EXCP_UDEF=undefined insn?) @ pc=0x%llx [%s] opcode=0x%08x",
                 intno, (unsigned long long)pc, sym, op);
        e->emu_stop = true;
        uc_emu_stop(uc);
        return;
    }

    uint64_t nr = reg_read(uc, UC_ARM64_REG_X8);
    uint64_t a[6] = {
        reg_read(uc, UC_ARM64_REG_X0), reg_read(uc, UC_ARM64_REG_X1),
        reg_read(uc, UC_ARM64_REG_X2), reg_read(uc, UC_ARM64_REG_X3),
        reg_read(uc, UC_ARM64_REG_X4), reg_read(uc, UC_ARM64_REG_X5),
    };

    /* engine-served calls from the guest allocator trampolines */
    if (nr >= UT_NR_MALLOC && nr <= UT_NR_FREE) {
        uint64_t out = 0;
        guest_alloc_syscall(uc, e, nr, untag(a[0]), untag(a[1]), &out);
        reg_write(uc, UC_ARM64_REG_X0, out);
        return;
    }

    long ret = 0;
    bool handled = true;
    bool forwarded = true;

    switch (nr) {
    /* ---- lifecycle: handled inside the emulator ---- */
    case 93:  /* exit */
    case 94:  /* exit_group */
        e->stats.exit_reason = 1;
        e->stats.exit_code = (int)(int64_t)a[0];
        reg_write(uc, UC_ARM64_REG_X0, a[0]);
        e->emu_stop = true;
        uc_emu_stop(uc);
        sys_record(e, nr, a[0], 0, 0, (int64_t)a[0]);
        return;
    case 139: /* rt_sigreturn — we never build emulated sigframes */
        reg_write(uc, UC_ARM64_REG_X0, 0);
        return;
    case 128: /* restart_syscall */
        ret = -EINTR;
        break;

    /* ---- not emulatable: refuse ---- */
    case 220: /* clone */
    case 435: /* clone3 */
    case 1079:/* fork */
    case 1071:/* vfork */
    case 221: /* execve */
    case 281: /* execveat */
        ret = -EPERM;
        forwarded = false;
        break;

    /* ---- memory management: forward + keep unicorn in sync ---- */
    case 222: { /* mmap */
        ret = raw_syscall6(__NR_mmap, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (ret > 0) {
            uint64_t len = (a[1] + e->page - 1) & ~(uint64_t)(e->page - 1);
            if (mirror_into_uc(e, (uint64_t)ret, (uint64_t)ret + len, PROT_READ | PROT_WRITE)) {
                if (!(a[3] & MAP_ANONYMOUS)) {
                    /* file-backed: copy what the kernel just paged in */
                    sync_out(e, (uint64_t)ret, a[1]);
                }
            }
            parse_maps(e);
        }
        break;
    }
    case 215: { /* munmap */
        ret = raw_syscall6(__NR_munmap, a[0], a[1], 0, 0, 0, 0);
        if (ret == 0) {
            uint64_t s = a[0] & ~(uint64_t)(e->page - 1);
            uint64_t ed = (a[0] + a[1] + e->page - 1) & ~(uint64_t)(e->page - 1);
            uc_mem_unmap(e->uc, s, ed - s);   /* best effort */
            e->uc_maps.erase(std::remove_if(e->uc_maps.begin(), e->uc_maps.end(),
                [&](const std::pair<uint64_t, uint64_t>& p) {
                    return !(p.second <= s || p.first >= ed);
                }), e->uc_maps.end());
            parse_maps(e);
        }
        break;
    }
    case 226: { /* mprotect */
        ret = raw_syscall6(__NR_mprotect, a[0], a[1], a[2], 0, 0, 0);
        if (ret == 0) {
            uint64_t s = a[0] & ~(uint64_t)(e->page - 1);
            uint64_t ed = (a[0] + a[1] + e->page - 1) & ~(uint64_t)(e->page - 1);
            uc_mem_protect(e->uc, s, ed - s, UC_PROT_ALL); /* best effort */
            parse_maps(e);
        }
        break;
    }
    case 214: { /* brk — served from the dedicated guest heap, never the
                   real [heap] (that would corrupt the host engine) */
        if (a[0] == 0 || a[0] < e->brk_base || a[0] > e->brk_end) {
            ret = (long)e->brk_cur;
        } else {
            if (a[0] > e->brk_cur) {
                /* grow: map zero pages in unicorn (real mapping exists) */
                uint64_t s = e->brk_cur & ~(uint64_t)(e->page - 1);
                uint64_t ed = (a[0] + e->page - 1) & ~(uint64_t)(e->page - 1);
                if (!mirror_into_uc(e, s, ed, PROT_READ | PROT_WRITE)) {
                    /* already (partially) mapped: fine */
                }
            }
            e->brk_cur = a[0];
            ret = (long)a[0];
        }
        break;
    }
    case 233: /* madvise */
    case 227: /* mlock */
    case 228: /* munlock */
    case 325: /* mlock2 */
    case 232: /* mincore */
        if (nr == __NR_mincore && a[1]) sync_out(e, a[1], a[2]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (nr == __NR_madvise) parse_maps(e);
        if (nr == __NR_mincore && a[1]) sync_out(e, a[1], a[2]);
        break;

    /* ---- io with user buffers ---- */
    case 63: /* read */
        ret = raw_syscall6(__NR_read, a[0], a[1], a[2], 0, 0, 0);
        if (ret > 0) sync_out(e, a[1], (uint64_t)ret);
        break;
    case 64: /* write */
        sync_in(e, a[1], a[2]);
        ret = raw_syscall6(__NR_write, a[0], a[1], a[2], 0, 0, 0);
        break;
    case 65: /* readv */
        sync_iov(e, a[1], a[2], false);
        ret = raw_syscall6(__NR_readv, a[0], a[1], a[2], 0, 0, 0);
        sync_iov(e, a[1], a[2], true);
        break;
    case 66: /* writev */
        sync_iov(e, a[1], a[2], false);
        ret = raw_syscall6(__NR_writev, a[0], a[1], a[2], 0, 0, 0);
        break;
    case 67: /* pread64 */
        ret = raw_syscall6(__NR_pread64, a[0], a[1], a[2], a[3], a[4], 0);
        if (ret > 0) sync_out(e, a[1], (uint64_t)ret);
        break;
    case 68: /* pwrite64 */
        sync_in(e, a[1], a[2]);
        ret = raw_syscall6(__NR_pwrite64, a[0], a[1], a[2], a[3], a[4], 0);
        break;
    case 61: /* getdents64 */
        ret = raw_syscall6(__NR_getdents64, a[0], a[1], a[2], 0, 0, 0);
        if (ret > 0) sync_out(e, a[1], (uint64_t)ret);
        break;
    case 17: /* getcwd */
        ret = raw_syscall6(__NR_getcwd, a[0], a[1], 0, 0, 0, 0);
        if (ret > 0) sync_out(e, a[0], (uint64_t)ret + 1);
        break;
    case 78: /* readlinkat */
        sync_in_str(e, a[1]);
        ret = raw_syscall6(__NR_readlinkat, a[0], a[1], a[2], a[3], 0, 0);
        if (ret > 0) sync_out(e, a[2], (uint64_t)ret + 1);
        break;

    /* ---- paths ---- */
    case 56: /* openat */
    case 48: /* faccessat */
    case 35: /* unlinkat */
    case 34: /* mkdirat */
    case 53: /* fchmodat */
        sync_in_str(e, a[1]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 38: /* renameat */
    case 37: /* linkat */
        sync_in_str(e, a[1]);
        sync_in_str(e, a[3]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 36: /* symlinkat */
        sync_in_str(e, a[0]);
        sync_in_str(e, a[2]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 279: /* memfd_create */
        sync_in_str(e, a[0]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;

    /* ---- stat family ---- */
    case 79: /* newfstatat */
        sync_in_str(e, a[1]);
        ret = raw_syscall6(__NR_newfstatat, a[0], a[1], a[2], a[3], 0, 0);
        if (ret == 0) sync_out(e, a[2], 128);
        break;
    case 80: /* fstat */
        ret = raw_syscall6(__NR_fstat, a[0], a[1], 0, 0, 0, 0);
        if (ret == 0) sync_out(e, a[1], 128);
        break;
    case 291: /* statx */
        sync_in_str(e, a[1]);
        ret = raw_syscall6(__NR_statx, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (ret == 0) sync_out(e, a[3], a[2] ? 256 : 256);
        break;
    case 43: /* statfs */
    case 44: /* fstatfs */
        ret = raw_syscall6((long)nr, a[0], a[1], 0, 0, 0, 0);
        if (ret == 0) sync_out(e, a[1], 120);
        break;

    /* ---- time: answered from the virtual clock (anti timing-detection).
     * Syscalls that really block (sleep/futex) fold their wall time into
     * the virtual clock first so "sleep then read" stays consistent. ---- */
    case 113: /* clock_gettime */
        if (e->time_sim) {
            virt_timespec(e, untag(a[1]), 0);
            ret = 0;
        } else {
            ret = raw_syscall6(__NR_clock_gettime, a[0], a[1], 0, 0, 0, 0);
            if (ret == 0) sync_out(e, a[1], 16);
        }
        break;
    case 169: /* gettimeofday */
        if (e->time_sim) {
            uint64_t ns = e->virt_ns;
            uint64_t tv[2] = { ns / 1000000000ull, (ns % 1000000000ull) / 1000ull };
            if (a[0]) uc_mem_write(uc, untag(a[0]), tv, 16);
            if (a[1]) { uint64_t tz = 0; uc_mem_write(uc, untag(a[1]), &tz, 8); }
            ret = 0;
        } else {
            ret = raw_syscall6(__NR_gettimeofday, a[0], a[1], 0, 0, 0, 0);
            if (ret == 0) { sync_out(e, a[0], 16); sync_out(e, a[1], 8); }
        }
        break;
    case 101: {/* nanosleep */
        sync_in(e, a[0], 16);
        uint64_t t0 = e->time_sim ? wall_ns_now() : 0;
        ret = raw_syscall6(__NR_nanosleep, a[0], a[1], 0, 0, 0, 0);
        if (e->time_sim) virt_advance_wall(e, wall_ns_now() - t0);
        sync_out(e, a[1], 16);
        break;
    }
    case 115: {/* clock_nanosleep */
        sync_in(e, a[2], 16);
        uint64_t t0 = e->time_sim ? wall_ns_now() : 0;
        ret = raw_syscall6(__NR_clock_nanosleep, a[0], a[1], a[2], a[3], 0, 0);
        if (e->time_sim) virt_advance_wall(e, wall_ns_now() - t0);
        sync_out(e, a[3], 16);
        break;
    }

    /* ---- signals: forwarded to the real system ---- */
    case 134: { /* rt_sigaction — bionic layout differs from kernel layout */
        struct k_sigaction k = {}, kold = {};
        bool have_new = a[1] && sigaction_to_kernel(uc, a[1], &k);
        ret = raw_syscall6(__NR_rt_sigaction, a[0],
                           have_new ? (uint64_t)(uintptr_t)&k : 0,
                           a[2] ? (uint64_t)(uintptr_t)&kold : 0, 8, 0, 0);
        if (ret == 0 && a[2]) sigaction_from_kernel(uc, a[2], &kold);
        break;
    }
    case 135: { /* rt_sigprocmask */
        if (a[1] && a[3]) sync_in(e, a[1], a[3]);
        ret = raw_syscall6(__NR_rt_sigprocmask, a[0], a[1], a[2], a[3], 0, 0);
        if (ret == 0 && a[2] && a[3]) sync_out(e, a[2], a[3]);
        break;
    }
    case 132: { /* sigaltstack */
        sync_in(e, a[1], 24);
        ret = raw_syscall6(__NR_sigaltstack, a[0], a[1], a[2], 0, 0, 0);
        if (ret == 0) sync_out(e, a[2], 24);
        break;
    }
    case 138: /* rt_sigqueueinfo */
    case 240: /* rt_tgsigqueueinfo */
        sync_in(e, a[2], 128);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 129: case 130: case 131: /* kill / tkill / tgkill */
        if (e->trace_level >= 1)
            LOGI("  svc kill-class %llu(0x%llx,0x%llx,0x%llx) about to forward",
                 (unsigned long long)nr,
                 (unsigned long long)a[0], (unsigned long long)a[1],
                 (unsigned long long)a[2]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        /* a real handler may have run natively and written real memory;
         * make those writes visible to the guest */
        refresh_all_mirror(e);
        if (e->trace_level >= 1) LOGI("  svc kill-class returned %ld", (long)ret);
        break;
    case 172: case 178:           /* getpid / gettid — plain forward */
    default_forward:
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;

    /* ---- futex: keep the futex word coherent both ways ---- */
    case 98: { /* futex */
        sync_in(e, a[0], 4);
        uint64_t t0 = e->time_sim ? wall_ns_now() : 0;
        ret = raw_syscall6(__NR_futex, a[0], a[1], a[2], a[3], a[4], a[5]);
        /* waiting on a futex really blocks: fold that wall time in */
        if (e->time_sim) virt_advance_wall(e, wall_ns_now() - t0);
        sync_out(e, a[0], 4);
        break;
    }

    /* ---- sockets ---- */
    case 200: case 201: case 203: /* bind listen connect */
        sync_in(e, a[1], a[2]);
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 206: /* sendto */
        sync_in(e, a[1], a[2]);
        if (a[4] && a[5]) sync_in(e, a[4], a[5]);
        ret = raw_syscall6(__NR_sendto, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 207: /* recvfrom */
        ret = raw_syscall6(__NR_recvfrom, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (ret > 0) sync_out(e, a[1], (uint64_t)ret);
        if (a[4]) { sync_out(e, a[4], 128); sync_out(e, a[5], 4); }
        break;
    case 212: /* recvmsg */
        ret = raw_syscall6(__NR_recvmsg, a[0], a[1], a[2], 0, 0, 0);
        sync_msghdr(e, a[1], false);
        break;
    case 211: /* sendmsg */
        sync_msghdr(e, a[1], true);
        ret = raw_syscall6(__NR_sendmsg, a[0], a[1], a[2], 0, 0, 0);
        break;
    case 52: /* fchmod — no user buffer */
        ret = raw_syscall6(__NR_fchmod, a[0], a[1], 0, 0, 0, 0);
        break;
    case 209: /* getsockopt */
        ret = raw_syscall6(__NR_getsockopt, a[0], a[1], a[2], a[3], a[4], 0);
        if (ret == 0 && a[3] && a[4]) {
            uint32_t len = 0;
            if (uc_read_safe(e->uc, a[4], &len, 4)) sync_out(e, a[3], len);
        }
        break;
    case 208: /* setsockopt */
        if (a[3] && a[4]) sync_in(e, a[3], a[4]);
        ret = raw_syscall6(__NR_setsockopt, a[0], a[1], a[2], a[3], a[4], 0);
        break;
    case 242: /* accept4 */
    case 202: /* accept */
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], 0, 0);
        if (ret >= 0 && a[1]) { sync_out(e, a[1], 128); sync_out(e, a[2], 4); }
        break;
    case 199: /* socketpair */
        ret = raw_syscall6(__NR_socketpair, a[0], a[1], a[2], a[3], 0, 0);
        if (ret == 0) sync_out(e, a[3], 16);
        break;

    /* ---- misc struct-out ---- */
    case 179: /* sysinfo */
        ret = raw_syscall6(__NR_sysinfo, a[0], 0, 0, 0, 0, 0);
        if (ret == 0) sync_out(e, a[0], 112);
        break;
    case 160: /* uname */
        ret = raw_syscall6(__NR_uname, a[0], 0, 0, 0, 0, 0);
        if (ret == 0) sync_out(e, a[0], 400);
        break;
    case 278: /* getrandom */
        ret = raw_syscall6(__NR_getrandom, a[0], a[1], a[2], 0, 0, 0);
        if (ret > 0) sync_out(e, a[0], (uint64_t)ret);
        break;
    case 163: /* getrlimit */
        ret = raw_syscall6(__NR_getrlimit, a[0], a[1], 0, 0, 0, 0);
        if (ret == 0) sync_out(e, a[1], 16);
        break;
    case 164: /* setrlimit */
        sync_in(e, a[1], 16);
        ret = raw_syscall6(__NR_setrlimit, a[0], a[1], 0, 0, 0, 0);
        break;
    case 261: { /* prlimit64 */
        sync_in(e, a[2], 16);
        ret = raw_syscall6(__NR_prlimit64, a[0], a[1], a[2], a[3], 0, 0);
        if (ret == 0) sync_out(e, a[3], 16);
        break;
    }
    case 165: /* getrusage */
    case 260: /* wait4 */
        if (nr == __NR_wait4) {
            ret = raw_syscall6(__NR_wait4, a[0], a[1], a[2], a[3], 0, 0);
            if (a[1]) sync_out(e, a[1], 4);
        } else {
            ret = raw_syscall6(__NR_getrusage, a[0], a[1], 0, 0, 0, 0);
        }
        if (ret == 0) sync_out(e, nr == __NR_wait4 ? a[3] : a[1], 144);
        break;
    case 73: { /* ppoll (arm64 generic has no separate poll) */
        sync_in(e, a[0], a[1] * 8);
        if (a[2]) sync_in(e, a[2], 16);
        if (a[3]) sync_in(e, a[3], 8);
        ret = raw_syscall6(__NR_ppoll, a[0], a[1], a[2], a[3], a[4], 0);
        sync_out(e, a[0], a[1] * 8);
        if (a[2]) sync_out(e, a[2], 16);
        break;
    }
    case 22: /* epoll_pwait (arm64 has no epoll_wait) */
        if (a[3]) sync_in(e, a[3], 8);
        ret = raw_syscall6(__NR_epoll_pwait, a[0], a[1], a[2], a[3], a[4], 0);
        if (ret > 0) sync_out(e, a[1], (uint64_t)ret * 12);
        break;
    case 59: /* pipe2 */
        ret = raw_syscall6(__NR_pipe2, a[0], a[1], 0, 0, 0, 0);
        if (ret == 0) sync_out(e, a[0], 8);
        break;
    case 158: /* getgroups */
        ret = raw_syscall6(__NR_getgroups, a[0], a[1], 0, 0, 0, 0);
        if (ret > 0) sync_out(e, a[1], (uint64_t)ret * 4);
        break;
    case 159: /* setgroups */
        sync_in(e, a[1], a[0] * 4);
        ret = raw_syscall6(__NR_setgroups, a[0], a[1], 0, 0, 0, 0);
        break;
    case 123: /* sched_getaffinity */
        ret = raw_syscall6(__NR_sched_getaffinity, a[0], a[1], a[2], 0, 0, 0);
        if (ret > 0) sync_out(e, a[2], (uint64_t)ret);
        break;
    case 122: /* sched_setaffinity */
        sync_in(e, a[2], a[3]);
        ret = raw_syscall6(__NR_sched_setaffinity, a[0], a[1], a[2], 0, 0, 0);
        break;
    case 270: { /* process_vm_readv */
        sync_iov(e, a[1], a[2], false);
        ret = raw_syscall6(__NR_process_vm_readv, a[0], a[1], a[2], a[3], a[4], a[5]);
        sync_iov(e, a[1], a[2], true);
        break;
    }
    case 271: /* process_vm_writev */
        sync_iov(e, a[1], a[2], false);
        ret = raw_syscall6(__NR_process_vm_writev, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    case 116: /* syslog */
        ret = raw_syscall6(__NR_syslog, a[0], a[1], a[2], 0, 0, 0);
        if (nr == __NR_syslog && a[0] == 3 && ret > 0) sync_out(e, a[1], (uint64_t)ret);
        break;
    case 167: { /* prctl */
        if (a[0] == 15 /* PR_SET_NAME */ && a[1]) sync_in(e, a[1], 16);
        ret = raw_syscall6(__NR_prctl, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (a[0] == 16 /* PR_GET_NAME */ && a[1] && ret == 0) sync_out(e, a[1], 16);
        break;
    }
    case 29: /* ioctl — variadic, best effort */
    default:
        handled = false;
        ret = raw_syscall6((long)nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        break;
    }
    (void)handled; (void)forwarded;

    reg_write(uc, UC_ARM64_REG_X0, (uint64_t)(int64_t)ret);
    e->stats.syscall_count++;
    sys_record(e, nr, a[0], a[1], a[2], ret);
    if (e->trace_level >= 1)
        LOGI("  svc %s(%#x,%#x,%#x,...) = %#llx", sys_name(nr),
             (unsigned)a[0], (unsigned)a[1], (unsigned)a[2],
             (unsigned long long)(uint64_t)(int64_t)ret);
    /* GumTrace-style svc line into the instruction trace buffer */
    if (e->trace_level >= 3) {
        char pathbuf[128];
        const char* pathp = nullptr;
        if (nr == 56 || nr == 79 || nr == 48 || nr == 78) {  /* openat/newfstatat/faccessat/readlinkat */
            uint64_t pa = (nr == 79 || nr == 48) ? a[1] : (nr == 78 ? a[1] : a[1]);
            if (tracer_guest_str(uc, untag(pa), pathbuf, sizeof(pathbuf)))
                pathp = pathbuf;
        }
        tracer_svc(nr, a, ret, pathp);
    }
}


/* ------------------------------------------------------------------ */
/* GumTrace-style instruction tracer                                   */
/* ------------------------------------------------------------------ */
/* CachedInsn lives in ut_internal.h (shared with ut_calltrace.cpp) */

/* Tenet-format export (defined near the file tail) */
static FILE* g_tenet_fp;
static void tenet_emit(uc_engine* uc, uint64_t pc);

struct TraceState {
    csh cs = 0;
    std::unordered_map<uint64_t, CachedInsn> icache;
    std::string buf;                /* the trace text */
    /* call frames: LR of each bl/blr */
    std::vector<uint64_t> call_stack;
    size_t buf_cap = 64u << 20;     /* 64MB trace cap */
} g_tr;

/* capstone AArch64 register -> unicorn register (and kind) */
struct RegMapEnt { int cs; int uc; bool simd; };
static std::vector<RegMapEnt> g_regmap;
static int g_cs_x0 = -1, g_cs_sp = -1, g_cs_lr = -1, g_cs_fp = -1;

static void tracer_init(void) {
    if (g_tr.cs) return;
    cs_err ce = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &g_tr.cs);
    if (ce != CS_ERR_OK) {
        LOGW("capstone cs_open failed: %d", (int)ce);
        g_tr.cs = 0;
        return;
    }
    cs_option(g_tr.cs, CS_OPT_DETAIL, CS_OPT_ON);
    g_regmap.clear();
    for (int i = 0; i <= 30; i++) {
        /* capstone: X0..X30 / W0..W30 share numeric range */
        g_regmap.push_back({ARM64_REG_X0 + i,
                            (i == 29) ? (int)UC_ARM64_REG_FP : (i == 30) ? (int)UC_ARM64_REG_LR
                                                                        : (int)(UC_ARM64_REG_X0 + i),
                            false});
        g_regmap.push_back({ARM64_REG_W0 + i,
                            (i == 29) ? (int)UC_ARM64_REG_FP : (i == 30) ? (int)UC_ARM64_REG_LR
                                                                        : (int)(UC_ARM64_REG_X0 + i),
                            false});
    }
    /* fp/simd views all map to the unicorn v registers */
    for (int i = 0; i <= 31; i++) {
        g_regmap.push_back({ARM64_REG_Q0 + i, (int)(UC_ARM64_REG_V0 + i), true});
        g_regmap.push_back({ARM64_REG_D0 + i, (int)(UC_ARM64_REG_V0 + i), true});
        g_regmap.push_back({ARM64_REG_S0 + i, (int)(UC_ARM64_REG_V0 + i), true});
        g_regmap.push_back({ARM64_REG_H0 + i, (int)(UC_ARM64_REG_V0 + i), true});
        g_regmap.push_back({ARM64_REG_B0 + i, (int)(UC_ARM64_REG_V0 + i), true});
    }
    g_regmap.push_back({ARM64_REG_SP, (int)UC_ARM64_REG_SP, false});
    g_regmap.push_back({ARM64_REG_LR, (int)UC_ARM64_REG_LR, false});
    g_regmap.push_back({ARM64_REG_FP, (int)UC_ARM64_REG_FP, false});
    g_regmap.push_back({ARM64_REG_X29, (int)UC_ARM64_REG_FP, false});
    g_regmap.push_back({ARM64_REG_X30, (int)UC_ARM64_REG_LR, false});
    g_cs_x0 = ARM64_REG_X0;
}

static const CachedInsn* disasm_cache(uc_engine* uc, uint64_t pc) {
    auto it = g_tr.icache.find(pc);
    if (it != g_tr.icache.end()) return &it->second;
    uint32_t code = 0;
    uc_err mrc = uc_mem_read(uc, pc, &code, 4);
    if (mrc != UC_ERR_OK) {
        LOGI("disasm_cache: uc_mem_read(0x%llx) -> %s",
             (unsigned long long)pc, uc_strerror(mrc));
        return nullptr;
    }
    cs_insn* ci_arr = nullptr;
    size_t nci = cs_disasm(g_tr.cs, (const uint8_t*)&code, 4, pc, 1, &ci_arr);
    if (nci != 1 || !ci_arr) {
        LOGI("disasm_cache: cs_disasm(0x%llx) failed, code=%08x",
             (unsigned long long)pc, code);
        if (ci_arr) cs_free(ci_arr, nci);
        return nullptr;
    }
    cs_insn* ci = ci_arr;
    CachedInsn c;
    memset(&c, 0, sizeof(c));
    snprintf(c.text, sizeof(c.text), "%s %s", ci->mnemonic, ci->op_str);
    cs_regs rd, wr;
    uint8_t nrd, nwr;
    if (cs_regs_access(g_tr.cs, ci, rd, &nrd, wr, &nwr) == CS_ERR_OK)
        c.n_read = (uint8_t)std::min<int>(nrd, (int)sizeof(c.regs_read));
    memcpy(c.regs_read, rd, c.n_read);
    /* writeback registers: resolve names + unicorn ids while we still have
     * the capstone detail around */
    for (uint8_t i = 0; i < nwr && i < 8; i++) {
        const char* nm = cs_reg_name(g_tr.cs, wr[i]);
        if (!nm) continue;
        for (auto& m : g_regmap)
            if (m.cs == (int)wr[i]) {
                snprintf(c.wr[c.n_written].name, 8, "%s", nm);
                c.wr[c.n_written].uc = m.uc;
                c.wr[c.n_written].simd = m.simd;
                c.n_written++;
                break;
            }
    }
    for (uint8_t i = 0; i < ci->detail->groups_count && i < 8; i++)
        c.groups[i] = (uint8_t)ci->detail->groups[i];
    c.n_groups = (uint8_t)std::min<int>(ci->detail->groups_count, 8);
    for (int i = 0; i < ci->detail->groups_count; i++) {
        unsigned g = ci->detail->groups[i];
        if (g == ARM64_GRP_CALL) {
            /* bl (direct) vs blr (indirect) */
            if (strncmp(ci->mnemonic, "bl", 2) == 0 && ci->detail->arm64.op_count >= 1 &&
                ci->detail->arm64.operands[0].type == ARM64_OP_IMM) {
                c.is_bl = true;
                c.branch_imm = ci->detail->arm64.operands[0].imm;
            } else {
                c.is_blr = true;
                if (ci->detail->arm64.op_count >= 1 &&
                    ci->detail->arm64.operands[0].type == ARM64_OP_REG)
                    c.branch_reg = (uint8_t)ci->detail->arm64.operands[0].reg;
            }
        } else if (g == ARM64_GRP_RET) {
            c.is_ret = true;
        } else if (g == ARM64_GRP_JUMP && strncmp(ci->mnemonic, "b", 1) == 0 &&
                   ci->detail->arm64.op_count >= 1 &&
                   ci->detail->arm64.operands[0].type == ARM64_OP_IMM) {
            c.is_b = true;
            c.branch_imm = ci->detail->arm64.operands[0].imm;
        }
    }
    cs_free(ci_arr, 1);
    auto res = g_tr.icache.emplace(pc, c);
    return &res.first->second;
}

static uint64_t uc_read_reg(uc_engine* uc, int ucreg, bool simd) {
    if (simd) {
        uint64_t v[2] = {0, 0};
        uc_reg_read(uc, ucreg, v);
        return v[0];
    }
    uint64_t v = 0;
    uc_reg_read(uc, ucreg, &v);
    return v;
}

/* module!sym string for a guest pc: "[libc.so] 0x7e..!0xbf4e0" prefix */
static void tracer_loc_prefix(uint64_t pc, char* out, size_t outsz) {
    Dl_info info = {};
    char sym[128];
    const char* mod = "??";
    uint64_t off = pc;
    if (dladdr((void*)(uintptr_t)pc, &info) && info.dli_fname) {
        const char* b = strrchr(info.dli_fname, '/');
        mod = b ? b + 1 : info.dli_fname;
        off = pc - (uint64_t)(uintptr_t)info.dli_fbase;
    }
    (void)sym;
    snprintf(out, outsz, "[%s] 0x%llx!0x%llx ", mod,
             (unsigned long long)pc, (unsigned long long)off);
}

/* append a line to the trace buffer (skips when the cap is reached) */
static void tracer_line(const char* fmt, ...) {
    if (g_tr.buf.size() >= g_tr.buf_cap) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            LOGI("instruction trace buffer capped at %zu bytes", g_tr.buf_cap);
        }
        return;
    }
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    g_tr.buf.append(tmp, (size_t)std::min<int>(n, (int)sizeof(tmp) - 1));
    g_tr.buf.push_back('\n');
}

/* try to read a C string from guest memory for call-arg decoration */
static bool tracer_guest_str(uc_engine* uc, uint64_t addr, char* out, size_t outsz) {
    if (!addr || addr > 0x0000FFFFFFFFFFFFULL) return false;
    uint64_t raw = 0;
    if (uc_mem_read(uc, addr, &raw, 8) != UC_ERR_OK) return false; /* probe */
    size_t i = 0;
    while (i + 8 <= outsz - 1) {
        if (uc_mem_read(uc, addr + i, out + i, 8) != UC_ERR_OK) break;
        bool done = false;
        for (int k = 0; k < 8; k++) {
            unsigned char c = (unsigned char)out[i + k];
            if (c == 0) { done = true; break; }
            if (c < 0x20 || c > 0x7e) return false;   /* not printable */
        }
        if (done) return true;
        i += 8;
    }
    return false;
}

/* one trace line is assembled in stages: the prefix (module, address,
 * disassembly, read-register values) is composed before the instruction
 * runs; the mem_r/mem_w fields fill up while it runs; the write-back
 * register values are read when the next instruction's hook fires (the
 * state has then advanced past this instruction). */
struct PendingLine {
    bool valid = false;
    uint64_t pc = 0;
    char prefix[448];
    uint64_t mem_r[4]; int mem_rsz[4]; int mem_r_n = 0;
    uint64_t mem_w[4]; int mem_wsz[4]; int mem_w_n = 0;
    CachedInsn::Wr wr[8]; int wr_n = 0;
    bool is_bl = false, is_blr = false, is_ret = false;
    uint64_t branch_imm = 0;
    uint8_t branch_reg = 0;
} g_pend;

/* if target is a PLT stub (adrp x16; ldr x17,[x16,#off]; add x16..; br x17),
 * read the GOT slot and return the real function address (else target) */
static uint64_t follow_plt_impl(uc_engine* uc, uint64_t target) {
    for (int hop = 0; hop < 3; hop++) {
        const CachedInsn* c = disasm_cache(uc, target);
        if (!c || strncmp(c->text, "adrp", 4) != 0) return target;
        uint32_t raw[4];
        if (uc_mem_read(uc, target, raw, 16) != UC_ERR_OK) return target;
        uint32_t adrp = raw[0];
        if (((adrp >> 24) & 0x9f) != 0x90) return target;
        /* adrp immediate: immhi:immlo is a signed 21-bit page offset */
        uint64_t imm21 = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2);
        int64_t simm = (int64_t)((int32_t)(imm21 << 11)) >> 11;
        uint64_t page = (target & ~0xfffull) + ((uint64_t)simm << 12);
        uint64_t slot = page;
        uint32_t ldr = raw[1];
        if (((ldr >> 22) & 0x3ff) == 0x3e5) {
            slot += ((ldr >> 10) & 0xfff) << 3;
        } else {
            return target;
        }
        uint64_t fn = 0;
        if (uc_mem_read(uc, slot, &fn, 8) != UC_ERR_OK || !fn) return target;
        if (fn == target) return target;
        target = untag(fn);
    }
    return target;
}

static uint64_t follow_plt(uc_engine* uc, uint64_t target) {
    /* stub bytes never change: resolve each stub once */
    auto it = g_plt_cache.find(target);
    if (it != g_plt_cache.end()) return it->second;
    uint64_t resolved = follow_plt_impl(uc, target);
    g_plt_cache.emplace(target, resolved);
    return resolved;
}

static void tracer_finalize(uc_engine* uc) {
    if (!g_pend.valid) return;
    tenet_emit(uc, g_pend.pc);
    /* full line: prefix + memory-access fields observed during execution */
    char tail[160];
    tail[0] = 0;
    int o = 0;
    for (int i = 0; i < g_pend.mem_r_n && o < 70; i++)
        o += snprintf(tail + o, sizeof(tail) - o, " mem_r=0x%llx",
                      (unsigned long long)g_pend.mem_r[i]);
    for (int i = 0; i < g_pend.mem_w_n && o < 150; i++)
        o += snprintf(tail + o, sizeof(tail) - o, " mem_w=0x%llx",
                      (unsigned long long)g_pend.mem_w[i]);
    tracer_line("%s%s", g_pend.prefix, tail);

    /* write-back */
    if (g_pend.wr_n) {
        char wb[256];
        int wo = snprintf(wb, sizeof(wb), "->");
        for (int i = 0; i < g_pend.wr_n && wo < (int)sizeof(wb) - 40; i++)
            wo += snprintf(wb + wo, sizeof(wb) - wo, " %s=0x%llx",
                           g_pend.wr[i].name,
                           (unsigned long long)uc_read_reg(uc, g_pend.wr[i].uc,
                                                           g_pend.wr[i].simd));
        tracer_line("%s", wb);
    }

    /* call decoration: bl/blr arguments are still intact right after the
     * branch instruction executed */
    if (g_pend.is_bl || g_pend.is_blr) {
        uint64_t target = g_pend.is_bl ? g_pend.branch_imm : 0;
        if (g_pend.is_blr) {
            for (auto& m : g_regmap)
                if (m.cs == (int)g_pend.branch_reg) {
                    target = uc_read_reg(uc, m.uc, m.simd);
                    break;
                }
        }
        target = follow_plt(uc, target);
        char sbuf[192];
        if (g_eng) {
            snprintf(sbuf, sizeof(sbuf), "%s", sym_cached(g_eng, target));
        } else {
            ut_symbolize(target, sbuf, sizeof(sbuf));
        }
        uint64_t args[8];
        static const int argregs[8] = {
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        };
        for (int i = 0; i < 8; i++)
            args[i] = uc_read_reg(uc, argregs[i], false);
        tracer_line("call func: %s(0x%llx, 0x%llx, 0x%llx, 0x%llx)",
                    sbuf,
                    (unsigned long long)args[0], (unsigned long long)args[1],
                    (unsigned long long)args[2], (unsigned long long)args[3]);
        char sv[96];
        for (int i = 0; i < 3; i++)
            if (tracer_guest_str(uc, args[i], sv, sizeof(sv)))
                tracer_line("args%d: %s", i, sv);
        g_tr.call_stack.push_back(reg_read(uc, UC_ARM64_REG_LR));
    }
    if (g_pend.is_ret) {
        if (!g_tr.call_stack.empty()) g_tr.call_stack.pop_back();
        tracer_line("ret: 0x%llx",
                    (unsigned long long)reg_read(uc, UC_ARM64_REG_X0));
    }

    g_pend.valid = false;
}

static void tracer_insn(uc_engine* uc, uint64_t pc) {
    if (g_eng) g_eng->stats.instr_count++;

    /* close the previous line now that the state has advanced */
    tracer_finalize(uc);

    const CachedInsn* ci = disasm_cache(uc, pc);
    if (!ci) {
        tracer_line("[??] 0x%llx!0x%llx <und>", (unsigned long long)pc,
                    (unsigned long long)pc);
        return;
    }

    char head[160];
    tracer_loc_prefix(pc, head, sizeof(head));
    char line[448];
    int o = snprintf(line, sizeof(line), "%s%s;", head, ci->text);
    for (int i = 0; i < ci->n_read && o < (int)sizeof(line) - 48; i++) {
        const char* nm = cs_reg_name(g_tr.cs, ci->regs_read[i]);
        int ureg = -1; bool simd = false;
        for (auto& m : g_regmap)
            if (m.cs == (int)ci->regs_read[i]) { ureg = m.uc; simd = m.simd; break; }
        if (ureg < 0 || !nm) continue;
        o += snprintf(line + o, sizeof(line) - o, " %s=0x%llx", nm,
                      (unsigned long long)uc_read_reg(uc, ureg, simd));
    }
    if (o < 0) o = 0;

    g_pend = PendingLine{};
    g_pend.valid = true;
    g_pend.pc = pc;
    memcpy(g_pend.prefix, line, (size_t)o + 1);
    g_pend.wr_n = ci->n_written;
    memcpy(g_pend.wr, ci->wr, sizeof(ci->wr));
    g_pend.is_bl = ci->is_bl; g_pend.is_blr = ci->is_blr; g_pend.is_ret = ci->is_ret;
    g_pend.branch_imm = ci->branch_imm;
    g_pend.branch_reg = ci->branch_reg;
}

/* memory hooks feeding the mem_r/mem_w fields of the current instruction */
static void tracer_mem(uc_engine* uc, uc_mem_type type, uint64_t address,
                       int size, int64_t value, void* ud) {
    (void)uc; (void)size; (void)value; (void)ud;
    if (!g_pend.valid) return;
    int sz = size > 0 && size <= 64 ? size : 8;
    if (type == UC_MEM_READ) {
        if (g_pend.mem_r_n < 4 &&
            (g_pend.mem_r_n == 0 || g_pend.mem_r[g_pend.mem_r_n - 1] != address)) {
            g_pend.mem_r[g_pend.mem_r_n] = address;
            g_pend.mem_rsz[g_pend.mem_r_n] = sz;
            g_pend.mem_r_n++;
        }
    } else if (type == UC_MEM_WRITE) {
        if (g_pend.mem_w_n < 4 &&
            (g_pend.mem_w_n == 0 || g_pend.mem_w[g_pend.mem_w_n - 1] != address)) {
            g_pend.mem_w[g_pend.mem_w_n] = address;
            g_pend.mem_wsz[g_pend.mem_w_n] = sz;
            g_pend.mem_w_n++;
        }
    }
}

/* svc line in GumTrace style (also mirrors to logcat at level >= 1) */
static void tracer_svc(uint64_t nr, const uint64_t a[6], long ret,
                       const char* path_str /*nullable*/) {
    if (g_eng && g_eng->trace_level >= 3) {
        tracer_line("svc %s(0x%llx, 0x%llx, 0x%llx, 0x%llx) = 0x%llx",
                    sys_name(nr),
                    (unsigned long long)untag(a[0]), (unsigned long long)untag(a[1]),
                    (unsigned long long)untag(a[2]), (unsigned long long)untag(a[3]),
                    (unsigned long long)(uint64_t)(int64_t)ret);
        if (path_str) tracer_line("path: %s", path_str);
    }
}

/* ------------------------------------------------------------------ */
/* unmapped access: lazy mirror from the real process                  */
/* ------------------------------------------------------------------ */
static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type,
                             uint64_t address, int size, int64_t value,
                             void* ud) {
    Engine* e = (Engine*)ud;
    uint64_t raw = address;          /* may carry a tag: map the alias */
    address = untag(address);
    e->note_tag(raw);

    if (address == g_magic_return) {
        /* shouldn't happen (handled by until=), but stop cleanly */
        e->emu_stop = true;
        uc_emu_stop(uc);
        return false;
    }

    /* which real region covers this? */
    int prot = 0;
    if (!real_addr_mapped(e, address, &prot)) {
        uint64_t pc = untag(reg_read(uc, UC_ARM64_REG_PC));
        uint32_t op = 0, op_real = 0;
        uc_mem_read(uc, pc, &op, 4);
        if (real_addr_mapped(e, pc)) memcpy(&op_real, (const void*)(uintptr_t)pc, 4);
        /* find first differing byte between guest and real in this page */
        char pgdiff[64] = "";
        {
            char gbuf[4096];
            uint64_t pgbase = pc & ~0xFFFULL;
            if (real_addr_mapped(e, pgbase) &&
                uc_mem_read(uc, pgbase, gbuf, sizeof(gbuf)) == UC_ERR_OK) {
                const unsigned char* rp = (const unsigned char*)(uintptr_t)pgbase;
                for (size_t i = 0; i < sizeof(gbuf); i++) {
                    if ((unsigned char)gbuf[i] != rp[i]) {
                        snprintf(pgdiff, sizeof(pgdiff), " page-diverge@+0x%zx(g=%02x r=%02x)",
                                 i, (unsigned char)gbuf[i], rp[i]);
                        break;
                    }
                }
            }
        }
        char sbuf[192];
        ut_symbolize(pc, sbuf, sizeof(sbuf));
        /* which of our mapping records covers the faulting pc's page? */
        char maprec[160] = "";
        uint64_t pg = pc & ~0xFFFULL;
        for (auto& p : e->uc_maps) {
            if (pg >= p.first && pg < p.second) {
                snprintf(maprec, sizeof(maprec), " ucmap=[%llx,%llx)",
                         (unsigned long long)p.first, (unsigned long long)p.second);
                break;
            }
        }
        /* ...and what does unicorn itself think is mapped there? */
        {
            uc_mem_region* regs = nullptr;
            uint32_t cnt = 0;
            if (uc_mem_regions(uc, &regs, &cnt) == UC_ERR_OK && regs) {
                for (uint32_t i = 0; i < cnt; i++) {
                    if (pg >= regs[i].begin && pg < regs[i].end) {
                        char t[96];
                        snprintf(t, sizeof(t), " ucreg=[%llx,%llx,perm=%u]",
                                 (unsigned long long)regs[i].begin,
                                 (unsigned long long)regs[i].end, regs[i].perms);
                        strncat(maprec, t, sizeof(maprec) - strlen(maprec) - 1);
                        break;
                    }
                }
                uc_free(regs);
            }
        }
        snprintf(e->fault_desc, sizeof(e->fault_desc),
                 "emulated SIGSEGV: %s @ 0x%llx not mapped (pc=0x%llx [%s] op=%08x real=%08x%s x16=%llx x17=%llx x30=%llx)",
                 type == UC_MEM_FETCH_UNMAPPED ? "fetch" :
                 (type == UC_MEM_WRITE_UNMAPPED ? "write" : "read"),
                 (unsigned long long)address,
                 (unsigned long long)pc, sbuf, op, op_real, pgdiff, maprec,
                 (unsigned long long)reg_read(uc, UC_ARM64_REG_X16),
                 (unsigned long long)reg_read(uc, UC_ARM64_REG_X17),
                 (unsigned long long)reg_read(uc, UC_ARM64_REG_LR));
        e->emu_stop = true;
        uc_emu_stop(uc);
        return false;
    }
    if (prot == PROT_NONE) {
        snprintf(e->fault_desc, sizeof(e->fault_desc),
                 "emulated SIGSEGV: %s @ 0x%llx hits a PROT_NONE page (pc=0x%llx)",
                 type == UC_MEM_FETCH_UNMAPPED ? "fetch" :
                 (type == UC_MEM_WRITE_UNMAPPED ? "write" : "read"),
                 (unsigned long long)address,
                 (unsigned long long)reg_read(uc, UC_ARM64_REG_PC));
        e->emu_stop = true;
        uc_emu_stop(uc);
        return false;
    }

    /* fast path: every page the faulting access touches is mirrored (an
     * access may straddle a page boundary, e.g. 16B SIMD loads) */
    e->page_attr_invalidate();
    {
        bool all = true;
        for (uint64_t a = raw; a < raw + (uint64_t)(size > 0 ? size : 1); a += e->page) {
            auto it = e->page_attr.find(a >> 12);
            if (it == e->page_attr.end() || !(it->second & PG_MAPPED)) {
                all = false;
                break;
            }
        }
        if (all) {
            /* page(s) mirrored: let qemu retry — same as the covered-range
             * early return in mirror_into_uc's clip loop */
        }
    }

    /* mirror the faulting page plus a chunk around it for locality */
    const Region* r = find_region(e, address);
    uint64_t start = address & ~(uint64_t)(e->page - 1);
    uint64_t end = start + e->page;
    /* widen: 16 pages before, 64 pages after (clamped to the region) */
    uint64_t want_start = start > 16 * e->page ? start - 16 * e->page : start;
    uint64_t want_end = end + 64 * e->page;
    if (r) {
        want_start = std::max(want_start, r->start);
        want_end = std::min(want_end, r->end);
    }
    if (e->trace_level >= 2)
        LOGI("  fault %s @0x%llx raw=%llx region=[%llx,%llx) want=[%llx,%llx)",
             type == UC_MEM_FETCH_UNMAPPED ? "fetch" :
             (type == UC_MEM_WRITE_UNMAPPED ? "write" : "read"),
             (unsigned long long)address, (unsigned long long)raw,
             (unsigned long long)(r ? r->start : 0),
             (unsigned long long)(r ? r->end : 0),
             (unsigned long long)want_start, (unsigned long long)want_end);
    if (want_end > want_start) {
        uint64_t tag = raw & ~0x0000FFFFFFFFFFFFULL;
        uint64_t len = want_end - want_start;
        want_start |= tag;                 /* map at the tagged alias */
        want_end = want_start + len;
    }
    if (mirror_into_uc(e, want_start, want_end, prot)) return true;

    snprintf(e->fault_desc, sizeof(e->fault_desc),
             "mirror failed for 0x%llx (pc=0x%llx)",
             (unsigned long long)address,
             (unsigned long long)reg_read(uc, UC_ARM64_REG_PC));
    e->emu_stop = true;
    uc_emu_stop(uc);
    return false;
}

/* ------------------------------------------------------------------ */
/* write-back: unicorn 2.1.4 has no WRITE_AFTER event, so emulated      */
/* stores are tracked as dirty pages (marked in the pre-write hook)    */
/* and flushed guest->real when emulation stops. Pointers the caller   */
/* passed in therefore hold the results after invokeCall returns.      */
/* During emulation, syscall forwarding stays coherent via sync_in().  */
/* ------------------------------------------------------------------ */
static void hook_write_mark(uc_engine* uc, uc_mem_type type,
                            uint64_t address, int size, int64_t value,
                            void* ud) {
    (void)uc; (void)type;
    Engine* e = (Engine*)ud;
    uint64_t raw = address;
    address = untag(address);

    extern uint64_t g_ut_watch_lo, g_ut_watch_hi, g_ut_watch_count;
    if (g_ut_watch_lo && address >= g_ut_watch_lo && address < g_ut_watch_hi &&
        g_ut_watch_count < 5) {
        g_ut_watch_count++;
        LOGI("  watch-write @0x%llx size=%d val=%llx pc=0x%llx",
             (unsigned long long)address, size,
             (unsigned long long)value,
             (unsigned long long)reg_read(uc, UC_ARM64_REG_PC));
    }
    /* fast path: cached page attributes — one hash lookup instead of a
     * binary search over ~2000 regions on EVERY scalar store */
    e->page_attr_invalidate();
    uint32_t attr = 0;
    auto it = e->page_attr.find(address >> 12);
    if (it != e->page_attr.end()) {
        attr = it->second;
    } else {
        int prot = 0;
        bool mapped = real_addr_mapped(e, address, &prot);
        attr = mapped ? PG_MAPPED : 0;
        if (mapped && (prot & PROT_WRITE)) attr |= PG_WRITABLE;
        if (mapped && (e->in_host_heap(address) || page_is_guest_private(e, address)))
            attr |= PG_PRIVATE;
        e->page_attr.emplace(address >> 12, attr);
    }
    if (!(attr & (PG_WRITABLE | PG_MAPPED)) || (attr & PG_PRIVATE)) return;
    if (!(attr & PG_WRITABLE)) {
        /* mapped but read-only: fall through to the exact check only when
         * the cache says MAPPED but not WRITABLE — mprotect may have run
         * since; keep the old conservative behavior */
        int prot2 = 0;
        if (!real_addr_mapped(e, address, &prot2) || !(prot2 & PROT_WRITE)) return;
    }

    if (size <= 0 || size > 8) {
        /* wide (SIMD) stores: defer to the post-run page flush. Mark every
         * alias view of the page so they all flush in lockstep. */
        uint64_t pg = raw & ~(uint64_t)(e->page - 1);
        e->dirty_pages.insert(pg);
        e->dirty_pages.insert(address & ~(uint64_t)(e->page - 1));
        for (uint64_t t : e->observed_tags) {
            uint64_t a = address | t;
            if (a != pg) e->dirty_pages.insert(a & ~(uint64_t)(e->page - 1));
        }
        return;
    }
    /* scalar stores: `value` holds the exact bytes (LE); write them through
     * immediately so ordering vs real signal handlers is preserved, and
     * mirror them into every mapped alias view of the page */
    if (e->redirected_slots.count(address)) {
        if (g_ut_watch_lo && address >= g_ut_watch_lo && address < g_ut_watch_hi)
            LOGI("  wt-guard: redirected slot");
        return;   /* keep real GOT intact */
    }
    memcpy((void*)(uintptr_t)address, &value, (size_t)size);
    if (g_ut_watch_lo && address >= g_ut_watch_lo && address < g_ut_watch_hi && g_ut_watch_count <= 6)
        LOGI("  wt-done @0x%llx size=%d now=%02x",
             (unsigned long long)address, size,
             *(unsigned char*)(uintptr_t)address);
    uint64_t rpg = raw & ~(uint64_t)(e->page - 1);
    uint64_t off = address & (e->page - 1);
    /* untagged twin */
    if ((address & ~(uint64_t)(e->page - 1)) != rpg && uc_has(e, address & ~(uint64_t)(e->page - 1)))
        uc_mem_write(uc, address & ~(uint64_t)(e->page - 1) | off, &value, (size_t)size);
    for (uint64_t t : e->observed_tags) {
        uint64_t a = (address | t) & ~(uint64_t)(e->page - 1);
        if (a == rpg) continue;   /* qemu already wrote the store there */
        if (!uc_has(e, a)) continue;
        uc_mem_write(uc, a + off, &value, (size_t)size);
    }
}

static void flush_dirty_pages(Engine* e) {
    std::vector<char> buf(e->page);
    for (uint64_t pg : e->dirty_pages) {
        uint64_t real_pg = untag(pg);
        if (e->in_host_heap(real_pg)) continue;   /* host heap: private view */
        if (page_is_guest_private(e, real_pg)) continue; /* syslibs: private */
        int prot = 0;
        if (!real_addr_mapped(e, real_pg, &prot) || !(prot & PROT_WRITE)) continue;
        if (uc_mem_read(e->uc, pg, buf.data(), buf.size()) != UC_ERR_OK)
            continue;   /* alias unmapped already */
        restore_real_ptrs_in(e, real_pg, buf.data(), buf.size());
        memcpy((void*)(uintptr_t)real_pg, buf.data(), buf.size());
    }
    e->dirty_pages.clear();
}

/* pull every mirrored page back in from real memory, so writes done by
 * real code (signal handlers running natively during a kill-class syscall)
 * become visible to the guest */
static void refresh_all_mirror(Engine* e) {
    flush_dirty_pages(e);   /* guest SIMD writes land in real first */
    std::vector<char> buf(e->page);
    for (auto& p : e->uc_maps) {
        for (uint64_t pg = p.first; pg < p.second; pg += e->page) {
            uint64_t real_pg = untag(pg);
            int prot = 0;
            if (!real_addr_mapped(e, real_pg, &prot) || !(prot & PROT_READ)) continue;
            memcpy(buf.data(), (const void*)(uintptr_t)real_pg, buf.size());
            uc_mem_write(e->uc, pg, buf.data(), buf.size());
        }
    }
    reapply_redirects(e);
}

/* ------------------------------------------------------------------ */
/* tracing hooks                                                       */
/* ------------------------------------------------------------------ */
static void hook_block(uc_engine* uc, uint64_t address, uint32_t size, void* ud) {
    Engine* e = (Engine*)ud;
    e->stats.block_count++;
    ut_callobs_on_block(uc, address, size);   /* cheap no-op unless enabled */
    if (e->time_sim) {
        /* advance the virtual clock by this block's instruction count so
         * timing detection measures real-hardware ticks-per-instruction */
        virt_advance_insns(e, size ? size / 4 : 1);
        virt_publish(e);
    }
    if (e->trace_level >= 2 && e->blocks.size() < 8192)
        e->blocks.push_back({address, size});
}

static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* ud) {
    Engine* e = (Engine*)ud;
    e->stats.instr_count++;
    if (e->trace_level >= 3 && e->blocks.size() < 8192)
        e->blocks.push_back({address, 0 /*single insn*/});
}

static void hook_insn_invalid(uc_engine* uc, void* ud) {
    Engine* e = (Engine*)ud;
    uint64_t pc = reg_read(uc, UC_ARM64_REG_PC);
    uint32_t op = 0;
    uc_mem_read(uc, pc, &op, 4);
    snprintf(e->fault_desc, sizeof(e->fault_desc),
             "invalid instruction @ pc=0x%llx opcode=0x%08x",
             (unsigned long long)pc, op);
    e->emu_stop = true;
    uc_emu_stop(uc);
}

/* ------------------------------------------------------------------ */
/* symbolization                                                       */
/* ------------------------------------------------------------------ */
/* module table built once from link_map: [base,end,name] sorted, so
 * symbolization avoids dladdr's repeated phdr walks entirely */
struct ModEnt { uint64_t base, end; char name[64]; };
static std::vector<ModEnt> g_mods;
static bool g_mods_ready = false;

static void build_module_table(void) {
    g_mods.clear();
    /* dl_iterate_phdr gives every loaded object with its load address */
    struct Ctx { std::vector<ModEnt>* out; } ctx{&g_mods};
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* out = ((Ctx*)data)->out;
        ModEnt m;
        m.base = (uint64_t)info->dlpi_addr;
        /* span = max p_vaddr+p_memsz over PT_LOAD */
        uint64_t end = m.base;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const Elf64_Phdr* ph = info->dlpi_phdr + i;
            if (ph->p_type == PT_LOAD) {
                uint64_t seg_end = m.base + ph->p_vaddr + ph->p_memsz;
                if (seg_end > end) end = seg_end;
            }
        }
        m.end = end;
        const char* n = info->dlpi_name;
        if (!n || !n[0]) n = "(exe)";
        const char* b = strrchr(n, '/');
        snprintf(m.name, sizeof(m.name), "%s", b ? b + 1 : n);
        out->push_back(m);
        return 0;
    }, &ctx);
    std::sort(g_mods.begin(), g_mods.end(),
              [](const ModEnt& a, const ModEnt& b) { return a.base < b.base; });
    g_mods_ready = true;
}

const char* ut_symbolize(uint64_t addr, char* buf, size_t bufsz) {
    /* module part from the one-time table when available; the symbol name
     * still needs dladdr, but callers on hot paths use sym_cached() so
     * this full walk happens at most once per distinct pc */
    Dl_info info = {};
    if (g_mods_ready) {
        auto it = std::upper_bound(g_mods.begin(), g_mods.end(), addr,
            [](uint64_t v, const ModEnt& m) { return v < m.base; });
        if (it != g_mods.begin()) {
            --it;
            if (addr >= it->base && addr < it->end) {
                uint64_t off = addr - it->base;
                Dl_info di = {};
                dladdr((void*)(uintptr_t)addr, &di);
                if (di.dli_sname) {
                    snprintf(buf, bufsz, "%s!%s+0x%llx", it->name, di.dli_sname,
                             (unsigned long long)(addr - (uint64_t)(uintptr_t)di.dli_saddr));
                } else {
                    snprintf(buf, bufsz, "%s+0x%llx", it->name,
                             (unsigned long long)off);
                }
                return buf;
            }
        }
    }
    if (dladdr((void*)(uintptr_t)addr, &info) && info.dli_fname) {
        const char* base = strrchr(info.dli_fname, '/');
        base = base ? base + 1 : info.dli_fname;
        uint64_t off = (uint64_t)(uintptr_t)info.dli_fbase
                       ? addr - (uint64_t)(uintptr_t)info.dli_fbase : addr;
        if (info.dli_sname) {
            snprintf(buf, bufsz, "%s!%s+0x%llx", base, info.dli_sname,
                     (unsigned long long)(addr - (uint64_t)(uintptr_t)info.dli_saddr));
        } else {
            snprintf(buf, bufsz, "%s+0x%llx", base, (unsigned long long)off);
        }
    } else {
        snprintf(buf, bufsz, "0x%llx", (unsigned long long)addr);
    }
    return buf;
}

static const char* sys_name(uint64_t nr) {
    static char buf[32];
    switch (nr) {
    case 17: return "getcwd";        case 29: return "ioctl";
    case 22 + 0: return "epoll_pwait";
    case 34: return "mkdirat";       case 35: return "unlinkat";
    case 43: return "statfs";        case 44: return "fstatfs";
    case 48: return "faccessat";     case 52: return "fchmod";
    case 53: return "fchmodat";      case 55: return "fchown";
    case 56: return "openat";
    case 57: return "close";         case 59: return "pipe2";
    case 61: return "getdents64";    case 62: return "lseek";
    case 63: return "read";          case 64: return "write";
    case 65: return "readv";         case 66: return "writev";
    case 67: return "pread64";       case 68: return "pwrite64";
    case 73: return "poll";          case 78: return "readlinkat";
    case 79: return "newfstatat";    case 80: return "fstat";
    case 93: return "exit";          case 94: return "exit_group";
    case 96: return "set_tid_address";
    case 98: return "futex";         case 101: return "nanosleep";
    case 113: return "clock_gettime";
    case 115: return "clock_nanosleep";
    case 116: return "syslog";       case 122: return "sched_setaffinity";
    case 123: return "sched_getaffinity";
    case 129: return "kill";         case 130: return "tkill";
    case 131: return "tgkill";       case 132: return "sigaltstack";
    case 134: return "rt_sigaction"; case 135: return "rt_sigprocmask";
    case 160: return "uname";        case 163: return "getrlimit";
    case 164: return "setrlimit";    case 165: return "getrusage";
    case 167: return "prctl";        case 169: return "gettimeofday";
    case 179: return "sysinfo";      case 200: return "bind";
    case 203: return "connect";      case 206: return "sendto";
    case 207: return "recvfrom";     case 214: return "sendmsg";
    case 215: return "munmap";       case 222: return "mmap";
    case 226: return "mprotect";
    case 227: return "mlock";        case 232: return "mincore";
    case 233: return "madvise";      case 260: return "wait4";
    case 261: return "prlimit64";    case 270: return "process_vm_readv";
    case 271: return "process_vm_writev";
    case 278: return "getrandom";    case 279: return "memfd_create";
    case 291: return "statx";
    }
    snprintf(buf, sizeof(buf), "sys_%llu", (unsigned long long)nr);
    return buf;
}

/* scan the real libc for scudo's pointer-tag instructions and remember
 * where they are, so the guest mirror can NOP them */
static void scan_libc_tag_insns(Engine* e) {
    void* h = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!h) return;
    void* sym = dlsym(h, "malloc");
    Dl_info info = {};
    uint64_t base = 0;
    if (sym && dladdr(sym, &info) && info.dli_fbase) base = (uint64_t)(uintptr_t)info.dli_fbase;
    dlclose(h);
    if (!base) return;
    /* find the executable regions belonging to libc.so */
    e->tag_insn_addrs.clear();
    e->libc_base = e->libc_end = 0;
    parse_maps(e);
    for (auto& r : e->regions) {
        if (!(r.prot & PROT_EXEC) || !strstr(r.path, "libc.so")) continue;
        if (!e->libc_base) e->libc_base = r.start;
        e->libc_end = r.end;
        for (uint64_t a = r.start; a + 4 <= r.end; a += 4) {
            uint32_t insn;
            memcpy(&insn, (const void*)(uintptr_t)a, 4);
            /* ORR Xd, Xn, Xm, LSL #56 : sf=1 opc=01 01010 shift=00 N=1
             * encoding 0xAA..: 1010_1010_000 Rm imm6(111000) Rn Rd */
            if ((insn & 0xFFE0FC00u) == 0xAA00E000u) {
                e->tag_insn_addrs.push_back(a);
            }
        }
    }
    LOGI("scudo tag-insns found in libc [0x%llx,0x%llx): %zu",
         (unsigned long long)e->libc_base, (unsigned long long)e->libc_end,
         e->tag_insn_addrs.size());

}

/* ------------------------------------------------------------------ */
/* guest allocator: replaces scudo inside the emulator                 */
/* ------------------------------------------------------------------ */
static uint64_t real_fn_addr(const char* name) {
    void* h = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!h) return 0;
    void* p = dlsym(h, name);
    dlclose(h);
    return (uint64_t)(uintptr_t)p;
}

static uint64_t emit_trampoline(uint64_t page, uint64_t& off, uint64_t nr) {
    /* movz x16, #(nr & 0xffff); movk x16, #(nr >> 16), lsl 16; svc #0; ret */
    uint32_t code[] = {
        0xD2800000u | (uint32_t)((nr & 0xFFFF) << 5) | 8u,           /* movz x8, lo */
        0xF2A00000u | (uint32_t)(((nr >> 16) & 0xFFFF) << 5) | 8u,   /* movk x8, hi, lsl16 */
        0xD4000001u,                                                  /* svc #0 */
        0xD65F03C0u,                                                  /* ret */
    };
    uint64_t entry = page + off;
    /* write into the REAL page first; it gets mirrored coherently */
    memcpy((void*)(uintptr_t)entry, code, sizeof(code));
    off += sizeof(code);
    return entry;
}

void Engine::setup_guest_allocator() {
    void* p = mmap(nullptr, 2 * 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;
    tramp_page = (uint64_t)(uintptr_t)p;
    memset(p, 0, 2 * 4096);
    uint64_t off = 0;
    tramp_malloc = emit_trampoline(tramp_page, off, UT_NR_MALLOC);
    tramp_calloc = emit_trampoline(tramp_page, off, UT_NR_CALLOC);
    tramp_realloc = emit_trampoline(tramp_page, off, UT_NR_REALLOC);
    tramp_free = emit_trampoline(tramp_page, off, UT_NR_FREE);
    bump_cur = brk_base;
    real_malloc = real_fn_addr("malloc");
    real_calloc = real_fn_addr("calloc");
    real_realloc = real_fn_addr("realloc");
    real_free = real_fn_addr("free");
    LOGI("guest allocator trampolines @0x%llx (malloc=0x%llx) real_malloc=0x%llx bump=0x%llx",
         (unsigned long long)tramp_page, (unsigned long long)tramp_malloc,
         (unsigned long long)real_malloc, (unsigned long long)bump_cur);
}

/* map a real allocator function address to its trampoline */
static uint64_t tramp_for(Engine* e, uint64_t real) {
    if (real == e->real_malloc) return e->tramp_malloc;
    if (real == e->real_calloc) return e->tramp_calloc;
    if (real == e->real_realloc) return e->tramp_realloc;
    if (real == e->real_free) return e->tramp_free;
    return 0;
}

/* real->guest refreshes would restore the original pointers; re-apply */
static void reapply_redirects(Engine* e) {
    for (uint64_t slot : e->redirected_slots) {
        if (!uc_has(e, slot)) continue;
        uint64_t cur = 0;
        if (uc_mem_read(e->uc, slot, &cur, 8) != UC_ERR_OK) continue;
        uint64_t t = tramp_for(e, cur);
        if (t) uc_mem_write(e->uc, slot, &t, 8);
    }
}

/* before writing a guest page back to real memory, restore original
 * allocator pointers at redirected slots so the real process stays intact */
static void restore_real_ptrs_in(Engine* e, uint64_t pg, char* buf, size_t len) {
    if (e->redirected_slots.empty()) return;
    for (uint64_t slot : e->redirected_slots) {
        if (slot < pg || slot + 8 > pg + len) continue;
        uint64_t real = 0;
        memcpy(&real, (const void*)(uintptr_t)slot, 8);   /* real GOT value */
        uint64_t t = tramp_for(e, real);
        if (t && (uint64_t)(uintptr_t)slot != 0)
            memcpy(buf + (slot - pg), &real, 8);
    }
}

/* serve a guest allocator trampoline call from the brk range */
static bool guest_alloc_syscall(uc_engine* uc, Engine* e, uint64_t nr,
                                uint64_t a0, uint64_t a1, uint64_t* out) {
    auto bump = [&](uint64_t sz) -> uint64_t {
        uint64_t p = (e->bump_cur + 15) & ~(uint64_t)15;
        if (p + sz > e->brk_end) return 0;
        e->bump_cur = p + sz;
        /* zero it in the guest view so calloc-like semantics hold */
        std::vector<char> z(std::min<uint64_t>(sz, 1 << 20), 0);
        for (uint64_t o = 0; o < sz; o += z.size())
            uc_mem_write(e->uc, p + o, z.data(),
                         (size_t)std::min<uint64_t>(z.size(), sz - o));
        return p;
    };
    switch (nr) {
    case UT_NR_MALLOC: {
        uint64_t p = bump(a0 ? a0 : 1);
        if (p) e->alloc_sizes[p] = a0;
        *out = p;
        return true;
    }
    case UT_NR_CALLOC: {
        uint64_t sz = a0 * a1;
        uint64_t p = bump(sz ? sz : 1);
        if (p) e->alloc_sizes[p] = sz;
        *out = p;
        return true;
    }
    case UT_NR_REALLOC: {
        auto it = e->alloc_sizes.find(a0);
        uint64_t old = it == e->alloc_sizes.end() ? 0 : it->second;
        uint64_t p = bump(a1 ? a1 : 1);
        if (!p) { *out = 0; return true; }
        if (old && a0) {
            uint64_t n = std::min(old, a1);
            std::vector<char> tmp(n);
            uc_mem_read(e->uc, a0, tmp.data(), (size_t)n);
            uc_mem_write(e->uc, p, tmp.data(), (size_t)n);
        }
        if (it != e->alloc_sizes.end()) e->alloc_sizes.erase(it);
        e->alloc_sizes[p] = a1;
        *out = p;
        return true;
    }
    case UT_NR_FREE:
        e->alloc_sizes.erase(a0);
        *out = 0;
        return true;
    }
    return false;
}


/* ------------------------------------------------------------------ */
/* CPU fingerprint simulation                                         */
/* ------------------------------------------------------------------ */
extern "C" int uc_arm64_ut_cpu_id_override(uc_engine* uc,
                                            uint64_t ctr, uint64_t dczid_bs,
                                            uint64_t midr, uint64_t cntfrq);

static uint64_t host_mrs_ctr(void) {
    uint64_t v = 0;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(v));
    return v;
}
static uint64_t host_mrs_dczid(void) {
    uint64_t v = 0;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(v));
    return v;
}

/* MIDR = implementer<<24 | variant<<20 | architecture<<16 | part<<4 | revision
 * rebuilt from the first processor's /proc/cpuinfo fields */
static uint64_t host_midr_from_cpuinfo(void) {
    uint64_t impl = 0x41, variant = 0, part = 0xd08, rev = 0;
    FILE* f = fopen("/proc/cpuinfo", "re");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            unsigned long v;
            if (sscanf(line, "CPU implementer : %lx", &v) == 1) { impl = v; break; }
        }
        rewind(f);
        while (fgets(line, sizeof(line), f)) {
            unsigned long v;
            if (sscanf(line, "CPU variant : %lx", &v) == 1) { variant = v; break; }
        }
        rewind(f);
        while (fgets(line, sizeof(line), f)) {
            unsigned long v;
            if (sscanf(line, "CPU part : %lx", &v) == 1) { part = v; break; }
        }
        rewind(f);
        while (fgets(line, sizeof(line), f)) {
            unsigned long v;
            if (sscanf(line, "CPU revision : %lu", &v) == 1) { rev = v; break; }
        }
        fclose(f);
    }
    return (impl & 0xff) << 24 | (variant & 0xf) << 20 | 0xfull << 16 |
           (part & 0xfff) << 4 | (rev & 0xf);
}

struct {
    bool host_mode = true;
    bool collected = false;
    uint64_t ctr, dczid, midr;
} g_cpu_prof;



static void collect_host_cpu(void) {
    if (g_cpu_prof.collected) return;
    g_cpu_prof.ctr = host_mrs_ctr();
    g_cpu_prof.dczid = host_mrs_dczid();
    g_cpu_prof.midr = host_midr_from_cpuinfo();
    g_cpu_prof.collected = true;
    LOGI("host cpu: CTR_EL0=0x%llx DCZID_EL0=0x%llx MIDR=0x%llx",
         (unsigned long long)g_cpu_prof.ctr,
         (unsigned long long)g_cpu_prof.dczid,
         (unsigned long long)g_cpu_prof.midr);
}

static int apply_cpu_profile(uc_engine* uc) {
    if (!g_cpu_prof.host_mode) return 0;
    collect_host_cpu();
    int rc = uc_arm64_ut_cpu_id_override(uc, g_cpu_prof.ctr,
                                         g_cpu_prof.dczid & 0xf,
                                         g_cpu_prof.midr, 0 /* keep qemu cntfrq */);
    if (rc != 0) return rc;   /* cpu not fully created yet */
    /* CPACR: keep NEON enabled (FPEN=11) but trap SVE at EL0 (ZEN=01),
     * matching a production non-SVE core like the host's */
    uint64_t cpacr = 0;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &cpacr);
    cpacr |= (3ull << 20);        /* FPEN = 11 */
    cpacr &= ~(3ull << 16);
    cpacr |= (1ull << 16);        /* ZEN = 01: EL0 SVE traps */
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &cpacr);
    return 0;
}

int ut_set_cpu_profile(const char* name) {
    if (!name) return -1;
    if (strcmp(name, "host") == 0) g_cpu_prof.host_mode = true;
    else if (strcmp(name, "off") == 0) g_cpu_prof.host_mode = false;
    else return -1;
    return 0;
}
uint64_t ut_get_host_ctr(void) { collect_host_cpu(); return g_cpu_prof.ctr; }
uint64_t ut_get_host_dczid(void) { collect_host_cpu(); return g_cpu_prof.dczid; }
uint64_t ut_get_host_midr(void) { collect_host_cpu(); return g_cpu_prof.midr; }

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */
static uint64_t read_tpidr(int which) {
    uint64_t v = 0;
    if (which == 0) __asm__ volatile("mrs %0, tpidr_el0" : "=r"(v));
    else if (which == 1) __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(v));
    else __asm__ volatile("mov %0, x18" : "=r"(v));   /* bionic thread ptr */
    return v;
}

static int g_trace_level_want = 1;
void ut_set_trace_level(int level) {
    g_trace_level_want = level;
    if (g_eng) g_eng->trace_level = level;
}
int  ut_get_trace_level(void) { return g_eng ? g_eng->trace_level : 0; }

int ut_init(void) {
    if (g_eng && g_eng->init_ok) return 0;
    if (!g_eng) g_eng = new Engine();
    g_eng->trace_level = g_trace_level_want;
    Engine* e = g_eng;
    if (e->init_ok) return 0;

    e->page = (size_t)sysconf(_SC_PAGESIZE);
    parse_maps(e);

    /* make sure the magic return page is really unmapped */
    while (real_addr_mapped(e, g_magic_return)) g_magic_return += 0x100000;

    /* reserve the guest heap (brk) range in the REAL process: the guest
     * allocator runs here; kernel syscalls on guest heap pointers land on
     * this mapping; the host engine never allocates in it (the mapping is
     * exclusively ours, so the host can never get pages in this range) */
    const uint64_t kBrkSize = 512ull << 20;
    void* r = mmap(nullptr, kBrkSize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (r == MAP_FAILED) {
        snprintf(e->init_err, sizeof(e->init_err),
                 "guest brk mmap failed: %s", strerror(errno));
        LOGE("%s", e->init_err);
        return -1;
    }
    e->brk_base = (uint64_t)(uintptr_t)r;
    e->brk_end = e->brk_base + kBrkSize;
    e->brk_cur = e->brk_base;

    scan_libc_tag_insns(e);
    e->setup_guest_allocator();

    build_module_table();   /* one-time module table for symbolization */

    /* anti timing-detection: anchor the virtual clock */
    virt_recompute_rcp(e);
    g_ut_virt_counter = 0;
    g_ut_virt_counter_enabled = e->time_sim ? 1 : 0;
    parse_maps(e);

    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, &e->uc);
    if (err) {
        snprintf(e->init_err, sizeof(e->init_err), "uc_open: %s", uc_strerror(err));
        LOGE("%s", e->init_err);
        return -1;
    }

    /* the default CPU lacks FEAT_LSE; real libc/pthread uses CAS/SWP
     * atomics, so run the "max" model */
    err = uc_ctl_set_cpu_model(e->uc, UC_CPU_ARM64_MAX);
    if (err) {
        LOGW("uc_ctl_set_cpu_model(max) failed: %s", uc_strerror(err));
    }

    /* simulate the real device cpu (CTR/DCZID/MIDR + SVE gating);
     * the cpu may not be fully created yet — retried on first invoke */
    e->cpu_profile_applied = (apply_cpu_profile(e->uc) == 0);

    /* real emulated stack (real mmap, lazily mirrored into unicorn) */
    void* stack = mmap(nullptr, kStackBytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (stack == MAP_FAILED) {
        snprintf(e->init_err, sizeof(e->init_err), "stack mmap failed");
        return -1;
    }
    e->stack_base = (uint64_t)(uintptr_t)stack;

    /* share the host thread pointers so TLS/errno/stack-guard work */
    reg_write(e->uc, UC_ARM64_REG_TPIDR_EL0, read_tpidr(0));
    reg_write(e->uc, UC_ARM64_REG_TPIDRRO_EL0, read_tpidr(1));
    reg_write(e->uc, UC_ARM64_REG_X18, read_tpidr(2));
    uint64_t pstate = 0 /* EL0t */;
    uc_reg_write(e->uc, UC_ARM64_REG_PSTATE, &pstate);

    uc_hook h;
    uc_hook_add(e->uc, &h, UC_HOOK_INTR, (void*)hook_intr, e, 1, 0);
    uc_hook_add(e->uc, &h, UC_HOOK_MEM_INVALID, (void*)hook_mem_invalid, e, 1, 0);
    uc_hook_add(e->uc, &h, UC_HOOK_INSN_INVALID, (void*)hook_insn_invalid, e, 1, 0);
    uc_hook_add(e->uc, &h, UC_HOOK_BLOCK, (void*)hook_block, e, 1, 0);
    uc_hook_add(e->uc, &h, UC_HOOK_MEM_WRITE, (void*)hook_write_mark, e, 1, 0);
    /* code hook registered lazily per-run (only at trace level 3) */

    parse_maps(e);
    e->init_ok = true;
    LOGI("unitrace ready: unicorn aarch64, page=%zu stack=0x%llx tpidr=0x%llx magic_lr=0x%llx",
         e->page, (unsigned long long)e->stack_base,
         (unsigned long long)read_tpidr(0), (unsigned long long)g_magic_return);
    return 0;
}

const char* ut_engine_info(void) {
    static char info[256];
    if (!g_eng || !g_eng->init_ok) return "engine not initialized";
    snprintf(info, sizeof(info),
             "unicorn=aarch64 page=%zu stack=0x%llx magic_lr=0x%llx regions=%zu",
             g_eng->page, (unsigned long long)g_eng->stack_base,
             (unsigned long long)g_magic_return, g_eng->regions.size());
    return info;
}

/* ------------------------------------------------------------------ */
/* trace rendering                                                     */
/* ------------------------------------------------------------------ */
static const char* sym_cached(Engine* e, uint64_t pc);   /* fwd */

/* cached symbolization: same pc never hits dladdr twice; module lookup is
 * a binary search over the one-time table, symbol names via dladdr only
 * on first sight of a page-sized bucket */
static const char* sym_cached(Engine* e, uint64_t pc) {
    auto it = e->sym_cache.find(pc);
    if (it != e->sym_cache.end()) return it->second.c_str();
    char buf[160];
    ut_symbolize(pc, buf, sizeof(buf));
    auto res = e->sym_cache.emplace(pc, buf);
    return res.first->second.c_str();
}

static void build_trace_text(Engine* e) {
    e->last_trace.clear();
    char line[256];
    if (!e->syscalls.empty()) {
        e->last_trace += "--- syscalls ---\n";
        size_t n = e->syscalls.size();
        size_t from = n > 64 ? n - 64 : 0;   /* keep the tail */
        for (size_t i = from; i < n; i++) {
            const SysEnt& s = e->syscalls[i];
            snprintf(line, sizeof(line), "%s(0x%llx, 0x%llx, 0x%llx, ...) = %lld (0x%llx)\n",
                     sys_name(s.nr), (unsigned long long)s.a0,
                     (unsigned long long)s.a1, (unsigned long long)s.a2,
                     (long long)s.ret, (unsigned long long)s.ret);
            e->last_trace += line;
        }
    }
    if (!e->blocks.empty()) {
        e->last_trace += "--- blocks ---\n";
        size_t n = e->blocks.size();
        size_t from = n > 256 ? n - 256 : 0;
        for (size_t i = from; i < n; i++) {
            const BlockEnt& b = e->blocks[i];
            snprintf(line, sizeof(line), "0x%012llx  %s%s\n",
                     (unsigned long long)b.pc, sym_cached(e, b.pc),
                     b.size ? "" : "  ; insn");
            e->last_trace += line;
        }
    }
    if (e->last_trace.size() > 96 * 1024)
        e->last_trace.resize(96 * 1024);
}

/* ------------------------------------------------------------------ */
/* invokeCall                                                          */
/* ------------------------------------------------------------------ */
static long* run_invoke(Engine* e, uint64_t address, uint64_t* args,
                        int args_length, uint64_t* out_regs) {
    if (args_length < 0 || args_length > 8) {
        snprintf(e->last_error, sizeof(e->last_error),
                 "args_length must be 0..8, got %d", args_length);
        return nullptr;
    }
    if (args_length > 0 && !args) {
        snprintf(e->last_error, sizeof(e->last_error),
                 "args is null but args_length=%d", args_length);
        return nullptr;
    }

    /* per-run state */
    e->blocks.clear();
    e->syscalls.clear();
    e->dirty_pages.clear();
    e->mirror_pages_run = 0;
    e->fault_desc[0] = 0;
    e->last_error[0] = 0;
    e->emu_stop = false;
    e->stats = {};

    if (e->call_obs || e->trace_level >= 3) tracer_init();
    if (e->call_obs) {
        ut_callobs_reset();
        uc_hook ch = 0;
        uc_hook_add(e->uc, &ch, UC_HOOK_CODE, (void*)ut_callobs_on_insn, e, 1, 0);
        e->tracer_hooks.push_back(ch);
    }
    if (e->trace_level >= 3) {
        tracer_init();
        if (g_tr.buf.capacity() < (1u << 20)) g_tr.buf.reserve(1u << 20);
        g_tr.buf.clear();
        g_tr.call_stack.clear();
        g_pend = PendingLine{};
        uc_hook h = 0;
        uc_hook_add(e->uc, &h, UC_HOOK_CODE, (void*)tracer_insn, e, 1, 0);
        e->tracer_hooks.push_back(h);
        uc_hook_add(e->uc, &h, UC_HOOK_MEM_READ, (void*)tracer_mem, e, 1, 0);
        e->tracer_hooks.push_back(h);
        uc_hook_add(e->uc, &h, UC_HOOK_MEM_WRITE, (void*)tracer_mem, e, 1, 0);
        e->tracer_hooks.push_back(h);
    }

    /* set up the CPU context */
    static const int argregs[8] = {
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    };
    for (int i = 0; i < 8; i++) {
        uint64_t v = (i < args_length && args) ? args[i] : 0;
        reg_write(e->uc, argregs[i], v);
    }
    static const int zeros[] = {
        UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
        UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
        UC_ARM64_REG_X16, UC_ARM64_REG_X17, /* x18 = bionic TLS, keep! */
        UC_ARM64_REG_X19,
        UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
        UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
        UC_ARM64_REG_X28, UC_ARM64_REG_FP,
    };
    for (int r : zeros) reg_write(e->uc, r, 0);
    reg_write(e->uc, UC_ARM64_REG_X18, read_tpidr(2));
    reg_write(e->uc, UC_ARM64_REG_LR, g_magic_return);
    uint64_t sp = e->stack_base + kStackBytes - 0x1000;
    sp &= ~(uint64_t)15;
    reg_write(e->uc, UC_ARM64_REG_SP, sp);
    uint64_t nzcv = 0;
    uc_reg_write(e->uc, UC_ARM64_REG_NZCV, &nzcv);

    /* pre-map the first stack pages so prologues don't fault immediately */
    mirror_into_uc(e, sp - 0x10000, sp + 0x1000, PROT_READ | PROT_WRITE);

    /* re-sync mirrored pages from the real process, EXCEPT the pages the
     * guest owns (brk) and system-lib data (guest-private libc state).
     * Read-only pages (all the code we mirrored) never change and are
     * skipped outright; writable pages are memcmp'd so unchanged content
     * costs no uc_mem_write. */
    {
        static thread_local std::vector<char> cmp_buf;
        cmp_buf.resize(e->page);
        for (auto& p : e->uc_maps) {
            for (uint64_t pg = p.first; pg < p.second; pg += e->page) {
                uint64_t real_pg = untag(pg);
                if (real_pg >= e->brk_base && real_pg < e->brk_end) continue;
                int prot = 0;
                if (!real_addr_mapped(e, real_pg, &prot) || !(prot & PROT_READ)) continue;
                if (!(prot & PROT_WRITE)) continue;            /* code/rodata */
                if (page_is_guest_private(e, real_pg)) continue;
                if (uc_mem_read(e->uc, pg, cmp_buf.data(), e->page) != UC_ERR_OK)
                    continue;
                if (memcmp(cmp_buf.data(), (const void*)(uintptr_t)real_pg, e->page) == 0)
                    continue;                                   /* identical */
                uc_mem_write(e->uc, pg, (const void*)(uintptr_t)real_pg, e->page);
            }
        }
        reapply_redirects(e);
    }

    virt_publish(e);
    if (!e->cpu_profile_applied) {
        int rc = apply_cpu_profile(e->uc);
        LOGI("cpu profile apply rc=%d", rc);
        e->cpu_profile_applied = (rc == 0);
    }

    uint64_t t0 = now_us();
    uc_err err = uc_emu_start(e->uc, address, g_magic_return, 0, 0);
    e->stats.elapsed_us = now_us() - t0;

    /* verify the scudo tag NOPs are really in the guest copy */
    if (!e->tag_insn_addrs.empty()) {
        uint32_t w = 0;
        uc_mem_read(e->uc, e->tag_insn_addrs[0], &w, 4);
        if (w != 0xD503201Fu)
            LOGW("tag NOP check: guest @0x%llx = %08x (NOT nop!)",
                 (unsigned long long)e->tag_insn_addrs[0], w);
    }

    tracer_finalize(e->uc);
    if (g_tenet_fp) fflush(g_tenet_fp);
    for (uc_hook h : e->tracer_hooks) uc_hook_del(e->uc, h);
    e->tracer_hooks.clear();
    flush_dirty_pages(e);

    if (out_regs) {
        for (int i = 0; i < 8; i++)
            out_regs[i] = reg_read(e->uc, argregs[i]);
    }

    if (e->stats.exit_reason != 1 && err != UC_ERR_OK && !e->emu_stop) {
        trace_file_dump_run(e, address);   /* partial trace on error */
        uint64_t epc = reg_read(e->uc, UC_ARM64_REG_PC);
        char esym[160];
        ut_symbolize(epc, esym, sizeof(esym));
        snprintf(e->last_error, sizeof(e->last_error),
                 "uc_emu_start: %s @ pc=0x%llx [%s] (%s)",
                 uc_strerror(err), (unsigned long long)epc, esym,
                 e->fault_desc[0] ? e->fault_desc : "no fault detail");
        build_trace_text(e);
        return nullptr;
    }
    if (e->stats.exit_reason != 1 && e->emu_stop) {
        trace_file_dump_run(e, address);   /* partial trace on fault */
        snprintf(e->last_error, sizeof(e->last_error), "%s",
                 e->fault_desc[0] ? e->fault_desc : "emulation stopped");
        build_trace_text(e);
        return nullptr;
    }

    /* recompute stats text */
    if (e->stats.instr_count == 0)
        e->stats.instr_count = e->stats.block_count * 4; /* rough */
    build_trace_text(e);
    trace_file_dump_run(e, address);
    return (long*)1; /* success sentinel */
}

long* invokeCallRegs(void* address, void* args, int args_length,
                     uint64_t* out_regs) {
    if (ut_init() != 0) {
        if (g_eng) snprintf(g_eng->last_error, sizeof(g_eng->last_error),
                            "engine init failed: %s", g_eng->init_err);
        return nullptr;
    }
    Engine* e = g_eng;
    pthread_mutex_lock(&e->lock);
    uint64_t aregs[8] = {0};
    long* ok = run_invoke(e, (uint64_t)(uintptr_t)address, (uint64_t*)args,
                          args_length, out_regs);
    long* result = nullptr;
    if (ok) {
        result = (long*)malloc(sizeof(long) * 8);
        if (out_regs)
            for (int i = 0; i < 8; i++) result[i] = (long)out_regs[i];
        else {
            static const int argregs[8] = {
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
            };
            for (int i = 0; i < 8; i++)
                result[i] = (long)reg_read(e->uc, argregs[i]);
        }
    }
    pthread_mutex_unlock(&e->lock);
    return result;
}

long* invokeCall(void* address, void* args, int args_length) {
    /* keep the requested 3-arg ABI: ret[0] = x0 */
    long* full = invokeCallRegs(address, args, args_length, nullptr);
    if (!full) return nullptr;
    long* r = (long*)malloc(sizeof(long));
    r[0] = full[0];
    free(full);
    return r;
}

void ut_free_result(long* result) { free(result); }

const char* ut_last_error(void) { return g_eng ? g_eng->last_error : "engine not initialized"; }

uint64_t ut_get_brk_base(void) { return g_eng ? g_eng->brk_base : 0; }

void ut_debug_watch(uint64_t lo, uint64_t hi) {
    g_ut_watch_lo = lo; g_ut_watch_hi = hi; g_ut_watch_count = 0;
}

size_t ut_debug_peek_guest(uint64_t addr, void* buf, size_t len) {
    if (!g_eng || !g_eng->init_ok) return 0;
    pthread_mutex_lock(&g_eng->lock);
    size_t n = 0;
    if (uc_mem_read(g_eng->uc, addr, buf, len) == UC_ERR_OK) n = len;
    pthread_mutex_unlock(&g_eng->lock);
    return n;
}
const char* ut_last_trace(void) {
    if (g_eng && g_eng->trace_level >= 3 && !g_tr.buf.empty())
        return g_tr.buf.c_str();
    if (ut_callobs_text()[0])
        return ut_callobs_text();
    return g_eng ? g_eng->last_trace.c_str() : "";
}

int ut_set_tenet_file(const char* path) {
    if (g_tenet_fp) { fclose(g_tenet_fp); g_tenet_fp = nullptr; }
    if (!path) return 0;
    g_tenet_fp = fopen(path, "wb");
    return g_tenet_fp ? 0 : -1;
}

long ut_trace_to_file(const char* path) {
    if (!path) return -1;
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = g_tr.buf.size();
    if (n) fwrite(g_tr.buf.data(), 1, n, f);
    fclose(f);
    return (long)n;
}

size_t ut_trace_size(void) { return g_tr.buf.size(); }

int ut_set_trace_file(const char* path) {
    if (!g_eng) return -1;
    if (g_eng->trace_fp) { fclose(g_eng->trace_fp); g_eng->trace_fp = nullptr; }
    g_eng->trace_path[0] = 0;
    if (!path) return 0;                       /* disable */
    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    g_eng->trace_fp = f;
    snprintf(g_eng->trace_path, sizeof(g_eng->trace_path), "%s", path);
    g_eng->trace_run_seq = 0;
    return 0;
}

/* called at the end of every run: append this run's trace with a header */
static void trace_file_dump_run(Engine* e, uint64_t fn_addr) {
    if (!e->trace_fp) return;
    e->trace_run_seq++;
    char sym[160];
    ut_symbolize(fn_addr, sym, sizeof(sym));
    fprintf(e->trace_fp,
            "==== run #%llu fn=0x%llx [%s] insns=%llu blocks=%llu syscalls=%llu ====\n",
            (unsigned long long)e->trace_run_seq,
            (unsigned long long)fn_addr, sym,
            (unsigned long long)e->stats.instr_count,
            (unsigned long long)e->stats.block_count,
            (unsigned long long)e->stats.syscall_count);
    const char* text;
    if (e->trace_level >= 3 && !g_tr.buf.empty())
        text = g_tr.buf.c_str();
    else if (e->call_obs && ut_callobs_text()[0])
        text = ut_callobs_text();
    else
        text = e->last_trace.c_str();
    size_t n = strlen(text);
    if (n) fwrite(text, 1, n, e->trace_fp);
    fputc('\n', e->trace_fp);
    fflush(e->trace_fp);
}
const struct ut_stats* ut_last_stats(void) { return g_eng ? &g_eng->stats : nullptr; }

/* ---- Tenet-format export --------------------------------------------
 * One line per instruction (parser: Tenet-IDA9.2 tenet/trace/file.py):
 *   PC=0x<pc>,<REG>=0x<val>...,MR=0x<addr>:<hex>,MW=0x<addr>:<hex>
 * Register set = regs READ by the instruction (pre-exec values, i.e. its
 * inputs) + regs WRITTEN (post-exec values from the write-back pass). */
static void tenet_emit(uc_engine* uc, uint64_t pc) {
    if (!g_tenet_fp) return;
    char line[640];
    int o = snprintf(line, sizeof(line), "PC=0x%llx", (unsigned long long)pc);
    /* read registers: values from the pending prefix pass were captured
     * pre-exec; re-reading now would give post-exec. We instead rely on
     * the disasm cache + current REG STATE for reads that were inputs —
     * for the common case inputs are unchanged by their own execution, so
     * reading them at finalize (before the NEXT instruction runs) yields
     * exactly the input values for all but the written registers, which
     * we emit from the write-back set. */
    const CachedInsn* ci = disasm_cache(uc, pc);
    if (ci) {
        /* canonical tenet register names: X0..X30 / SP, uppercase; the
         * parser matches after .upper() so case is cosmetic, but alias
         * names (fp/lr/w-views) must map to the canonical set */
        auto canon = [](const char* in, char* out, size_t cap) -> bool {
            const char* n = in;
            if ((n[0] == 'w' || n[0] == 'q') && n[1] >= '0' && n[1] <= '9') n++;
            if (!strcasecmp(n, "fp")) n = "X29";
            else if (!strcasecmp(n, "lr")) n = "X30";
            else if (!strcasecmp(n, "sp")) n = "SP";
            else if ((n[0] == 'x' || n[0] == 'X') && n[1] >= '0' && n[1] <= '9') {
                /* Xn stays */
            } else return false;
            snprintf(out, cap, "%s", n);
            for (char* q = out; *q; q++) *q = toupper((unsigned char)*q);
            return true;
        };
        char cn[16];
        for (int i = 0; i < ci->n_read && o < (int)sizeof(line) - 40; i++) {
            const char* nm = cs_reg_name((csh)ut_cs_handle(), ci->regs_read[i]);
            int ureg = -1; bool simd = false;
            for (auto& m : g_regmap)
                if (m.cs == (int)ci->regs_read[i]) { ureg = m.uc; simd = m.simd; break; }
            if (ureg < 0 || !nm || !canon(nm, cn, sizeof(cn))) continue;
            o += snprintf(line + o, sizeof(line) - o, ",%s=0x%llx", cn,
                          (unsigned long long)uc_read_reg(uc, ureg, simd));
        }
        /* written registers carry post-exec values; when a register is in
         * BOTH sets the write entry comes later and wins in the parser —
         * exactly the post-exec semantics we want */
        for (int i = 0; i < ci->n_written && o < (int)sizeof(line) - 40; i++) {
            if (!canon(ci->wr[i].name, cn, sizeof(cn))) continue;
            o += snprintf(line + o, sizeof(line) - o, ",%s=0x%llx", cn,
                          (unsigned long long)uc_read_reg(uc, ci->wr[i].uc,
                                                          ci->wr[i].simd));
        }
    }
    /* memory payloads from guest memory (state == post-instruction) */
    for (int i = 0; i < g_pend.mem_r_n && o < (int)sizeof(line) - 150; i++) {
        unsigned char d[16] = {0};
        int sz = g_pend.mem_rsz[i] > 16 ? 16 : g_pend.mem_rsz[i];
        if (uc_mem_read(uc, g_pend.mem_r[i], d, (size_t)sz) != UC_ERR_OK) continue;
        o += snprintf(line + o, sizeof(line) - o, ",MR=0x%llx:",
                      (unsigned long long)g_pend.mem_r[i]);
        for (int k = 0; k < sz && o < (int)sizeof(line) - 4; k++)
            o += snprintf(line + o, sizeof(line) - o, "%02x", d[k]);
    }
    for (int i = 0; i < g_pend.mem_w_n && o < (int)sizeof(line) - 150; i++) {
        unsigned char d[16] = {0};
        int sz = g_pend.mem_wsz[i] > 16 ? 16 : g_pend.mem_wsz[i];
        if (uc_mem_read(uc, g_pend.mem_w[i], d, (size_t)sz) != UC_ERR_OK) continue;
        o += snprintf(line + o, sizeof(line) - o, ",MW=0x%llx:",
                      (unsigned long long)g_pend.mem_w[i]);
        for (int k = 0; k < sz && o < (int)sizeof(line) - 4; k++)
            o += snprintf(line + o, sizeof(line) - o, "%02x", d[k]);
    }
    fputs(line, g_tenet_fp);
    fputc('\n', g_tenet_fp);
}

/* ---- internal exports for observation modules (see ut_internal.h) ---- */
extern "C" {

uintptr_t ut_cs_handle(void) {
    tracer_init();
    return (uintptr_t)g_tr.cs;
}

const struct CachedInsn* ut_disasm_insn(uc_engine* uc, uint64_t pc) {
    return disasm_cache(uc, pc);
}

uint64_t ut_read_cs_reg(uc_engine* uc, unsigned cs_reg) {
    tracer_init();
    for (auto& m : g_regmap)
        if ((unsigned)m.cs == cs_reg) return uc_read_reg(uc, m.uc, m.simd);
    return 0;
}

uint64_t ut_follow_plt(uc_engine* uc, uint64_t target) {
    return follow_plt(uc, target);
}

const char* ut_sym_cached(uint64_t pc) {
    if (g_eng) return sym_cached(g_eng, pc);
    static char b[160];
    return ut_symbolize(pc, b, sizeof(b));
}

bool ut_probe_cstring(uc_engine* uc, uint64_t addr, char* out, size_t cap) {
    return tracer_guest_str(uc, addr, out, cap);
}

void ut_engine_set_call_obs(int enable) {
    if (g_eng) g_eng->call_obs = enable != 0;
}

} /* extern "C" */
