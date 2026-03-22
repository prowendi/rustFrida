/*
 * hook_engine_mem.c - Memory pool management, XOM-safe read, wxshadow, cache flush
 *
 * Contains: pool permission management, entry allocation/free, wxshadow patching,
 * write_jump_back, hook_write_jump, hook_alloc, hook_relocate_instructions,
 * hook_flush_cache.
 */

#include "hook_engine_internal.h"

/* --- Page permission helpers --- */

/*
 * Check if the page containing addr has read permission.
 * Parses /proc/self/maps to find the VMA and check perms[0] == 'r'.
 * Returns 1 if readable, 0 otherwise.
 */
int page_has_read_perm(uintptr_t addr) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int readable = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                readable = (perms[0] == 'r');
                break;
            }
        }
    }
    fclose(f);
    return readable;
}

/*
 * Safely read bytes from a target address.
 *
 * Strategy:
 *   1. Check VMA permission — if readable, direct memcpy.
 *   2. Otherwise read via /proc/self/mem (no permission change).
 *
 * Returns 0 on success, -1 on failure.
 */
int read_target_safe(void* target, void* buf, size_t len) {
    /* If page is already readable, just memcpy */
    if (page_has_read_perm((uintptr_t)target)) {
        memcpy(buf, target, len);
        return 0;
    }

    /* Page not readable (XOM / --x) — mprotect to add read, then memcpy */
    uintptr_t page_start = (uintptr_t)target & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) == 0) {
        memcpy(buf, target, len);
        /* mprotect already set r-x, no need to restore */
        return 0;
    }

    hook_log("read_target_safe: mprotect failed errno=%d", errno);
    return -1;
}

/* --- Pool permission management --- */

/*
 * Restore a target code page to R-X after patching.
 * Try 0x2000 (two pages) first in case the hook spans a page boundary.
 * Fall back to two separate 0x1000 calls when the range crosses a VMA
 * boundary (mprotect returns EINVAL for the 2-page span but succeeds per page).
 */
void restore_page_rx(uintptr_t page_start) {
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) != 0) {
        mprotect((void*)page_start, 0x1000, PROT_READ | PROT_EXEC);
        mprotect((void*)(page_start + 0x1000), 0x1000, PROT_READ | PROT_EXEC);
    }
}

/* --- Entry free list management --- */

HookEntry* alloc_entry(void) {
    HookEntry* entry = NULL;

    if (g_engine.free_list) {
        /* Reuse from free list, preserving pool memory allocations */
        entry = g_engine.free_list;
        g_engine.free_list = entry->next;

        void* saved_trampoline = entry->trampoline;
        size_t saved_trampoline_alloc = entry->trampoline_alloc;
        void* saved_thunk = entry->thunk;
        size_t saved_thunk_alloc = entry->thunk_alloc;

        memset(entry, 0, sizeof(HookEntry));

        entry->trampoline = saved_trampoline;
        entry->trampoline_alloc = saved_trampoline_alloc;
        entry->thunk = saved_thunk;
        entry->thunk_alloc = saved_thunk_alloc;
    } else {
        entry = (HookEntry*)hook_alloc(sizeof(HookEntry));
        if (entry) memset(entry, 0, sizeof(HookEntry));
    }

    return entry;
}

void free_entry(HookEntry* entry) {
    entry->next = g_engine.free_list;
    g_engine.free_list = entry;
}

/* --- Cache flush --- */

void hook_flush_cache(void* start, size_t size) {
    __builtin___clear_cache((char*)start, (char*)start + size);
}

/* --- wxshadow (two-step shadow page patching) --- */

/*
 * Find the VMA containing addr by parsing /proc/self/maps.
 * Returns 0 on success, -1 if not found.
 */
static int find_containing_vma(uintptr_t addr, uintptr_t* vma_start, size_t* vma_size) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return -1;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                *vma_start = start;
                *vma_size = end - start;
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/*
 * Split PMD block / contiguous PTE group by mprotect on the ENTIRE
 * containing VMA + COW write.  Operating on the full VMA boundary
 * avoids VMA fragmentation in /proc/self/maps.
 *
 * The transient RWX window is unavoidable but:
 *   - wxshadow itself causes VMA splits (more detectable than RWX)
 *   - The window is microseconds (single volatile write)
 *   - Without this, wxshadow fails on contiguous PTE pages
 *
 * Returns 0 on success, -1 on failure.
 */
static int pmd_split_cow(void* addr) {
    uintptr_t vma_start = 0;
    size_t vma_size = 0;

    if (find_containing_vma((uintptr_t)addr, &vma_start, &vma_size) != 0) {
        hook_log("pmd_split_cow: VMA not found for addr=%p", addr);
        return -1;
    }

    /* mprotect the entire VMA to rwx — no VMA split */
    if (mprotect((void*)vma_start, vma_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        hook_log("pmd_split_cow: mprotect(rwx) failed errno=%d", errno);
        return -1;
    }

    /* Write original byte back to trigger COW + split contiguous PTE group.
     * The write fault handler splits PMD block entries AND clears the
     * contiguous bit on ARM64 PTE groups before creating the COW copy. */
    *(volatile uint8_t*)addr = *(volatile uint8_t*)addr;

    /* Restore entire VMA to r-x — no VMA split */
    mprotect((void*)vma_start, vma_size, PROT_READ | PROT_EXEC);

    hook_log("pmd_split_cow: COW triggered for addr=%p (VMA=%p-%p)",
             addr, (void*)vma_start, (void*)(vma_start + vma_size));
    return 0;
}

/*
 * Stealth-patch target address using wxshadow shadow pages:
 *   PATCH — one-step: create shadow + write buf + activate (--x)
 *
 * prctl(PR_WXSHADOW_PATCH, pid, addr, buf, len)
 * Tries pid=0 first, then getpid() as fallback.
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
int wxshadow_patch(void* addr, const void* buf, size_t len) {
    int ret;

    ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, len);
    if (ret != 0) {
        ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, len);
    }

    if (ret != 0) {
        /* PATCH failed — likely 2MB section (PMD) mapping.
         * wxshadow only supports 4KB PTE-mapped pages.
         *
         * Split the PMD by triggering COW on the target page.  We must
         * mprotect the ENTIRE containing VMA (not just the target page)
         * to avoid creating a VMA split visible in /proc/self/maps.
         * V-OS detection scans /proc/self/maps for unexpected VMA splits
         * in libart.so — mprotecting a sub-range would fragment the VMA. */
        hook_log("wxshadow PATCH failed (errno=%d), trying PMD split + COW for addr=%p", errno, addr);

        if (pmd_split_cow(addr) == 0) {
            ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, len);
            if (ret != 0) {
                ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, len);
            }
        }

        if (ret != 0) {
            hook_log("wxshadow PATCH failed after COW: addr=%p errno=%d", addr, errno);
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        hook_log("wxshadow PATCH succeeded after PMD split: addr=%p", addr);
    }

    hook_log("wxshadow stealth patch OK: addr=%p len=%zu", addr, len);
    return 0;
}

/*
 * Release a wxshadow patch by its exact patch start address.
 * The supplied address must match the addr argument previously passed to PATCH.
 */
int wxshadow_release(void* addr) {
    int ret = prctl(PR_WXSHADOW_RELEASE, 0, (uintptr_t)addr, 0, 0);
    if (ret != 0) {
        ret = prctl(PR_WXSHADOW_RELEASE, getpid(), (uintptr_t)addr, 0, 0);
    }
    if (ret != 0) {
        hook_log("wxshadow_release: failed for addr=%p (errno=%d)", addr, errno);
        return HOOK_ERROR_WXSHADOW_FAILED;
    }
    return 0;
}

/* --- Jump writing and allocation --- */

/* BRK 填充 + 清理 writer，返回写入字节数 */
static int finalize_jump_writer(Arm64Writer* w) {
    while (arm64_writer_offset(w) < MIN_HOOK_SIZE && arm64_writer_can_write(w, 4)) {
        arm64_writer_put_brk_imm(w, 0xFFFF);
    }
    int bytes_written = (int)arm64_writer_offset(w);
    arm64_writer_clear(w);
    return bytes_written;
}

/*
 * Write a trampoline jump-back using a dynamically chosen scratch register.
 *
 * Analyzes which GPRs are written by the relocated instructions (via
 * written_regs bitmask) and picks a scratch register that won't be
 * clobbered:
 *   - Prefer X17 (IP1, intra-procedure-call scratch)
 *   - Fall back to X16 (IP0) if X17 is written
 *   - If both are written, still use X17 (extremely rare edge case)
 */
int write_jump_back(void* dst, void* target, uint32_t written_regs) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    Arm64Reg scratch;
    if (!(written_regs & (1u << 17))) {
        scratch = ARM64_REG_X17;    /* Prefer X17 */
    } else if (!(written_regs & (1u << 16))) {
        scratch = ARM64_REG_X16;    /* Fall back to X16 */
    } else {
        scratch = ARM64_REG_X17;    /* Both written — use X17, log warning */
        hook_log("[hook] WARNING: both X16 and X17 written by relocated code, "
                 "X17 may be clobbered");
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, (uint64_t)dst, MIN_HOOK_SIZE);
    arm64_writer_put_mov_reg_imm(&w, scratch, (uint64_t)target);
    arm64_writer_put_br_reg(&w, scratch);

    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    return finalize_jump_writer(&w);
}

/* Write a jump to target at the given execution PC.
 * 优先 ADRP+ADD+BR (12B, wxshadow 安全, 需 ±4GB),
 * fallback 到 MOVZ+MOVK+BR (16B, 无限制)。
 *
 * exec_pc: the address where this code will actually execute.
 *   - For direct patching (stealth=0): exec_pc == dst
 *   - For wxshadow (stealth=1): exec_pc == hook target addr (not the tmp buffer)
 *   This ensures ADRP offsets are correct for the actual execution context. */
int hook_write_jump_at(void* dst, uint64_t exec_pc, void* target) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, exec_pc, MIN_HOOK_SIZE);

    /* 尝试 ADRP+ADD+BR (12 字节, ±4GB) */
    int64_t pc_rel = (int64_t)(uint64_t)target - (int64_t)exec_pc;
    int64_t adrp_range = (int64_t)1 << 32; /* ±4GB */
    if (pc_rel > -adrp_range && pc_rel < adrp_range) {
        arm64_writer_put_adrp_add_br(&w, ARM64_REG_X16, (uint64_t)target);
    } else {
        /* Fallback: MOVZ+MOVK+BR (16+ 字节) */
        arm64_writer_put_branch_address(&w, (uint64_t)target);
    }

    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    /* 不 pad BRK — 返回实际字节数 (ADRP=12, MOVZ=16)。
     * 调用方（patch_target/OAT）按返回值决定 overwrite 大小。 */
    int bytes_written = (int)arm64_writer_offset(&w);
    arm64_writer_clear(&w);
    return bytes_written;
}

/* Backward-compatible wrapper: exec_pc == dst (for direct patching). */
int hook_write_jump(void* dst, void* target) {
    return hook_write_jump_at(dst, (uint64_t)dst, target);
}

/* Allocate from executable memory pool */
/* 从指定 pool 分配 */
static void* alloc_from_pool(ExecPool* pool, size_t size) {
    if (pool->used + size > pool->size) return NULL;
    void* ptr = (uint8_t*)pool->base + pool->used;
    pool->used += size;
    return ptr;
}

/* 参数化版本: 搜索 target ±max_range 范围内的 maps 空隙，mmap RWX 内存。
 * target=NULL 时退化为普通 mmap(NULL)。
 * 返回 mmap 得到的指针，MAP_FAILED 表示失败。 */
void* hook_mmap_near_range(void* target, size_t alloc_size, int64_t max_range) {
    if (!target) {
        return mmap(NULL, alloc_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    uintptr_t target_addr = (uintptr_t)target;

    /* 搜索区间 [search_lo, search_hi) */
    uintptr_t search_lo = 0;
    if (target_addr > (uintptr_t)max_range)
        search_lo = (target_addr - (uintptr_t)max_range + page_size - 1) & ~(page_size - 1);
    else
        search_lo = (uintptr_t)page_size;
    uintptr_t search_hi = target_addr + (uintptr_t)max_range;
    if (search_hi < target_addr) search_hi = UINTPTR_MAX;

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) {
        hook_log("hook_mmap_near_range: failed to open /proc/self/maps");
        return MAP_FAILED;
    }

    #define MAX_CANDIDATES 32
    struct { uintptr_t addr; int64_t dist; } candidates[MAX_CANDIDATES];
    int num_candidates = 0;

    char line[512];
    uintptr_t prev_end = 0;

    while (fgets(line, sizeof(line), f)) {
        uintptr_t vma_start = 0, vma_end = 0;
        if (sscanf(line, "%lx-%lx", &vma_start, &vma_end) < 2) continue;

        if (prev_end > 0 && vma_start > prev_end) {
            uintptr_t gap_start = prev_end;
            uintptr_t gap_end = vma_start;

            if (gap_start < search_hi && gap_end > search_lo) {
                if (gap_start < search_lo) gap_start = search_lo;
                if (gap_end > search_hi) gap_end = search_hi;
                gap_start = (gap_start + page_size - 1) & ~(page_size - 1);

                if (gap_end > gap_start && (gap_end - gap_start) >= alloc_size) {
                    uintptr_t gap_last = (gap_end - alloc_size) & ~(page_size - 1);
                    uintptr_t center;
                    uintptr_t trials[8];
                    int num_trials = 0;

                    if (target_addr >= gap_start && target_addr < gap_end) {
                        center = target_addr & ~(page_size - 1);
                        if (center < gap_start) center = gap_start;
                        if (center > gap_last) center = gap_last;
                    } else if (target_addr < gap_start) {
                        center = gap_start;
                    } else {
                        center = gap_last;
                    }

                    /* 同一 gap 内多点尝试：
                     * - 起点 / 终点
                     * - target 对齐点
                     * - target 左右一个 alloc_size
                     * - target 左右 16KB
                     * 这样能避免“gap 足够大，但单个候选点刚好被占用”的情况。 */
                    trials[num_trials++] = center;
                    trials[num_trials++] = gap_start;
                    trials[num_trials++] = gap_last;

                    if (center >= gap_start + alloc_size)
                        trials[num_trials++] = center - alloc_size;
                    if (center + alloc_size <= gap_last)
                        trials[num_trials++] = center + alloc_size;
                    if (center >= gap_start + (uintptr_t)(page_size * 4))
                        trials[num_trials++] = center - (uintptr_t)(page_size * 4);
                    if (center + (uintptr_t)(page_size * 4) <= gap_last)
                        trials[num_trials++] = center + (uintptr_t)(page_size * 4);

                    for (int t = 0; t < num_trials && num_candidates < MAX_CANDIDATES; t++) {
                        uintptr_t candidate = trials[t] & ~(page_size - 1);
                        if (candidate < gap_start || candidate > gap_last)
                            continue;

                        int duplicate = 0;
                        for (int k = 0; k < num_candidates; k++) {
                            if (candidates[k].addr == candidate) {
                                duplicate = 1;
                                break;
                            }
                        }
                        if (duplicate)
                            continue;

                        int64_t d = (int64_t)(candidate - target_addr);
                        if (d < 0) d = -d;
                        candidates[num_candidates].addr = candidate;
                        candidates[num_candidates].dist = d;
                        num_candidates++;
                    }
                }
            }
        }
        prev_end = vma_end;
    }
    fclose(f);

    /* 按距离排序 */
    for (int i = 1; i < num_candidates; i++) {
        __typeof__(candidates[0]) tmp = candidates[i];
        int j = i - 1;
        while (j >= 0 && candidates[j].dist > tmp.dist) {
            candidates[j + 1] = candidates[j];
            j--;
        }
        candidates[j + 1] = tmp;
    }

    int max_tries = num_candidates < MAX_CANDIDATES ? num_candidates : MAX_CANDIDATES;

    #ifndef MAP_FIXED_NOREPLACE
    #define MAP_FIXED_NOREPLACE 0x100000
    #endif

    for (int i = 0; i < max_tries; i++) {
        void* cand = (void*)candidates[i].addr;

        void* ptr = mmap(cand, alloc_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

        /* MAP_FIXED_NOREPLACE 要求候选地址完全可用；若该点被占用（EEXIST），
         * 仍可退回普通 hint mmap，让内核在同一 gap 内挑一个附近可用地址。
         * 之后再用距离校验保证结果仍在允许范围内。 */
        if (ptr == MAP_FAILED && (errno == ENOSYS || errno == EINVAL || errno == EEXIST)) {
            ptr = mmap(cand, alloc_size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (ptr != MAP_FAILED) {
                int64_t d = (int64_t)((uint8_t*)ptr - (uint8_t*)target);
                if (d < -max_range || d >= max_range) {
                    munmap(ptr, alloc_size);
                    ptr = MAP_FAILED;
                }
            }
        }

        if (ptr != MAP_FAILED) {
            hook_log("hook_mmap_near_range: OK at %p for target %p (range=±%lld)",
                     ptr, target, (long long)max_range);
            return ptr;
        }
    }

    hook_log("hook_mmap_near_range: all %d candidates failed for target %p (range=±%lld)",
             max_tries, target, (long long)max_range);
    return MAP_FAILED;
    #undef MAX_CANDIDATES
}

/* 公共函数: 默认 ±4GB (ADRP range) 的 wrapper，保持 ABI 兼容 */
void* hook_mmap_near(void* target, size_t alloc_size) {
    return hook_mmap_near_range(target, alloc_size, (int64_t)1 << 32);
}

/* 创建新 pool，限定 ±max_range 范围 */
static ExecPool* create_pool_near_range(void* target, int64_t max_range) {
    if (g_engine.pool_count >= MAX_EXEC_POOLS) {
        hook_log("create_pool_near_range: pool count %d reached MAX_EXEC_POOLS", g_engine.pool_count);
        return NULL;
    }

    void* ptr = hook_mmap_near_range(target, EXEC_POOL_SIZE, max_range);
    if (ptr == MAP_FAILED) return NULL;

    ExecPool* pool = &g_engine.pools[g_engine.pool_count++];
    pool->base = ptr;
    pool->size = EXEC_POOL_SIZE;
    pool->used = 0;
    return pool;
}

/* 创建新 pool（默认 ±4GB）— 保持现有调用方兼容 */
static ExecPool* create_pool_near(void* target) {
    return create_pool_near_range(target, (int64_t)1 << 32);
}


/* 判断 pool 是否在 target 的 ADRP 范围内 (±4GB) */
static int pool_in_adrp_range(ExecPool* pool, void* target) {
    int64_t dist = (int64_t)((uint8_t*)pool->base - (uint8_t*)target);
    int64_t range = (int64_t)1 << 32;
    return dist > -range && dist < range;
}

/* 判断 pool 是否在 target 的指定范围内 */
static int pool_in_range(ExecPool* pool, void* target, int64_t range) {
    int64_t dist = (int64_t)((uint8_t*)pool->base - (uint8_t*)target);
    return dist > -range && dist < range;
}


void* hook_alloc(size_t size) {
    if (!g_engine.initialized) return NULL;
    size = (size + 7) & ~7;

    /* 先试初始 pool */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
        g_engine.exec_mem_used += size;
        return ptr;
    }

    /* 试其他 pool */
    for (int i = 0; i < g_engine.pool_count; i++) {
        void* ptr = alloc_from_pool(&g_engine.pools[i], size);
        if (ptr) return ptr;
    }

    /* 创建新 pool（无 hint） */
    ExecPool* pool = create_pool_near(NULL);
    return pool ? alloc_from_pool(pool, size) : NULL;
}

void* hook_alloc_near(size_t size, void* target) {
    if (!g_engine.initialized) return NULL;
    size = (size + 7) & ~7;

    int64_t adrp_range = (int64_t)1 << 32;

    /* Phase 1: 遍历所有 pool（含初始 pool），找 ADRP 可达 + 有空间的 */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        int64_t dist = (int64_t)((uint8_t*)g_engine.exec_mem - (uint8_t*)target);
        if (dist > -adrp_range && dist < adrp_range) {
            void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
            g_engine.exec_mem_used += size;
            return ptr;
        }
    }
    for (int i = 0; i < g_engine.pool_count; i++) {
        if (pool_in_adrp_range(&g_engine.pools[i], target)) {
            void* ptr = alloc_from_pool(&g_engine.pools[i], size);
            if (ptr) return ptr;
        }
    }

    /* Phase 2: 优先用通用分配兜底（节省 pool slot 给 hook_alloc_near_range）。
     * hook_alloc_near 不要求严格距离，MOVZ+MOVK 路径始终可用。
     * 只在通用空间耗尽时才创建 nearby pool。 */
    void* fallback = hook_alloc(size);
    if (fallback) {
        /* 即使不在 ADRP 范围也返回 — hook_write_jump 会用 MOVZ+MOVK 兜底 */
        return fallback;
    }

    /* Phase 3: 通用空间耗尽 → 创建 nearby pool */
    ExecPool* near_pool = create_pool_near(target);
    return near_pool ? alloc_from_pool(near_pool, size) : NULL;
}

/* 在 target ±max_range 范围内分配可执行内存。
 * 与 hook_alloc_near 不同: 不会 fallback 到 generic pool。
 * 用途: stealth2 B 指令需要 ±128MB 范围。 */
void* hook_alloc_near_range(size_t size, void* target, int64_t max_range) {
    if (!g_engine.initialized || !target) return NULL;
    size = (size + 7) & ~7;

    /* Phase 1: 初始 pool */
    if (g_engine.exec_mem_used + size <= g_engine.exec_mem_size) {
        int64_t dist = (int64_t)((uint8_t*)g_engine.exec_mem - (uint8_t*)target);
        if (dist > -max_range && dist < max_range) {
            void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
            g_engine.exec_mem_used += size;
            return ptr;
        }
    }

    /* Phase 1b: 额外 pool */
    for (int i = 0; i < g_engine.pool_count; i++) {
        ExecPool* pool = &g_engine.pools[i];
        if (pool_in_range(pool, target, max_range) && pool->used + size <= pool->size) {
            return alloc_from_pool(pool, size);
        }
    }

    /* Phase 2: 创建 pool (maps 空隙扫描，限定 ±max_range) */
    ExecPool* pool = create_pool_near_range(target, max_range);
    if (pool) {
        void* ptr = alloc_from_pool(pool, size);
        if (ptr) return ptr;
    }

    /* 不 fallback — 调用方需要保证距离 */
    hook_log("hook_alloc_near_range: FAILED for target %p within ±%lld",
             target, (long long)max_range);
    return NULL;
}


/* --- Instruction relocation --- */

/* Relocate instructions from a pre-read buffer (src_buf) to dst, using
 * src_pc as the original PC for PC-relative fixups.
 *
 * Separating src_buf from src_pc lets the caller read the original bytes
 * safely (e.g., via /proc/self/mem to bypass XOM) and then pass that buffer
 * here, while still computing correct relocations against the real address.
 *
 * Within-region branch fix: before the write loop we pre-create one writer
 * label per source instruction and record them in the relocator's region_labels
 * table.  Just before writing each instruction we place its label at the current
 * writer PC.  This allows arm64_relocator_write_one() to emit label-based
 * branches (rather than absolute branches to the now-overwritten original code)
 * for any PC-relative branch whose target lies inside [src_pc, src_pc+min_bytes). */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc, void* dst, size_t min_bytes, uint32_t* out_written_regs) {
    Arm64Writer w;
    Arm64Relocator r;

    arm64_writer_init(&w, dst, (uint64_t)dst, 256);
    arm64_relocator_init(&r, src_buf, src_pc, &w);

    /* Pre-create one label per source instruction in the hook region. */
    int n = (int)(min_bytes / INSN_SIZE);
    if (n > ARM64_RELOC_MAX_REGION) n = ARM64_RELOC_MAX_REGION;
    r.region_end = src_pc + min_bytes;
    r.region_label_count = n;
    for (int i = 0; i < n; i++) {
        r.region_labels[i].src_pc = src_pc + (uint64_t)(i * INSN_SIZE);
        r.region_labels[i].label_id = arm64_writer_new_label_id(&w);
    }

    size_t src_offset = 0;
    int insn_idx = 0;
    while (src_offset < min_bytes) {
        /* Place this instruction's label at the current write position BEFORE
         * emitting the instruction so that backward references work immediately
         * and forward references are resolved during flush. */
        if (insn_idx < n)
            arm64_writer_put_label(&w, r.region_labels[insn_idx].label_id);

        if (arm64_relocator_read_one(&r) == 0) break;
        arm64_relocator_write_one(&r);
        src_offset += INSN_SIZE;
        insn_idx++;
    }

    /* Place labels for any instructions that were not reached (e.g. early EOI)
     * so that forward label references created before the loop exits are always
     * resolved to a valid (if imprecise) position. */
    for (int i = insn_idx; i < n; i++)
        arm64_writer_put_label(&w, r.region_labels[i].label_id);

    /* Flush pending label references (CBZ forward refs etc.) */
    arm64_writer_flush(&w);

    size_t written = arm64_writer_offset(&w);

    if (out_written_regs)
        *out_written_regs = r.written_regs;

    arm64_writer_clear(&w);
    arm64_relocator_clear(&r);

    return written;
}

/* --- Hook installation helpers --- */

HookEntry* setup_hook_entry(void* target) {
    /* Caller must hold g_engine.lock */

    /* Check if already hooked */
    if (find_hook(target)) {
        return NULL;
    }

    /* Allocate hook entry (reuse from free list if possible) */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        return NULL;
    }

    entry->target = target;

    /* trampoline 不需要 near: jump-back 用 MOVZ+MOVK 绝对跳转，
     * thunk 也通过 MOVZ+MOVK 加载 trampoline 地址。节省 nearby pool 空间。 */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        return NULL;
    }

    /* Save original bytes — use XOM-safe read */
    if (read_target_safe(target, entry->original_bytes, MIN_HOOK_SIZE) != 0) {
        hook_log("setup_hook_entry: target %p is not readable, aborting", target);
        free_entry(entry);
        return NULL;
    }
    entry->original_size = MIN_HOOK_SIZE;

    return entry;
}

int build_trampoline(HookEntry* entry) {
    /* Relocate original instructions to trampoline.
     * 用 original_size（= 实际 patch 大小，ADRP=12 或 MOVZ=16），不用 MIN_HOOK_SIZE。 */
    uint32_t written_regs = 0;
    size_t overwrite = entry->original_size;
    size_t relocated_size = hook_relocate_instructions(
        entry->original_bytes, (uint64_t)entry->target,
        entry->trampoline, overwrite, &written_regs);

    /* Write jump back to original code after the relocated instructions */
    void* jump_back_target = (uint8_t*)entry->target + overwrite;
    int jump_result = write_jump_back(
        (uint8_t*)entry->trampoline + relocated_size,
        jump_back_target, written_regs);

    return jump_result;
}

int patch_target(void* target, void* jump_dest, int stealth, HookEntry* entry) {
    int jump_result;

    if (stealth == 2) {
        /* Recomp 模式: 写 4 字节 B 指令到 recomp 页。
         * recomp 内核模块只改原始页 PTE，不碰 recomp 页，mprotect 安全。 */
        int64_t b_offset = (int64_t)(uintptr_t)jump_dest - (int64_t)(uintptr_t)target;
        if (b_offset < -(1 << 27) || b_offset >= (1 << 27)) {
            hook_log("\033[31m[STEALTH 失效] recomp B 指令距离超限 %p (offset=%lld)，hook 安装失败！\033[0m",
                     target, (long long)b_offset);
            return HOOK_ERROR_BUFFER_TOO_SMALL;
        }
        uint32_t b_imm26 = ((uint32_t)(b_offset >> 2)) & 0x3FFFFFF;
        uint32_t b_insn = 0x14000000 | b_imm26;

        uintptr_t page_start = (uintptr_t)target & ~0xFFF;
        if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            return HOOK_ERROR_MPROTECT_FAILED;
        }
        *(volatile uint32_t*)target = b_insn;
        hook_flush_cache(target, 4);
        entry->stealth = 2;
        entry->original_size = 4;
        restore_page_rx(page_start);

        return 0;
    }

    if (stealth == 1) {
        /* wxshadow 模式: 一步写入 shadow 页.
         * 1. aligned(32) 防止 buf 跨页 (copy_from_user_via_pte 不支持跨页)
         * 2. hook_write_jump_at 用 target 的 PC 算 ADRP，而非 buf 的栈地址，
         *    使 target↔thunk 在 ±4GB 时走 ADRP+ADD+BR (12B) 而非 MOVZ (16B) */
        uint8_t jump_buf[MIN_HOOK_SIZE] __attribute__((aligned(32)));
        jump_result = hook_write_jump_at(jump_buf, (uint64_t)target, jump_dest);
        if (jump_result < 0) {
            return jump_result;
        }
        if (wxshadow_patch(target, jump_buf, jump_result) == 0) {
            entry->stealth = 1;
            entry->original_size = jump_result;
            return 0;
        }
        /* stealth1 严格模式: wxshadow 失败拒绝降级到 mprotect。
         * 降级会直接修改原始内存字节 + RWX 权限变更，
         * hunter CRC 校验 / /proc/self/maps 扫描均可检测。 */
        hook_log("\033[31m[STEALTH] wxshadow 失败 %p，拒绝降级 mprotect（hunter 防检测）\033[0m", target);
        return HOOK_ERROR_WXSHADOW_FAILED;
    }

    /* Normal mode (stealth=0): mprotect + direct write */
    uintptr_t page_start = (uintptr_t)target & ~0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return HOOK_ERROR_MPROTECT_FAILED;
    }
    jump_result = hook_write_jump(target, jump_dest);
    if (jump_result < 0) {
        restore_page_rx(page_start);
        return jump_result;
    }
    entry->stealth = 0;
    entry->original_size = jump_result;
    restore_page_rx(page_start);

    return 0;
}

void finalize_hook(HookEntry* entry, void* thunk, size_t thunk_size) {
    /* Flush caches */
    if (!entry->stealth) {
        hook_flush_cache(entry->target, MIN_HOOK_SIZE);
    }
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);
    if (thunk && thunk_size > 0) {
        hook_flush_cache(thunk, thunk_size);
    }

    /* Add to hook list */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;
}
