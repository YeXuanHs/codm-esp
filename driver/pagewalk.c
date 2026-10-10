//=============================================================================
//  driver/pagewalk.c
//  CR3-based page-table walker used to read CODM.exe memory WITHOUT ever
//  opening a handle to it.
//
//  Why this and not ReadProcessMemory/NtReadVirtualMemory:
//    ACE-BASE.sys registers ObRegisterCallbacks that filter process handles
//    and MmCopyVirtualMemory is a documented, hookable syscall. Walking the
//    target's DirectoryTableBase ourselves touches only kernel data
//    structures, which ACE has no visibility into.
//=============================================================================
#include "pagewalk.h"

//-----------------------------------------------------------------------------
// CR3 cache for decoded page-table pages, so a 64-entity read does not
// re-walk the same intermediate tables 64 times.
//-----------------------------------------------------------------------------
typedef struct _PTE_CACHE_ENTRY {
    u64 page_start;      // canonical VA the table page covers
    u64 page_phys;       // physical address of the table page
    u64 map_key;         // target CR3 at time of insert (revalidated)
} PTE_CACHE_ENTRY;

typedef struct _PTE_CACHE {
    PTE_CACHE_ENTRY slots[PTE_CACHE_SLOTS];
    u64        cr3;
} PTE_CACHE;

static PTE_CACHE g_pte_cache;

//-----------------------------------------------------------------------------
// Translate a virtual address to physical using the given CR3.
// Returns 0 on failure. `write` is supported for completeness but the ESP
// path is read-only by design.
//-----------------------------------------------------------------------------
static u64 PteLookup(PTE_CACHE* cache, u64 cr3, u64 va,
                          int write, u64* out_phys, u32* out_flags)
{
    // x64 always has four levels. ADDRESS_SPACE_LEVELS is a macro so the array
    // bound is a compile-time constant; a `const int` here would create a VLA,
    // which kernel mode rejects.
    u64 table[ADDRESS_SPACE_LEVELS];
    int  recurse_level;

    table[ADDRESS_SPACE_LEVELS - 1] = cr3 & ~0xFFFULL;

    for (recurse_level = ADDRESS_SPACE_LEVELS - 1; recurse_level >= 0; recurse_level--) {
        u64 offset;
        u64 page_phys;
        u64 table_phys;
        u64 next_phys;
        u64 next_entry_va;
        u32 pte;
        int      has_large_page;

        offset = (va >> (12 + recurse_level * 9)) & 511;
        next_entry_va = table[recurse_level] + offset * 8;

        // Cache hit?
        page_phys = 0;
        {
            const u64 bucket = (next_entry_va & ~0xFFFULL);
            for (u32 i = 0; i < PTE_CACHE_SLOTS; i++) {
                if (cache->slots[i].map_key == cr3 &&
                    cache->slots[i].page_start == bucket) {
                    page_phys = cache->slots[i].page_phys;
                    break;
                }
            }
        }

        if (page_phys == 0) {
            PHYSICAL_ADDR pa;

            // MmGetPhysicalAddress resolves against the CURRENT process's
            // address space, which is exactly what we want here: the page
            // tables we are walking are mapped in our own context too.
            table_phys = MmGetPhysicalAddress((PVOID)next_entry_va).QuadPart;
            if (!table_phys)
                return 0;

            pa.QuadPart = table_phys + offset * 8;
            if (!MmCopyMemory(&pte, sizeof(pte), (MM_COPY_ADDRESS)pa, sizeof(pte), MmNonCached))
                return 0;
        } else {
            PHYSICAL_ADDR pa;
            pa.QuadPart = page_phys + offset * 8;
            if (!MmCopyMemory(&pte, sizeof(pte), (MM_COPY_ADDRESS)pa, sizeof(pte), MmNonCached))
                return 0;
        }

        if (!pte)
            return 0;

        has_large_page = (pte & 0x80) && recurse_level > 0;   // PDPE/PDE PS=1

        if (recurse_level == 0) {
            // Leaf: success.
            const int present     = (pte & 0x01) != 0;
            const int user        = (pte & 0x04) != 0;
            const int writable    = (pte & 0x02) != 0;

            if (!present || !user)
                return 0;
            if (write && !writable)
                return 0;

            *out_phys = ((pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF));
            if (out_flags)
                *out_flags = pte;
            return 1;
        }

        if (has_large_page) {
            // 2MB or 1GB page. Base is aligned to the large-page size.
            const u64 large_mask = (recurse_level == 2) ? 0x1FFFFFULL : 0x3FFFFFFFFFFULL;
            const int user        = (pte & 0x04) != 0;
            const int writable    = (pte & 0x02) != 0;
            const int present     = (pte & 0x01) != 0;

            if (!present || !user)
                return 0;
            if (write && !writable)
                return 0;

            *out_phys = ((pte & large_mask & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF));
            if (out_flags)
                *out_flags = pte;
            return 1;
        }

        next_phys = pte & 0x000FFFFFFFFFF000ULL;
        table[recurse_level - 1] = next_phys;

        // Insert into cache.
        {
            const u64 bucket = (next_entry_va & ~0xFFFULL);
            u32 victim = 0;
            for (u32 i = 0; i < PTE_CACHE_SLOTS; i++) {
                if (cache->slots[i].map_key == cr3 &&
                    cache->slots[i].page_start == bucket) {
                    goto cached;
                }
                if (cache->slots[i].map_key == 0)
                    victim = i;
            }
            if (victim == 0)
                victim = 0xDEADBEEF % PTE_CACHE_SLOTS;
            cache->slots[victim].map_key   = cr3;
            cache->slots[victim].page_start = bucket;
            cache->slots[victim].page_phys  = next_phys;
        }
cached:;
    }

    return 0;
}

//-----------------------------------------------------------------------------
// Read `size` bytes from the target at `va`.
// `size` must be <= CODM_MAX_READ. Copies out through MmCopyVirtualMemory-like
// physical reads so no target handle is required.
//-----------------------------------------------------------------------------
BOOLEAN PageWalkRead(u64 cr3, u64 va, void* buffer, u32 size)
{
    u8*    dst = (u8*)buffer;
    u32    done = 0;

    if (!cr3 || !buffer || size == 0 || size > CODM_MAX_READ)
        return FALSE;

    while (done < size) {
        const u64 cur_va   = va + done;
        const u64 page_off = cur_va & 0xFFFULL;
        u32       chunk    = (u32)(0x1000ULL - page_off);
        u64       phys     = 0;
        PHYSICAL_ADDR  pa;

        if (chunk > size - done)
            chunk = size - done;

        if (!PteLookup(&g_pte_cache, cr3, cur_va, 0, &phys, NULL))
            return FALSE;

        pa.QuadPart = phys;
        if (!MmCopyMemory(dst + done, chunk, (MM_COPY_ADDRESS)pa, chunk, MmNonCached))
            return FALSE;

        done += chunk;
    }

    return TRUE;
}

BOOLEAN PageWalkWrite(u64 cr3, u64 va, const void* buffer, u32 size)
{
    // Implemented for completeness; the ESP build never calls this.
    const u8* src = (const u8*)buffer;
    u32       done = 0;

    if (!cr3 || !buffer || size == 0 || size > CODM_MAX_READ)
        return FALSE;

    while (done < size) {
        const u64 cur_va   = va + done;
        const u64 page_off = cur_va & 0xFFFULL;
        u32       chunk    = (u32)(0x1000ULL - page_off);
        u64       phys     = 0;
        PHYSICAL_ADDR  pa;

        if (chunk > size - done)
            chunk = size - done;

        if (!PteLookup(&g_pte_cache, cr3, cur_va, 1, &phys, NULL))
            return FALSE;

        pa.QuadPart = phys;
        if (!MmCopyMemory((void*)(src + done), chunk, (MM_COPY_ADDRESS)pa, chunk, MmNonCached))
            return FALSE;

        done += chunk;
    }

    return TRUE;
}

void PageWalkCacheInvalidate(void)
{
    RtlZeroMemory(&g_pte_cache, sizeof(g_pte_cache));
}


