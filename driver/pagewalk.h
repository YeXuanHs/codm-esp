//=============================================================================
//  driver/pagewalk.h
//=============================================================================
#pragma once

#include <ntddk.h>

#define ADDRESS_SPACE_LEVELS  4
#define PTE_CACHE_SLOTS        256
#define CODM_MAX_READ          1024

// Translate a VA in the process owning `cr3` to a physical address.
// Returns TRUE on success and stores the physical address in `out_phys`.
BOOLEAN PteLookupInternal(uint64_t cr3, uint64_t va, int write,
                          uint64_t* out_phys, uint32_t* out_flags);

// Read/write up to CODM_MAX_READ bytes in the target process by CR3 walk.
BOOLEAN PageWalkRead(uint64_t cr3, uint64_t va, void* buffer, uint32_t size);
BOOLEAN PageWalkWrite(uint64_t cr3, uint64_t va, const void* buffer, uint32_t size);

// Drop cached page-table translations (call on attach/detach/process exit).
void PageWalkCacheInvalidate(void);
