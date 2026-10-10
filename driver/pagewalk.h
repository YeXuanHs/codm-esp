//=============================================================================
//  driver/pagewalk.h
//=============================================================================
#pragma once

#include <ntddk.h>
// ntioapi.h provides PHYSICAL_ADDR, MM_COPY_ADDRESS and
// SID_IDENTIFIER_AUTHORITY, and is part of the WDK's km headers. Including it
// is cleaner (and correct) than redeclaring those layouts here.
#include <ntioapi.h>

// Kernel headers use the NT typedefs, not the C99 ones. Provide the 64-bit
// scalar names our code uses so the translation unit stays readable.
typedef UINT64  u64;
typedef UINT32  u32;
typedef UINT8   u8;
typedef BOOLEAN bool_t;

#define ADDRESS_SPACE_LEVELS  4
#define PTE_CACHE_SLOTS        256
#define CODM_MAX_READ          1024

// Translate a VA in the process owning `cr3` to a physical address.
// Returns TRUE on success and stores the physical address in `out_phys`.
BOOLEAN PteLookupInternal(u64 cr3, u64 va, int write,
                          u64* out_phys, u32* out_flags);

// Read/write up to CODM_MAX_READ bytes in the target process by CR3 walk.
BOOLEAN PageWalkRead(u64 cr3, u64 va, void* buffer, u32 size);
BOOLEAN PageWalkWrite(u64 cr3, u64 va, const void* buffer, u32 size);

// Drop cached page-table translations (call on attach/detach/process exit).
void PageWalkCacheInvalidate(void);
