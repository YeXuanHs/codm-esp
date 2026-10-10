//=============================================================================
//  driver/pagewalk.h
//=============================================================================
#pragma once

// ntifs.h (not ntddk.h) so this header composes with driver.c, which includes
// ntifs.h; including both would redefine PEPROCESS/PETHREAD.
#include <ntifs.h>

// Kernel headers use the NT typedefs, not the C99 ones. Provide the 64-bit
// scalar names our code uses so the translation unit stays readable.
typedef UINT64  u64;
typedef UINT32  u32;
typedef UINT8   u8;
typedef BOOLEAN bool_t;

// PHYSICAL_ADDR and MM_COPY_ADDRESS live in ntioapi.h, which the WDK does not
// ship as a standalone km header. Their layout is fixed and exported by
// ntoskrnl.exe:
//   typedef struct _PHYSICAL_ADDR { LARGE_INTEGER QuadPart; } PHYSICAL_ADDR;
//   typedef PHYSICAL_ADDR MM_COPY_ADDRESS;
// Declare them under our own names so a future kit that does expose ntioapi.h
// cannot collide with these.
typedef struct _CODM_PHYSICAL_ADDR {
    LARGE_INTEGER QuadPart;
} CODM_PHYSICAL_ADDR, CODM_MM_COPY_ADDRESS;

#define PHYSICAL_ADDR     CODM_PHYSICAL_ADDR
#define MM_COPY_ADDRESS   CODM_MM_COPY_ADDRESS

#define ADDRESS_SPACE_LEVELS  4
#define PTE_CACHE_SLOTS        256
#define CODM_MAX_READ          1024

// Translate a VA in the process owning `cr3` to a physical address.
// Returns TRUE on success and stores the physical address in `out_phys`.
BOOLEAN PteLookupInternal(u64 cr3, u64 va, int write,
                          u64* out_phys, u32* out_flags);

// Read/write up to CODM_MAX_READ bytes in the target process by CR3 walk.
BOOLEAN PageWalkRead(u64 cr3, u64 va, void* buffer, u32 size);

// Copy `size` bytes out of the physical page at `phys`.
//
// MmCopyMemory is deliberately NOT used: it is an undocumented ntoskrnl export
// whose prototype differs between Windows builds (the WDK header here declares
// it as (PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T), while the running
// kernel exports the five-argument (Target, SourceAddress, Length, Flags,
// ReturnSize) form). Binding to either is a portability trap. MmMapIoSpace +
// MmUnmapIoSpace are documented, present in every x64 kernel since Vista, and
// give the same read access to a physical page without opening a handle to the
// owning process -- which is the property that keeps this invisible to ACE's
// ObRegisterCallbacks.
BOOLEAN MmCopyFromPhys(u64 phys, void* dst, u32 size);

//-----------------------------------------------------------------------------
// Physical address sanity bounds.
//
// A stale CR3 (target exited, address space torn down between our two reads)
// makes the page-table walk produce values that look like addresses but point
// nowhere. Mapping such a page with MmMapIoSpace and then touching it raises a
// hard page-fault that bugchecks the machine. Every physical address this
// module produces is checked against these bounds first, and a failure is
// reported as an IOCTL error.
//
// The lower bound rejects the small reserved addresses; the upper bound is
// derived from the maximum physical address the machine reports, which keeps a
// 16 GB host from ever accepting a value that only a much larger box could
// have produced.
//-----------------------------------------------------------------------------
BOOLEAN PhysAddrPlausible(u64 phys);

// Returns the highest valid physical address + 1 on this machine.
u64    PhysAddrLimit(void);

