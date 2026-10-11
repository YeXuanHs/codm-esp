#pragma once
#include <ntifs.h>
#include <ntintsafe.h>

// ============================================================
// CODM ESP — read-only kernel R/W (derived from laith-km-driver)
// Read-only: no write IOCTL, no unlink, no process-terminating calls.
// Target: CODMGameApps/CODMGameApps.exe (Unity IL2CPP, ACE-protected).
// Load: kdmapper (IoCreateDriver manual map; DO_NOT_WAIT used by mapper).
// ============================================================

#define POOL_TAG 'oamL'

// --- EPROCESS offsets (Win11 26H1 / Build 28000) ---
// TODO: confirm against target ntoskrnl PDB before trusting.
#define EPROCESS_ImageFileName        0x5A8
#define EPROCESS_ActiveThreads        0x5F0
#define EPROCESS_ThreadListHead       0x5E0
#define EPROCESS_ActiveProcessLinks   0x448
#define EPROCESS_UniqueProcessId      0x440

// Read size limits
#define SINGLE_MAX_READ  0x4000       // 16KB per single read
#define BATCH_MAX_REQS   0x1000       // 4096 reads per batch

static PEPROCESS cached_process = nullptr;
static HANDLE    cached_pid = nullptr;
static FAST_MUTEX cache_lock;

extern "C" {
    NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
        PDRIVER_INITIALIZE InitializationFunction);

    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
        PEPROCESS TargetProcess, PVOID TargetAddress,
        SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize);

    NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
    NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
}

void debug_print(PCSTR text) {
#ifdef DEBUG
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
#else
    UNREFERENCED_PARAMETER(text);
#endif
}

// ------------------------------------------------------------
// Structures shared with usermode (must match um/client.cpp)
// ------------------------------------------------------------

// Single read: read SIZE bytes from target VA into caller's buffer
typedef struct _Request {
    HANDLE process_id;
    PVOID  target;    // target virtual address
    PVOID  buffer;    // usermode output buffer
    SIZE_T size;
} Request, *PRequest;

// PID lookup by process name
typedef struct _PID_PACK {
    UINT32 pid;
    WCHAR  name[260];
} PID_PACK, *P_PID_PACK;

// Module base lookup
typedef struct _MODULE_PACK_KM {
    UINT32 pid;
    UINT64 baseAddress;
    SIZE_T size;
    WCHAR  moduleName[260];
} MODULE_PACK_KM, *PMODULE_PACK_KM;

// Batch read: many addresses in one ioctl
typedef struct _BatchReadRequest {
    DWORD64 address;
    SIZE_T  size;
    SIZE_T  offset_in_buffer;   // offset into output buffer
} BatchReadRequest, *PBatchReadRequest;

typedef struct _BatchReadHeader {
    HANDLE  process_id;
    UINT32  num_requests;
    SIZE_T  total_buffer_size;  // size of output buffer after request array
    // Followed by BatchReadRequest[num_requests], then output buffer
} BatchReadHeader, *PBatchReadHeader;

// ------------------------------------------------------------
// ZwQuerySystemInformation types
// ------------------------------------------------------------
#define SystemModuleInformation 11
#define SystemProcessInformation 5

typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved[2];
    PVOID  Base;
    ULONG  Size;
    ULONG  Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG_PTR     ulModuleCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG  WaitTime;
    PVOID  StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG   BasePriority;
    ULONG  ContextSwitches;
    ULONG  ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// ------------------------------------------------------------
// PEB structures (for module base lookup)
// ------------------------------------------------------------
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        } Info;
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

// Safe compare: return true if str starts with in_str (case-insensitive)
template <typename str_type, typename str_type_2>
__forceinline bool crt_starts_with(str_type str, str_type_2 in_str) {
    if (!str || !in_str) return false;
    wchar_t c1, c2;
#define to_lower(c) ((c >= 'A' && c <= 'Z') ? (c + 32) : c)
    do {
        c1 = *str++; c2 = *in_str++;
        c1 = to_lower(c1); c2 = to_lower(c2);
        if (!c2) return true;
    } while (c1 && c1 == c2);
    return false;
#undef to_lower
}

// Get PID by process name (exact, case-insensitive)
HANDLE GetPID(const wchar_t* process_name) {
    ULONG length = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &length);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, POOL_TAG);
    if (!buffer) return NULL;

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, length, &length);
    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        return NULL;
    }

    auto* process_info = (PSYSTEM_PROCESS_INFORMATION)buffer;
    HANDLE result = NULL;

    while (TRUE) {
        if (process_info->ImageName.Buffer && process_info->ImageName.Length > 0) {
            if (_wcsicmp(process_info->ImageName.Buffer, process_name) == 0) {
                result = process_info->UniqueProcessId;
                break;
            }
        }
        if (process_info->NextEntryOffset == 0) break;
        process_info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)process_info + process_info->NextEntryOffset);
    }

    ExFreePool(buffer);
    return result;
}

// Get module base by walking PEB loader list
PVOID GetProcessModuleBase(HANDLE processId, const wchar_t* moduleName) {
    PEPROCESS targetProcess = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(processId, &targetProcess);
    if (!NT_SUCCESS(status) || !targetProcess) return nullptr;

    KAPC_STATE apcState;
    KeStackAttachProcess(targetProcess, &apcState);

    PVOID moduleBase = nullptr;
    __try {
        PPEB peb = PsGetProcessPeb(targetProcess);
        if (!peb) __leave;

        PPEB_LDR_DATA ldrData = peb->Ldr;
        if (!ldrData) __leave;

        PLIST_ENTRY listHead = &ldrData->InLoadOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;

        while (listEntry != listHead) {
            auto* ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0) {
                UNICODE_STRING target = {};
                RtlInitUnicodeString(&target, moduleName);
                if (RtlEqualUnicodeString(&ldrEntry->BaseDllName, &target, TRUE)) {
                    moduleBase = ldrEntry->DllBase;
                    break;
                }
            }
            listEntry = listEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        moduleBase = nullptr;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);
    return moduleBase;
}

// Resolve process PEPROCESS with cache
PEPROCESS ResolveProcess(HANDLE pid) {
    PEPROCESS proc = nullptr;

    ExAcquireFastMutex(&cache_lock);
    if (cached_process && cached_pid == pid) {
        proc = cached_process;
        ObReferenceObject(proc);
        ExReleaseFastMutex(&cache_lock);
        return proc;
    }
    ExReleaseFastMutex(&cache_lock);

    NTSTATUS status = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(status)) return nullptr;

    ExAcquireFastMutex(&cache_lock);
    if (cached_process) ObDereferenceObject(cached_process);
    cached_process = proc;
    cached_pid = pid;
    ObReferenceObject(proc);
    ExReleaseFastMutex(&cache_lock);

    return proc;
}

// ------------------------------------------------------------
// IOCTL handlers (called from device_control in main.cpp)
// ------------------------------------------------------------

NTSTATUS handle_attach(PIRP irp, SIZE_T* information) {
    auto* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS temp_process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(request->process_id, &temp_process);

    if (NT_SUCCESS(status)) {
        ExAcquireFastMutex(&cache_lock);
        if (cached_process && cached_pid != request->process_id) {
            ObDereferenceObject(cached_process);
        }
        cached_process = temp_process;
        cached_pid = request->process_id;
        ExReleaseFastMutex(&cache_lock);
    }

    *information = NT_SUCCESS(status) ? sizeof(Request) : 0;
    return status;
}

NTSTATUS handle_get_pid(PIRP irp, SIZE_T* information) {
    auto* pidPack = (P_PID_PACK)irp->AssociatedIrp.SystemBuffer;

    if (pidPack && pidPack->name[0] != 0) {
        HANDLE processId = GetPID(pidPack->name);
        pidPack->pid = HandleToULong(processId);
        *information = sizeof(PID_PACK);
        return (processId != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    *information = 0;
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS handle_get_module(PIRP irp, SIZE_T* information) {
    auto* modulePack = (PMODULE_PACK_KM)irp->AssociatedIrp.SystemBuffer;

    if (modulePack && modulePack->moduleName[0] != 0 && modulePack->pid != 0) {
        HANDLE processId = ULongToHandle(modulePack->pid);
        PVOID baseAddr = GetProcessModuleBase(processId, modulePack->moduleName);

        modulePack->baseAddress = (UINT64)baseAddr;
        *information = sizeof(MODULE_PACK_KM);
        return (baseAddr != nullptr) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    *information = 0;
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS handle_read(PIRP irp, SIZE_T* information) {
    auto* request = (Request*)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS target_process = ResolveProcess(request->process_id);
    if (!target_process) {
        *information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    // Validate
    ULONG_PTR addr = (ULONG_PTR)request->target;
    SIZE_T size = request->size;
    if (size == 0 || size > SINGLE_MAX_READ ||
        !request->buffer ||
        addr < 0x10000 || addr >= 0x7FFFFFFFFFFF ||
        (addr + size) <= addr) {
        ObDereferenceObject(target_process);
        *information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T return_size = 0;
    NTSTATUS status = MmCopyVirtualMemory(
        target_process, request->target,
        PsGetCurrentProcess(), request->buffer,
        size, KernelMode, &return_size);

    ObDereferenceObject(target_process);
    *information = NT_SUCCESS(status) ? sizeof(Request) : 0;
    return status;
}

NTSTATUS handle_batch_read(PIRP irp, PIO_STACK_LOCATION stack_irp, SIZE_T* information) {
    auto* header = (PBatchReadHeader)irp->AssociatedIrp.SystemBuffer;

    UINT32 num_requests = header->num_requests;
    if (num_requests == 0 || num_requests > BATCH_MAX_REQS) {
        *information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T expected_size = sizeof(BatchReadHeader) + (num_requests * sizeof(BatchReadRequest));
    if (stack_irp->Parameters.DeviceIoControl.InputBufferLength < expected_size) {
        *information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEPROCESS target_process = ResolveProcess(header->process_id);
    if (!target_process) {
        *information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    auto* requests = (PBatchReadRequest)(header + 1);
    BYTE* output_buffer = (BYTE*)requests + (num_requests * sizeof(BatchReadRequest));
    SIZE_T total_buffer_size = header->total_buffer_size;

    UINT32 successful_reads = 0;

    for (UINT32 i = 0; i < num_requests; ++i) {
        auto* req = &requests[i];
        ULONG_PTR addr = (ULONG_PTR)req->address;
        SIZE_T size = req->size;
        SIZE_T offset = req->offset_in_buffer;

        // Validate each read
        if (size == 0 || size > 0x10000 ||
            addr < 0x10000 || addr >= 0x7FFFFFFFFFFF ||
            (addr + size) <= addr ||
            (offset + size) > total_buffer_size) {
            if ((offset + size) <= total_buffer_size)
                RtlZeroMemory(output_buffer + offset, size);
            continue;
        }

        SIZE_T bytes_read = 0;
        if (NT_SUCCESS(MmCopyVirtualMemory(
                target_process, (PVOID)addr,
                PsGetCurrentProcess(), output_buffer + offset,
                size, KernelMode, &bytes_read))) {
            ++successful_reads;
        } else {
            RtlZeroMemory(output_buffer + offset, size);
        }
    }

    ObDereferenceObject(target_process);

    NTSTATUS status = successful_reads ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    *information = NT_SUCCESS(status)
        ? stack_irp->Parameters.DeviceIoControl.InputBufferLength : 0;
    return status;
}
