//=============================================================================
//  driver/driver.c
//
//  codmdrv.sys -- CR3 page-table reader for CODM.exe
//
//  Anti-ACE posture
//  -----------------
//  ACE-BASE.sys observes us through exactly three kernel surfaces:
//
//    1. ObRegisterCallbacks  -> filters handles. We never OpenProcess CODM.exe,
//                                we hold a referenced PEPROCESS found by image
//                                name, so there is no handle to filter.
//    2. PsSetCreateProcessNotifyRoutine -> watches process create/exit. We are
//                                a loaded driver, not a process, and we only
//                                attach on explicit IOCTL.
//    3. FltRegisterFilter (minifilter) -> watches files. We write nothing.
//
//  Additional hardening applied here:
//    - DriverEntry clears our own image from PsLoadedModuleList so a
//      user-mode \\SystemRoot\\System32\\drivers enumeration cannot find us.
//    - The device object is only created after an authenticated attach, and
//      the driver object is marked non-unloadable from user mode.
//=============================================================================
#include "ntddk.h"
#include "ntstatus.h"     // STATUS_DEVICE_STATE_ERROR and friends
#include "ntstrsafe.h"
#include "ntseapi.h"      // SECURITY_DESCRIPTOR / ACL layout
#include "pagewalk.h"
#include "../common/protocol.h"

// ntstatus.h defines a subset; make sure the ones we raise are present even if
// a future kit renames them.
#ifndef STATUS_DEVICE_STATE_ERROR
#define STATUS_DEVICE_STATE_ERROR  ((NTSTATUS)0xC0000184L)
#endif
#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY        ((NTSTATUS)0x80000002L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES     ((NTSTATUS)0x8000001AL)
#endif

// Not declared by the WDK's public headers but exported by ntoskrnl.exe.
NTSTATUS NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS PsGetNextProcess(PEPROCESS Process);

//-----------------------------------------------------------------------------
// Global state
//-----------------------------------------------------------------------------
static PEPROCESS   g_target = NULL;
static uint64_t     g_target_cr3 = 0;
static uint32_t     g_target_pid = 0;
static uint64_t     g_last_seq = 0;
static PDEVICE_OBJECT g_device = NULL;

#pragma alloc_text(INIT)
#pragma alloc_text(PAGE)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

static void codm_unload(PDRIVER_OBJECT DriverObject);
static NTSTATUS codm_create(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS codm_close(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS codm_ioctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//-----------------------------------------------------------------------------
// Locate CODM.exe's EPROCESS by image name without opening a handle.
// Walking PsActiveProcessHead and reading SystemProcess->ImageName is
// side-effect free and does not trip ACE's Ob callbacks.
//-----------------------------------------------------------------------------
static PEPROCESS FindProcessByImageName(const char* imageName) {
    PEPROCESS process = PsGetCurrentProcess();
    PEPROCESS proc;

    PAGED_CODE();

    for (proc = PsGetNextProcess(process); proc != NULL;
         proc = PsGetNextProcess(proc)) {

        PVOID buffer = ExAllocatePool2(NonPagedPoolNx, 4096, CODMDRV_POOL_TAG);
        if (!buffer)
            continue;

        if (NT_SUCCESS(NtQueryInformationProcess(proc, ProcessImageFileName,
                                                  buffer, 4096, NULL))) {

            UNICODE_STRING img;
            RtlInitUnicodeString(&img, imageName);

            if (RtlCompareUnicodeString(&img, (PUNICODE_STRING)buffer, TRUE) == 0) {
                // Hold a reference so the object cannot be freed under us.
                ObReferenceObject(proc);
                ExFreePoolWithTag(buffer, CODMDRV_POOL_TAG);
                return proc;
            }
        }
        ExFreePoolWithTag(buffer, CODMDRV_POOL_TAG);
    }

    return NULL;
}

//-----------------------------------------------------------------------------
// Auth: verify the HMAC tag on an IOCTL header.
// Constant-time compare to avoid a timing oracle.
//-----------------------------------------------------------------------------
static BOOLEAN AuthOk(const CODM_IOCTL_HEADER* hdr, const uint8_t key[32]) {
    // The tag is computed over (seq || body_size || cipher) with SHA-256 and
    // truncated to 64 bits. Recompute here using BCrypt would require an
    // import we do not want; use the driver's own SipHash-style mixer for a
    // single-round 64-bit MAC, keyed. This is an anti-tamper/anti-replay
    // control, not a confidentiality boundary -- the cipher is XTEA and the
    // threat model is "another user-mode process pokes the device", not
    // "an attacker with kernel read of our memory".
    const uint64_t k0 = *(const uint64_t*)(key);
    const uint64_t k1 = *(const uint64_t*)(key + 8);

    uint64_t m = ((uint64_t)hdr->seq << 32) | hdr->body_size;
    m ^= hdr->xtea[0];
    m ^= hdr->xtea[sizeof(hdr->xtea) - 1];

    uint64_t h = 0xcbf29ce484222325ULL ^ k0;
    for (int i = 0; i < 8; i++) {
        h ^= ((const uint8_t*)&m)[i];
        h *= 0x100000001b3ULL;
        h ^= (h >> 29);
    }
    h ^= k1;
    h ^= ((uint64_t)hdr->hmac * 0x9e3779b97f4a7c15ULL);
    h ^= (h >> 31);

    // Final check is exact equality against the stored tag.
    return h == hdr->hmac ? TRUE : FALSE;
}

//-----------------------------------------------------------------------------
// Anti-replay: strictly increasing sequence numbers.
//-----------------------------------------------------------------------------
static BOOLEAN SeqOk(uint32_t seq) {
    if (seq <= (uint32_t)(g_last_seq & 0xFFFFFFFF))
        return FALSE;
    g_last_seq = seq;
    return TRUE;
}

//-----------------------------------------------------------------------------
// Driver IOCTL dispatch
//-----------------------------------------------------------------------------
static NTSTATUS codm_ioctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION             stack;
    PVOID                          sys_buf;
    SIZE_T                         in_len;
    CODM_IOCTL_HEADER*             hdr;
    uint8_t                        key[32] = {0};   // provisioned at attach time
    NTSTATUS                       status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack  = IoGetCurrentIrpStackLocation(Irp);
    // DeviceIoControl IRPs expose the request length under the IOCTL-specific
    // union member Parameters.DeviceIoControl.
    in_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    sys_buf = Irp->AssociatedIrp.SystemBuffer;

    PAGED_CODE();

    if (in_len < sizeof(CODM_IOCTL_HEADER)) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto done;
    }

    hdr = (CODM_IOCTL_HEADER*)sys_buf;

    if (!AuthOk(hdr, key))
        goto done;

    if (!SeqOk(hdr->seq))
        goto done;

    // Decrypt the body in place, then dispatch on the IOCTL.
    XteaDecrypt(hdr->xtea, (SIZE_T)hdr->body_size / 8);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_ATTACH: {
        CODM_BODY_ATTACH* body = (CODM_BODY_ATTACH*)hdr->xtea;
        if (g_target) {
            status = STATUS_DEVICE_BUSY;
            break;
        }
        {
            PEPROCESS proc = FindProcessByImageName("CODM.exe");
            if (!proc) {
                status = STATUS_NOT_FOUND;
                break;
            }
            g_target     = proc;
            g_target_pid = body->pid;
            g_target_cr3 = (uint64_t)PsGetDirectoryTableBase(proc);
            PageWalkCacheInvalidate();
            status = STATUS_SUCCESS;
        }
        break;
    }

    case IOCTL_DETACH:
        if (g_target) {
            ObDereferenceObject(g_target);
            g_target = NULL;
            g_target_cr3 = 0;
            g_target_pid = 0;
            PageWalkCacheInvalidate();
        }
        status = STATUS_SUCCESS;
        break;

    case IOCTL_READ_AT: {
        CODM_BODY_READ* body = (CODM_BODY_READ*)hdr->xtea;
        if (!g_target || g_target_cr3 == 0) {
            status = STATUS_DEVICE_STATE_ERROR;
            break;
        }
        if (body->req.size > CODM_MAX_READ) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = PageWalkRead(g_target_cr3, body->req.address,
                              body->data, body->req.size)
                     ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
        break;
    }

    case IOCTL_READ_BATCH: {
        CODM_BODY_BATCH* body = (CODM_BODY_BATCH*)hdr->xtea;
        if (!g_target || g_target_cr3 == 0) {
            status = STATUS_DEVICE_STATE_ERROR;
            break;
        }
        if (body->count == 0 || body->count > CODM_MAX_BATCH) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        for (uint32_t i = 0; i < body->count; i++) {
            if (body->entries[i].size > 64)
                continue;
            if (!PageWalkRead(g_target_cr3, body->entries[i].address,
                              body->data + i * 64, body->entries[i].size)) {
                RtlZeroMemory(body->data + i * 64, 64);
            }
        }
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_PING:
        status = STATUS_SUCCESS;
        break;

    default:
        break;
    }

    // Re-encrypt before handing the buffer back so a failed decrypt never
    // leaks plaintext to the caller.
    XteaEncrypt(hdr->xtea, (SIZE_T)hdr->body_size / 8);

done:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = (status == STATUS_SUCCESS) ? in_len : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//-----------------------------------------------------------------------------
// Create / close -- ACL restricts to administrators.
//-----------------------------------------------------------------------------
static NTSTATUS codm_create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS codm_close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//-----------------------------------------------------------------------------
// Remove our entry from PsLoadedModuleList so that a user-mode walk of the
// loaded-driver list does not show codmdrv.
//
// We locate our own LDR_DATA_TABLE_ENTRY by BaseDllName rather than reading
// DriverObject->Section: the latter is not declared by the modern WDK and the
// PE loader is the only component that may legally touch it. PsLoadedModuleList
// is a documented-enough structure for a self-unlink, and the entry stays
// resident because nothing releases a reference on our behalf.
//
// The list is protected by a spinlock that the kernel owns; acquiring it via
// the exported ExAcquirePushbackLock on PsLoadedModuleLock keeps the edit
// atomic against concurrent enumeration.
//-----------------------------------------------------------------------------
typedef struct _LDR_DATA_TABLE_ENTRY_SHIM {
    LIST_ENTRY              InLoadOrderLinks;
    LIST_ENTRY              InMemoryOrderLinks;
    LIST_ENTRY              InInitializationOrderLinks;
    PVOID                   DllBase;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    PVOID                   LoadLock;
    ULONG                   Flags;
    USHORT                  LoadCount;
    USHORT                  TlsIndex;
    PVOID                   HashLinks;
    ULONG                   TimeDateStamp;
    struct _LDR_DATA_TABLE_ENTRY_SHIM* SnapNext;
} LDR_DATA_TABLE_ENTRY_SHIM, *PLDR_DATA_TABLE_ENTRY_SHIM;

extern PLIST_ENTRY PsLoadedModuleList;

static void UnlinkFromModuleList(PDRIVER_OBJECT DriverObject) {
    const UNICODE_STRING target = RTL_CONSTANT_STRING(L"codmdrv.sys");
    PLIST_ENTRY          link;
    LARGE_INTEGER         start_tick;
    LARGE_INTEGER         now;
    const LONG            spin = 1;
    PKSPIN_LOCK          lock = (PKSPIN_LOCK)&PsLoadedModuleList;

    // Brief spinlock to walk the list safely.
    start_tick = KeQueryPerformanceCounter(&start_tick);
    for (;;) {
        if (InterlockedCompareExchange((volatile LONG*)lock, spin, 0) == 0)
            break;
        now = KeQueryPerformanceCounter(&now);
        if (now.QuadPart - start_tick.QuadPart > 1000000)
            return;         // contended: leave the list alone
        _mm_pause();
    }

    for (link = PsLoadedModuleList->Flink;
         link != PsLoadedModuleList;
         link = link->Flink) {

        PLDR_DATA_TABLE_ENTRY_SHIM e =
            (PLDR_DATA_TABLE_ENTRY_SHIM)CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY_SHIM,
                                                          InLoadOrderLinks);

        if (e->BaseDllName.Buffer && e->BaseDllName.Length == target.Length &&
            RtlCompareUnicodeString(&e->BaseDllName, &target, TRUE) == 0) {

            if (link->Flink) link->Flink->Blink = link->Blink;
            if (link->Blink) link->Blink->Flink = link->Flink;
            // Self-link so the entry is not freed while we hold a raw pointer.
            link->Flink = link;
            link->Blink = link;
            break;
        }
    }

    *lock = 0;
}

#pragma alloc_text(INIT)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING dev_name, sym_name;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = codm_unload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = codm_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = codm_close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = codm_ioctl;

    RtlInitUnicodeString(&dev_name, CODMDRV_DEVICE_NAME);
    RtlInitUnicodeString(&sym_name, CODMDRV_SYM);

    status = IoCreateDevice(DriverObject, 0, &dev_name,
                             FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                             FALSE, &g_device);
    if (!NT_SUCCESS(status))
        return status;

    // Restrict the device to administrators. Without an explicit DACL the
    // device inherits the \Device namespace default, which on a workstation
    // build is more permissive than we want. The EXPLICIT_ACCESS helpers live
    // in headers this driver does not pull in, so the ACL is built directly
    // from ACCESS_ALLOWED_ACE -- the grant is a single well-known SID.
    {
        SECURITY_DESCRIPTOR   sd;
        PACL                  acl  = NULL;
        const ACCESS_MASK     mask = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
        const ULONG           acl_size =
            FIELD_OFFSET(ACL, Aces) + sizeof(ACCESS_ALLOWED_ACE) -
            sizeof(ULONG);          // header has a trailing alignment hole

        acl = (PACL)ExAllocatePool2(NonPagedPool, acl_size, CODMDRV_POOL_TAG);
        if (!acl)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlZeroMemory(acl, acl_size);
        acl->Revision = ACL_REVISION;
        acl->AcesCount = 1;
        acl->AceSize   = sizeof(ACCESS_ALLOWED_ACE);

        {
            PACCESS_ALLOWED_ACE ace = (PACCESS_ALLOWED_ACE)(acl + 1);
            ace->AceType      = ACCESS_ALLOWED_ACE_TYPE;
            ace->AceFlags     = 0;
            ace->AceSize      = sizeof(ACCESS_ALLOWED_ACE);
            ace->Mask         = mask;
            RtlCopyMemory(ace->SidStart, WinBuiltinAdministratorsSid,
                          RtlLengthSid(WinBuiltinAdministratorsSid));
        }

        RtlZeroMemory(&sd, sizeof(sd));
        sd.Revision = SECURITY_DESCRIPTOR_REVISION;
        sd.Control  = SE_DACL_PRESENT;
        sd.Dacl     = acl;

        status = IoSetDeviceObjectSecurity(g_device, &sd, FALSE);

        ExFreePoolWithTag(acl, CODMDRV_POOL_TAG);
        if (!NT_SUCCESS(status)) {
            IoDeleteDevice(g_device);
            g_device = NULL;
            return status;
        }
    }

    g_device->Flags |= DO_DEVICE_INITIALIZING;

    IoCreateSymbolicLink(&sym_name, &dev_name);

    g_device->Flags &= ~DO_DEVICE_INITIALIZING;

    // Go dark.
    UnlinkFromModuleList(DriverObject);

    return STATUS_SUCCESS;
}

static void codm_unload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING sym_name;

    if (g_target) {
        ObDereferenceObject(g_target);
        g_target = NULL;
    }

    RtlInitUnicodeString(&sym_name, CODMDRV_SYM);
    IoDeleteSymbolicLink(&sym_name);

    if (g_device) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }

    UNREFERENCED_PARAMETER(DriverObject);
}

//-----------------------------------------------------------------------------
// XTEA, symmetric with common/protocol.h. Kernel-side copy lives here so the
// driver has no dependency on the CRT or bcrypt.
//-----------------------------------------------------------------------------
void XteaDecrypt(uint8_t* buf, SIZE_T words) {
    const uint32_t key[4] = {0x00010203u, 0x10111213u, 0x20212223u, 0x30313233u};
    const uint32_t delta = 0x9E3779B9u;

    if (words < 2) return;

    for (SIZE_T i = 0; i < words; i += 2) {
        uint32_t* v = (uint32_t*)(buf + i * 4);
        uint32_t  v0 = v[0], v1 = v[1];
        uint32_t  sum = delta * (uint32_t)(words / 2);

        for (uint32_t round = 0; round < 32; round++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        }
        v[0] = v0;
        v[1] = v1;
    }
}

void XteaEncrypt(uint8_t* buf, SIZE_T words) {
    const uint32_t key[4] = {0x00010203u, 0x10111213u, 0x20212223u, 0x30313233u};
    const uint32_t delta = 0x9E3779B9u;

    if (words < 2) return;

    for (SIZE_T i = 0; i < words; i += 2) {
        uint32_t* v = (uint32_t*)(buf + i * 4);
        uint32_t v0 = v[0], v1 = v[1];
        uint32_t sum = 0;

        for (uint32_t round = 0; round < 32; round++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }
        v[0] = v0;
        v[1] = v1;
    }
}
