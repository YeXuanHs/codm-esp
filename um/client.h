#pragma once
// ============================================================
// Shared IOCTL protocol — usermode client (must match helpers.h)
// Read-only: no write operations.
// ============================================================

#include <Windows.h>
#include <cstdint>

// Device path
#define DEVICE_PATH L"\\\\.\\laithdriver"

// IOCTL codes (FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CODM_ATTACH     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CODM_READ       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CODM_GET_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CODM_GET_PID    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CODM_BATCH_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Limits (must match helpers.h)
#define SINGLE_MAX_READ 0x4000   // 16KB per single read
#define BATCH_MAX_REQS  0x1000   // 4096 reads per batch

// ------------------------------------------------------------
// Structures (must match helpers.h)
// ------------------------------------------------------------

// Single read request
typedef struct _Request {
    HANDLE process_id;
    PVOID  target;
    PVOID  buffer;
    SIZE_T size;
} Request, *PRequest;

// PID lookup
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

// Batch read
typedef struct _BatchReadRequest {
    DWORD64 address;
    SIZE_T  size;
    SIZE_T  offset_in_buffer;
} BatchReadRequest, *PBatchReadRequest;

typedef struct _BatchReadHeader {
    HANDLE  process_id;
    UINT32  num_requests;
    SIZE_T  total_buffer_size;
    // Followed by BatchReadRequest[num_requests], then output buffer
} BatchReadHeader, *PBatchReadHeader;

// ------------------------------------------------------------
// KernelDriver client class
// ------------------------------------------------------------
class KernelDriver {
public:
    HANDLE hDevice;

    KernelDriver() : hDevice(INVALID_HANDLE_VALUE) {}
    ~KernelDriver() { Disconnect(); }

    bool Connect() {
        hDevice = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return hDevice != INVALID_HANDLE_VALUE;
    }

    void Disconnect() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    bool IsConnected() const { return hDevice != INVALID_HANDLE_VALUE; }

    // Attach to target process by PID
    bool Attach(DWORD pid) {
        if (!IsConnected()) return false;

        Request req = {};
        req.process_id = (HANDLE)(ULONG_PTR)pid;

        DWORD bytes_returned = 0;
        return DeviceIoControl(hDevice, IOCTL_CODM_ATTACH,
            &req, sizeof(req), nullptr, 0, &bytes_returned, nullptr) != FALSE;
    }

    // Read memory from target process
    bool Read(DWORD pid, UINT64 address, void* buffer, SIZE_T size) {
        if (!IsConnected()) return false;
        if (size == 0 || size > SINGLE_MAX_READ) return false;

        Request req = {};
        req.process_id = (HANDLE)(ULONG_PTR)pid;
        req.target = (PVOID)address;
        req.buffer = buffer;
        req.size = size;

        DWORD bytes_returned = 0;
        return DeviceIoControl(hDevice, IOCTL_CODM_READ,
            &req, sizeof(req), nullptr, 0, &bytes_returned, nullptr) != FALSE;
    }

    // Get PID by process name
    DWORD GetPID(const wchar_t* name) {
        if (!IsConnected()) return 0;

        PID_PACK pack = {};
        wcsncpy_s(pack.name, name, _TRUNCATE);

        DWORD bytes_returned = 0;
        if (!DeviceIoControl(hDevice, IOCTL_CODM_GET_PID,
                &pack, sizeof(pack), &pack, sizeof(pack), &bytes_returned, nullptr)) {
            return 0;
        }
        return pack.pid;
    }

    // Get module base by name
    UINT64 GetModuleBase(DWORD pid, const wchar_t* moduleName) {
        if (!IsConnected()) return 0;

        MODULE_PACK_KM pack = {};
        pack.pid = pid;
        wcsncpy_s(pack.moduleName, moduleName, _TRUNCATE);

        DWORD bytes_returned = 0;
        if (!DeviceIoControl(hDevice, IOCTL_CODM_GET_MODULE,
                &pack, sizeof(pack), &pack, sizeof(pack), &bytes_returned, nullptr)) {
            return 0;
        }
        return pack.baseAddress;
    }

    // Batch read: read many addresses in one ioctl
    bool BatchRead(DWORD pid, const BatchReadRequest* requests, UINT32 count,
                   void* outputBuffer, SIZE_T outputSize) {
        if (!IsConnected()) return false;
        if (count == 0 || count > BATCH_MAX_REQS) return false;

        // Allocate: header + request array + output buffer
        SIZE_T total_size = sizeof(BatchReadHeader)
                          + count * sizeof(BatchReadRequest)
                          + outputSize;
        auto* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total_size);
        if (!buf) return false;

        auto* header = (PBatchReadHeader)buf;
        header->process_id = (HANDLE)(ULONG_PTR)pid;
        header->num_requests = count;
        header->total_buffer_size = outputSize;

        auto* reqs = (PBatchReadRequest)(header + 1);
        memcpy(reqs, requests, count * sizeof(BatchReadRequest));

        // Output buffer is after request array
        BYTE* out = (BYTE*)reqs + count * sizeof(BatchReadRequest);

        DWORD bytes_returned = 0;
        BOOL ok = DeviceIoControl(hDevice, IOCTL_CODM_BATCH_READ,
            buf, (DWORD)total_size, buf, (DWORD)total_size, &bytes_returned, nullptr);

        if (ok) {
            memcpy(outputBuffer, out, outputSize);
        }

        HeapFree(GetProcessHeap(), 0, buf);
        return ok != FALSE;
    }
};
