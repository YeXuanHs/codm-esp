//=============================================================================
//  common/protocol.h
//  Shared contract between codmdrv.sys (kernel) and esp.exe (user mode).
//
//  Design notes
//  ------------
//  * The driver NEVER opens a handle to CODM.exe. It walks the target's page
//    tables directly (EPROCESS->DirectoryTableBase), so ACE's
//    ObRegisterCallbacks process-handle filtering never observes us.
//  * The device object is created with FILE_DEVICE_SECURE_OPEN and a caller
//    SID check; the IOCTL surface is an allow-list, not a generic read().
//  * Every request is authenticated with a per-session XTEA block so a
//    third-party process that manages to open \\.\CodeMmDrv cannot drive it.
//=============================================================================
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

//-----------------------------------------------------------------------------
// Device / driver constants
//-----------------------------------------------------------------------------
#define CODMDRV_DEVICE_NAME     L"\\Device\\CodeMmDrv"
#define CODMDRV_SYM             L"\\DosDevices\\CodeMmDrv"
#define CODMDRV_POOL_TAG        'mMdC'

#define CODMDRV_VERSION         0x00010000

//-----------------------------------------------------------------------------
// IOCTLs - deliberately narrow.
//-----------------------------------------------------------------------------
#define IOCTL_ATTACH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DETACH        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_AT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_BATCH    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

//-----------------------------------------------------------------------------
// Authenticated IOCTL payload.
//
// Every IOCTL buffer is wrapped in this header. `xtea` holds the encrypted
// copy of the real body; `hmac` is TruncatedHmacSha256(policy_key, cipher||seq).
// The driver recomputes and compares before touching anything.
//-----------------------------------------------------------------------------
#pragma pack(push, 8)
typedef struct _CODM_IOCTL_HEADER {
    uint32_t seq;            // monotonic sequence number, anti-replay
    uint32_t body_size;      // decrypted body length
    uint64_t hmac;           // authentication tag
    uint8_t  xtea[4096];     // encrypted body (XTEA, 8-byte blocks)
} CODM_IOCTL_HEADER;

// Plain bodies, one per IOCTL.
typedef struct _CODM_BODY_ATTACH {
    uint32_t pid;            // target process id
} CODM_BODY_ATTACH;

typedef struct _CODM_BODY_DETACH {
    uint32_t reserved;
} CODM_BODY_DETACH;

typedef struct _CODM_READ_REQ {
    uint64_t address;        // virtual address in the TARGET process
    uint32_t size;           // bytes, <= CODM_MAX_READ
    uint32_t flags;          // reserved
} CODM_READ_REQ;

typedef struct _CODM_BODY_READ {
    CODM_READ_REQ req;
    uint8_t       data[1024];
} CODM_BODY_READ;

#define CODM_MAX_BATCH        64
typedef struct _CODM_BATCH_ENTRY {
    uint64_t address;
    uint32_t size;
    uint32_t pad;
} CODM_BATCH_ENTRY;

typedef struct _CODM_BODY_BATCH {
    uint32_t            count;
    CODM_BATCH_ENTRY    entries[CODM_MAX_BATCH];
    uint8_t             data[CODM_MAX_BATCH * 64];
} CODM_BODY_BATCH;

typedef struct _CODM_BODY_PING {
    uint32_t nonce;
    uint32_t reserved;
} CODM_BODY_PING;
#pragma pack(pop)

//-----------------------------------------------------------------------------
// User-mode side helpers (implemented in esp.exe / dumper.exe)
//-----------------------------------------------------------------------------
namespace codm {

// XTEA block cipher, ECB, 32 rounds. Mirrors the kernel implementation.
void xtea_encrypt(uint8_t* buf, size_t words);
void xtea_decrypt(uint8_t* buf, size_t words);

// Authenticated wrap / unwrap of an IOCTL body.
bool ioctl_wrap(CODM_IOCTL_HEADER* hdr, const void* body, uint32_t body_size,
                const uint8_t key[32], uint32_t seq);
bool ioctl_unwrap(const CODM_IOCTL_HEADER* hdr, void* out, uint32_t out_cap,
                  const uint8_t key[32]);

// Driver client: opens \\.\CodeMmDrv and exposes typed helpers.
class DriverClient {
public:
    bool open();
    void close();
    bool ping(uint32_t nonce);
    bool attach(uint32_t pid);
    void detach();
    bool read(uint64_t addr, void* out, uint32_t size);
    // Reads up to `count` (<= CODM_MAX_BATCH) scatters in one round trip.
    // sizes[i] must be <= 64.
    bool read_batch(const uint64_t* addrs, const uint32_t* sizes, uint8_t* out,
                    uint32_t count);

    HANDLE handle() const { return h_; }
private:
    bool transact(IOCTL_CODES code, void* body, uint32_t size);
    HANDLE h_ = INVALID_HANDLE_VALUE;
    uint32_t seq_ = 0;
};

// Locate CODM.exe by image name. Returns 0 if not found / not started.
uint32_t find_process_by_name(const wchar_t* name);

// Read an entire file into a vector. Returns false on failure.
bool read_file(const wchar_t* path, std::vector<uint8_t>& out);
void write_file(const wchar_t* path, const uint8_t* data, size_t size);

} // namespace codm
