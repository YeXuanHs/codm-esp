// ============================================================
// CODM ESP — IL2CPP memory scanner / metadata dumper
//
// Uses the read-only kernel driver (km.sys) to:
//   * enumerate every module of the target process
//   * blind-scan the address space for the IL2CPP global-metadata
//     magic (0xFAB11BAF) and other signatures
//   * dump the whole metadata blob to disk for offline analysis
//
// Usage:
//   scanner modules
//   scanner scan [--deep] [--range START:END]...
//   scanner dump <addr> <size> <outfile>
//   scanner pe <moduleName> <outfile>
//   scanner meta [--deep]
//   scanner read <addr> <size>
// ============================================================

#include "client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>

#pragma comment(lib, "ntdll.lib")

// ------------------------------------------------------------
// Signatures
// ------------------------------------------------------------
struct Magic {
    uint32_t    value;
    const char* name;
};

static const Magic kMagics[] = {
    { 0xFAB11BAFu, "il2cpp-global-metadata" },
    { 0x0BADF00Du,  "ace-debug-marker"       },
    { 0xC0DECAFEu,  "codm-marker"           },
};
static const size_t kMagicCount = sizeof(kMagics) / sizeof(kMagics[0]);

// ------------------------------------------------------------
// Tunables
// ------------------------------------------------------------
static const uint64_t kPageSize        = 0x1000;
static const uint64_t kPageOverlap     = 0x10;   // catch magics straddling pages
static const UINT32   kBatchPages      = 256;    // pages per DriverIoControl call
static const uint64_t kMinUserAddr     = 0x10000;
static const uint64_t kMaxUserAddr     = 0x00007FFFFFFFFFFFull;

// Default scan windows (a full x64 user range is far too big to brute force).
struct Range { uint64_t start; uint64_t end; const char* label; };

static const Range kDefaultRanges[] = {
    { 0x0000000000010000ull, 0x0000000000100000ull, "low-1MB"        },
    { 0x0000000000100000ull, 0x0000000010000000ull, "user-2G"        },
    { 0x0000000010000000ull, 0x0000000080000000ull, "heap-2G"        },
    { 0x0000000080000000ull, 0x0000000100000000ull, "mid-512M"       },
};
static const size_t kDefaultRangeCount = sizeof(kDefaultRanges) / sizeof(kDefaultRanges[0]);

// Deep ranges: only used with --deep (slow, several minutes)
static const Range kDeepRanges[] = {
    { 0x0000000100000000ull, 0x0000000800000000ull, "high-16G" },
    { 0x0000000800000000ull, 0x0000004000000000ull, "high-64G" },
};
static const size_t kDeepRangeCount = sizeof(kDeepRanges) / sizeof(kDeepRanges[0]);

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
static double Now() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

struct Hit {
    uint64_t    address;
    const char* kind;
};

static std::vector<Hit> g_hits;

static bool IsKnownHit(uint64_t addr) {
    for (const auto& h : g_hits)
        if (h.address == addr) return true;
    return false;
}

static void AddHit(uint64_t addr, const char* kind) {
    if (IsKnownHit(addr)) return;
    g_hits.push_back({ addr, kind });
    printf("[+] HIT  %016llX  %s\n", (unsigned long long)addr, kind);
    fflush(stdout);
}

// Read a contiguous block with the single-read IOCTL (max 16 KB per call)
static bool ReadBlock(KernelDriver& kd, DWORD pid, uint64_t addr, uint8_t* buf, size_t size) {
    size_t done = 0;
    while (done < size) {
        size_t chunk = std::min<size_t>(SINGLE_MAX_READ, size - done);
        if (!kd.Read(pid, addr + done, buf + done, chunk))
            return false;
        done += chunk;
    }
    return true;
}

// ------------------------------------------------------------
// Signature scan over an already-read buffer
// Returns number of matches found.
//
static int ScanBuffer(const uint8_t* buf, size_t len, uint64_t base) {
    int found = 0;
    if (len < 4) return 0;

    for (const auto& m : kMagics) {
        for (size_t i = 0; i + 4 <= len; ++i) {
            uint32_t v;
            memcpy(&v, buf + i, 4);
            if (v == m.value) {
                AddHit(base + i, m.name);
                ++found;
            }
        }
    }
    return found;
}

// ------------------------------------------------------------
// Blind-scan an address range using batched page reads
// ------------------------------------------------------------
static void ScanRange(KernelDriver& kd, DWORD pid,
                      uint64_t start, uint64_t end, const char* label) {
    if (end <= start) return;

    const uint64_t span = kPageSize + kPageOverlap;   // bytes fetched per page
    const uint64_t total = end - start;
    uint64_t scanned = 0;
    uint64_t mappedBytes = 0;
    double t0 = Now();

    printf("[*] Scanning %-12s %016llX - %016llX (%.2f GB)\n",
           label, (unsigned long long)start, (unsigned long long)end,
           total / (1024.0 * 1024.0 * 1024.0));
    fflush(stdout);

    std::vector<BatchReadRequest> reqs;
    std::vector<uint8_t>           out;
    reqs.reserve(kBatchPages);
    out.resize((size_t)kBatchPages * span);

    while (start < end) {
        reqs.clear();

        for (UINT32 i = 0; i < kBatchPages && start < end; ++i) {
            BatchReadRequest r = {};
            r.address          = start;
            r.size             = span;
            r.offset_in_buffer = (SIZE_T)i * span;
            reqs.push_back(r);
            start += kPageSize;
        }

        if (reqs.empty()) break;

        kd.BatchRead(pid, reqs.data(), (UINT32)reqs.size(),
                     out.data(), (SIZE_T)reqs.size() * span);

        for (UINT32 i = 0; i < reqs.size(); ++i) {
            const uint8_t* p = out.data() + (size_t)i * span;

            // A mapped page is one that is not entirely zero AND sits next to
            // readable content. Unmapped pages come back zero-filled.
            bool nonZero = false;
            for (size_t k = 0; k < kPageSize; k += 64) {
                if (p[k]) { nonZero = true; break; }
            }
            if (nonZero) mappedBytes += kPageSize;

            ScanBuffer(p, (size_t)span, reqs[i].address);
        }

        scanned += (uint64_t)reqs.size() * kPageSize;
        if ((scanned & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            double rate = el > 0 ? (scanned / 1024.0 / 1024.0) / el : 0;
            printf("    %6.2f GB scanned  %6.1f MB/s  hits=%zu\n",
                   scanned / (1024.0 * 1024.0 * 1024.0), rate, g_hits.size());
            fflush(stdout);
        }
    }

    printf("[*] %-12s done in %.1fs (mapped ~%.2f GB)\n\n",
           label, Now() - t0, mappedBytes / (1024.0 * 1024.0 * 1024.0));
}

// ------------------------------------------------------------
// Scan a module image (contiguous reads, much faster per byte)
// ------------------------------------------------------------
static void ScanModule(KernelDriver& kd, DWORD pid,
                       const MODULE_PACK_KM& m) {
    printf("[*] Module %-32s %016llX - %016llX (%.2f MB)\n",
           m.moduleName,
           (unsigned long long)m.baseAddress,
           (unsigned long long)(m.baseAddress + m.size),
           m.size / (1024.0 * 1024.0));
    fflush(stdout);

    double t0 = Now();
    uint64_t done = 0;
    std::vector<uint8_t> buf(SINGLE_MAX_READ);

    while (done < m.size) {
        size_t chunk = std::min<size_t>(SINGLE_MAX_READ, (size_t)(m.size - done));
        if (!kd.Read(pid, m.baseAddress + done, buf.data(), chunk)) break;

        ScanBuffer(buf.data(), chunk, m.baseAddress + done);

        done += chunk;
        if ((done & 0x200000ull) == 0) {
            printf("    %6.2f / %6.2f MB\n",
                   done / 1024.0 / 1024.0, m.size / 1024.0 / 1024.0);
            fflush(stdout);
        }
    }
    printf("[*] module scan done in %.1fs\n\n", Now() - t0);
}

// ------------------------------------------------------------
// Scan a range for 8-byte little-endian pointers equal to `target`.
// Used to locate IL2CPP runtime objects (Il2CppClass, Il2CppType,
// metadata registration entries) by the address of their name string.
//
//   scanner findptr 2A717399
// ------------------------------------------------------------
static std::vector<uint64_t> g_ptr_hits;

static void ScanValue(KernelDriver& kd, DWORD pid,
                      uint64_t start, uint64_t end, uint64_t target,
                      const char* label) {
    if (end <= start) return;

    const uint64_t span = kPageSize + kPageOverlap;
    const uint64_t total = end - start;
    uint64_t scanned = 0;
    double t0 = Now();

    printf("[*] findptr %016llX in %-12s %016llX - %016llX (%.2f GB)\n",
           (unsigned long long)target, label,
           (unsigned long long)start, (unsigned long long)end,
           total / (1024.0 * 1024.0 * 1024.0));
    fflush(stdout);

    std::vector<BatchReadRequest> reqs;
    std::vector<uint8_t>           out;
    reqs.reserve(kBatchPages);
    out.resize((size_t)kBatchPages * span);

    while (start < end) {
        reqs.clear();
        for (UINT32 i = 0; i < kBatchPages && start < end; ++i) {
            BatchReadRequest r = {};
            r.address          = start;
            r.size             = span;
            r.offset_in_buffer = (SIZE_T)i * span;
            reqs.push_back(r);
            start += kPageSize;
        }
        if (reqs.empty()) break;

        kd.BatchRead(pid, reqs.data(), (UINT32)reqs.size(),
                     out.data(), (SIZE_T)reqs.size() * span);

        for (UINT32 i = 0; i < reqs.size(); ++i) {
            const uint8_t* p = out.data() + (size_t)i * span;
            uint64_t base = reqs[i].address;
            // pointers are 8-aligned; step 8 from the (page-aligned) base
            for (uint64_t o = 0; o + 8 <= span; o += 8) {
                uint64_t v;
                memcpy(&v, p + o, 8);
                if (v == target) {
                    uint64_t at = base + o;
                    g_ptr_hits.push_back(at);
                    printf("[+] PTR HIT %016llX -> %016llX\n",
                           (unsigned long long)at, (unsigned long long)v);
                    fflush(stdout);
                }
            }
        }

        scanned += (uint64_t)reqs.size() * kPageSize;
        if ((scanned & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            printf("    %6.2f GB scanned  %6.1f MB/s  hits=%zu\n",
                   scanned / (1024.0 * 1024.0 * 1024.0),
                   el > 0 ? (scanned / 1048576.0) / el : 0, g_ptr_hits.size());
            fflush(stdout);
        }
    }

    printf("[*] findptr done in %.1fs, %zu hits\n\n", Now() - t0, g_ptr_hits.size());
}

static int CmdFindPtr(KernelDriver& kd, DWORD pid, uint64_t target,
                      const std::vector<Range>& extra) {
    for (size_t i = 0; i < kDefaultRangeCount; ++i)
        ScanValue(kd, pid, kDefaultRanges[i].start, kDefaultRanges[i].end,
                  target, kDefaultRanges[i].label);

    for (const auto& r : extra)
        ScanValue(kd, pid, r.start, r.end, target, "custom");

    printf("[=] %zu pointer(s) to %016llX\n", g_ptr_hits.size(), (unsigned long long)target);
    return g_ptr_hits.size() ? 0 : 1;
}

// ------------------------------------------------------------
// Byte-pattern scan: find every copy of an ASCII string in memory.
// IL2CPP keeps its own heap copies of type names, so the runtime
// Il2CppClass->name points at one of these, not at the metadata blob.
//
//   scanner findstr A2DCharacterBaseData
// ------------------------------------------------------------
static std::vector<uint64_t> g_str_hits;

static void ScanPattern(KernelDriver& kd, DWORD pid,
                        uint64_t start, uint64_t end,
                        const std::vector<uint8_t>& pat,
                        const char* label) {
    if (end <= start || pat.empty()) return;

    const uint64_t span = kPageSize + kPageOverlap;
    uint64_t scanned = 0;
    double t0 = Now();

    printf("[*] findstr (%zu bytes) in %-12s %016llX - %016llX\n",
           pat.size(), label,
           (unsigned long long)start, (unsigned long long)end);
    fflush(stdout);

    std::vector<BatchReadRequest> reqs;
    std::vector<uint8_t>           out;
    reqs.reserve(kBatchPages);
    out.resize((size_t)kBatchPages * span);

    while (start < end) {
        reqs.clear();
        for (UINT32 i = 0; i < kBatchPages && start < end; ++i) {
            BatchReadRequest r = {};
            r.address          = start;
            r.size             = span;
            r.offset_in_buffer = (SIZE_T)i * span;
            reqs.push_back(r);
            start += kPageSize;
        }
        if (reqs.empty()) break;

        kd.BatchRead(pid, reqs.data(), (UINT32)reqs.size(),
                     out.data(), (SIZE_T)reqs.size() * span);

        for (UINT32 i = 0; i < reqs.size(); ++i) {
            const uint8_t* p = out.data() + (size_t)i * span;
            size_t limit = (size_t)span - pat.size();
            for (size_t o = 0; o <= limit; ++o) {
                if (memcmp(p + o, pat.data(), pat.size()) == 0) {
                    uint64_t at = reqs[i].address + o;
                    g_str_hits.push_back(at);
                    printf("[+] STR HIT %016llX\n", (unsigned long long)at);
                    fflush(stdout);
                }
            }
        }

        scanned += (uint64_t)reqs.size() * kPageSize;
        if ((scanned & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            printf("    %6.2f GB scanned  %6.1f MB/s  hits=%zu\n",
                   scanned / (1024.0 * 1024.0 * 1024.0),
                   el > 0 ? (scanned / 1048576.0) / el : 0, g_str_hits.size());
            fflush(stdout);
        }
    }

    printf("[*] findstr done in %.1fs, %zu hits\n\n", Now() - t0, g_str_hits.size());
}

static int CmdFindStr(KernelDriver& kd, DWORD pid, const char* text,
                      const std::vector<Range>& extra) {
    std::vector<uint8_t> pat(text, text + strlen(text));
    pat.push_back(0);

    for (size_t i = 0; i < kDefaultRangeCount; ++i)
        ScanPattern(kd, pid, kDefaultRanges[i].start, kDefaultRanges[i].end,
                    pat, kDefaultRanges[i].label);
    for (const auto& r : extra)
        ScanPattern(kd, pid, r.start, r.end, pat, "custom");

    printf("[=] %zu copy/copies of \"%s\"\n", g_str_hits.size(), text);
    return g_str_hits.size() ? 0 : 1;
}

// ------------------------------------------------------------
// Structure probe: dump 256 bytes as qwords and, for every value that
// looks like a pointer into a mapped page, try to render it as a string.
// Used to reverse the (custom, non-stock) Il2CppClass layout.
// ------------------------------------------------------------
static bool LooksLikeString(KernelDriver& kd, DWORD pid, uint64_t addr, char* outBuf,
                            size_t bufSize) {
    uint8_t tmp[64] = {};
    if (!kd.Read(pid, addr, tmp, 48)) return false;
    size_t n = 0;
    for (; n < 48 && tmp[n]; ++n) {
        if (tmp[n] < 0x20 || tmp[n] > 0x7E) return false;
        outBuf[n] = (char)tmp[n];
    }
    if (n < 2 || n >= bufSize) return false;
    outBuf[n] = 0;
    return true;
}

static int CmdProbe(KernelDriver& kd, DWORD pid, uint64_t addr, size_t bytes) {
    if (bytes < 8 || bytes > 0x400) bytes = 0x100;
    std::vector<uint8_t> buf(bytes);
    if (!ReadBlock(kd, pid, addr, buf.data(), bytes)) {
        printf("[!] Read failed at %016llX\n", (unsigned long long)addr);
        return 2;
    }

    printf("== probe %016llX (%zu bytes) ==\n", (unsigned long long)addr, bytes);
    for (size_t o = 0; o + 8 <= bytes; o += 8) {
        uint64_t v;
        memcpy(&v, buf.data() + o, 8);
        printf("  +0x%02X  %016llX", (unsigned)o, (unsigned long long)v);

        char s[64];
        if (v >= kMinUserAddr && v < kMaxUserAddr &&
            LooksLikeString(kd, pid, v, s, sizeof(s))) {
            printf("   -> \"%s\"", s);
        } else if (v == 0) {
            printf("   (null)");
        }
        printf("\n");
    }
    return 0;
}

// ------------------------------------------------------------
// findclass <TypeName>: findstr for the name, then findptr on each copy,
// then probe every candidate. This walks name-string -> Il2CppClass without
// knowing anything about the (custom) Il2CppClass layout.
// ------------------------------------------------------------
static int CmdFindClass(KernelDriver& kd, DWORD pid, const char* name,
                        const std::vector<Range>& extra) {
    // 1) every heap copy of the type name
    CmdFindStr(kd, pid, name, extra);
    if (g_str_hits.empty()) {
        printf("[!] no copy of \"%s\" found\n", name);
        return 1;
    }

    // 2) pointers to each copy -> Il2CppClass (or whatever holds the name)
    for (uint64_t s : g_str_hits) {
        g_ptr_hits.clear();
        for (size_t i = 0; i < kDefaultRangeCount; ++i)
            ScanValue(kd, pid, kDefaultRanges[i].start, kDefaultRanges[i].end,
                      s, kDefaultRanges[i].label);
        for (const auto& r : extra)
            ScanValue(kd, pid, r.start, r.end, s, "custom");

        printf("\n===== string %016llX : %zu referrer(s) =====\n",
               (unsigned long long)s, g_ptr_hits.size());
        for (uint64_t p : g_ptr_hits)
            CmdProbe(kd, pid, p >= 8 ? p - 8 : p, 0x80);
    }
    return 0;
}

// ------------------------------------------------------------
// probeobj <addr> <size>
//
// Walks an object slot by slot and annotates every 8-byte field. The
// Il2CppClass layout in this build is confirmed as:
//     +0x10 name (metadata string)   +0x18 namespace
// so any slot that points at a class can be printed by name, and any slot
// that points straight at printable text is a runtime string.
// ------------------------------------------------------------
static bool ReadCString(KernelDriver& kd, DWORD pid, uint64_t addr,
                        char* out, size_t outSize) {
    uint8_t tmp[96] = {};
    if (!kd.Read(pid, addr, tmp, sizeof(tmp))) return false;
    size_t n = 0;
    for (; n < sizeof(tmp) && tmp[n]; ++n) {
        if (tmp[n] < 0x20 || tmp[n] > 0x7E) return false;
        out[n] = (char)tmp[n];
    }
    if (n < 2 || n >= outSize) return false;
    out[n] = 0;
    return true;
}

static int CmdProbeObj(KernelDriver& kd, DWORD pid, uint64_t addr, size_t size) {
    if (size == 0 || size > 0x8000) size = 0x1000;
    std::vector<uint8_t> buf(size);
    if (!ReadBlock(kd, pid, addr, buf.data(), size)) {
        printf("[!] Read failed at %016llX\n", (unsigned long long)addr);
        return 2;
    }

    printf("== probeobj %016llX (%zu bytes) ==\n", (unsigned long long)addr, size);
    size_t slots = size / 8;

    for (size_t i = 0; i < slots; ++i) {
        uint64_t v;
        memcpy(&v, buf.data() + i * 8, 8);

        char s[96];
        const char* tag = nullptr;

        if (v == 0) {
            tag = "null";
        } else if (v >= kMinUserAddr && v < kMaxUserAddr) {
            // 1) does it point at an Il2CppClass? (name@+0x10, ns@+0x18)
            char name[64] = {}, ns[64] = {};
            if (ReadCString(kd, pid, v + 0x10, name, sizeof(name)) &&
                ReadCString(kd, pid, v + 0x18, ns, sizeof(ns))) {
                printf("  +0x%04X  %016llX  class %s.%s\n", (unsigned)(i * 8),
                       (unsigned long long)v, ns, name);
                continue;
            }
            // 2) is it a plain runtime string?
            if (ReadCString(kd, pid, v, s, sizeof(s))) {
                printf("  +0x%04X  %016llX  str  \"%s\"\n", (unsigned)(i * 8),
                       (unsigned long long)v, s);
                continue;
            }
            tag = "ptr";
        } else {
            tag = "imm";
        }

        uint32_t lo = (uint32_t)(v & 0xFFFFFFFF);
        uint32_t hi = (uint32_t)(v >> 32);
        float  f;
        memcpy(&f, &lo, 4);

        if (tag && !strcmp(tag, "imm")) {
            if (hi == 0) {
                if (lo < 0x10000)
                    printf("  +0x%04X  %016llX  int  %u\n", (unsigned)(i * 8),
                           (unsigned long long)v, lo);
                else
                    printf("  +0x%04X  %016llX  flt  %g\n", (unsigned)(i * 8),
                           (unsigned long long)v, (double)f);
            } else {
                printf("  +0x%04X  %016llX  raw  %u:%u\n", (unsigned)(i * 8),
                       (unsigned long long)v, hi, lo);
            }
        } else {
            printf("  +0x%04X  %016llX  %s\n", (unsigned)(i * 8),
                   (unsigned long long)v, tag);
        }
    }
    return 0;
}

// ------------------------------------------------------------
// findobj <classAddr> [size]
//
// findptr hits are mostly type-registration tables, so keep only the
// candidates that look like real managed objects: the whole instance must be
// readable and a meaningful share of the slots must point back into the
// process.
// ------------------------------------------------------------
static int CmdFindObj(KernelDriver& kd, DWORD pid, uint64_t classAddr,
                      size_t instSize) {
    g_ptr_hits.clear();
    for (size_t i = 0; i < kDefaultRangeCount; ++i)
        ScanValue(kd, pid, kDefaultRanges[i].start, kDefaultRanges[i].end,
                  classAddr, kDefaultRanges[i].label);
    for (size_t i = 0; i < kDeepRangeCount; ++i)
        ScanValue(kd, pid, kDeepRanges[i].start, kDeepRanges[i].end,
                  classAddr, kDeepRanges[i].label);

    if (instSize == 0) instSize = 0x100;
    printf("\n[=] %zu raw references; validating as instances...\n", g_ptr_hits.size());

    std::vector<uint8_t> buf(instSize);
    size_t good = 0;
    for (uint64_t a : g_ptr_hits) {
        if (!ReadBlock(kd, pid, a, buf.data(), instSize)) continue;
        size_t slots = instSize / 8;
        size_t ptrs = 0, nonzero = 0;
        for (size_t i = 1; i < slots; ++i) {
            uint64_t v;
            memcpy(&v, buf.data() + i * 8, 8);
            if (!v) continue;
            ++nonzero;
            if (v >= kMinUserAddr && v < kMaxUserAddr) ++ptrs;
        }
        // a real object of this class has plenty of live references and data
        if (ptrs < 3 || nonzero < 4) continue;
        ++good;
        printf("  OBJ %016llX  ptrs=%zu/%zu nonzero=%zu\n",
               (unsigned long long)a, ptrs, slots, nonzero);
    }
    printf("[=] %zu plausible objects\n", good);
    return good ? 0 : 1;
}

// ------------------------------------------------------------
// findoffsets <classAddr>
//
// Tencent's build keeps fieldOffsets out of the obvious stock slot, so try
// every pointer in the class record and keep the ones that decode into a
// non-decreasing uint32 array of exactly field_count entries (that is what
// IL2CPP emits: fields are laid out sequentially from the object header).
// ------------------------------------------------------------
static int CmdFindOffsets(KernelDriver& kd, DWORD pid, uint64_t classAddr) {
    uint8_t rec[0x200];
    if (!ReadBlock(kd, pid, classAddr, rec, sizeof(rec))) {
        printf("[!] Read failed at %016llX\n", (unsigned long long)classAddr);
        return 2;
    }

    char nm[64] = {}, ns[64] = {};
    ReadCString(kd, pid, classAddr + 0x10, nm, sizeof(nm));
    ReadCString(kd, pid, classAddr + 0x18, ns, sizeof(ns));
    printf("== class %s.%s @ %016llX ==\n", ns, nm, (unsigned long long)classAddr);

    // Every uint16 in the tail of the record is a candidate count. Pair each
    // one with every pointer slot and keep the combination that decodes into
    // a non-decreasing offset array.
    std::vector<uint64_t> ptrs;
    for (size_t off = 0; off + 8 <= sizeof(rec); off += 8) {
        uint64_t v;
        memcpy(&v, rec + off, 8);
        if (v >= kMinUserAddr && v < kMaxUserAddr) {
            ptrs.push_back(v);
            printf("   slot +0x%02X = %016llX\n", (unsigned)off, (unsigned long long)v);
        }
    }

    std::vector<uint8_t> arr(8192 * 4);
    int found = 0;
    for (size_t off = 0xE8; off + 2 <= sizeof(rec); off += 2) {
        unsigned fcount;
        memcpy(&fcount, rec + off, 2);
        if (fcount < 4 || fcount > 8192) continue;
        if ((size_t)fcount * 4 > arr.size()) continue;

        for (uint64_t p : ptrs) {
            if (!ReadBlock(kd, pid, p, arr.data(), (size_t)fcount * 4)) continue;

            unsigned prev = 0, first = 0;
            bool ok = true;
            for (unsigned k = 0; k < fcount; ++k) {
                unsigned o;
                memcpy(&o, arr.data() + (size_t)k * 4, 4);
                if (k == 0) first = o;
                if (o < prev || o > 0x100000) { ok = false; break; }
                prev = o;
            }
            if (ok && first <= 0x100) {
                printf("[+] HIT count=%u (from class+0x%02X) array=%016llX "
                       "first=0x%X last=0x%X\n",
                       fcount, (unsigned)off, (unsigned long long)p, first, prev);
                ++found;
            }
        }
    }
    printf("[=] %d candidates\n", found);
    return found ? 0 : 1;
}

// ------------------------------------------------------------
// diffscan <start> <end> [batchKB] [delayMs]
//
// Blind differential scan: read a block, wait, read it again, and report
// every 4-byte slot that moved. This finds live gameplay state (world
// position, velocity, timers) without knowing which class owns it, which is
// what we need on a build that hides the field-offset table.
//
// Only values that look like gameplay floats (finite, |v| in range) or small
// ints are reported, otherwise every ticking counter drowns the output.
// ------------------------------------------------------------
static int CmdDiffScan(KernelDriver& kd, DWORD pid, uint64_t start, uint64_t end,
                       size_t batchBytes, int delayMs) {
    if (batchBytes < 0x1000) batchBytes = 0x40000;      // 256 KB
    if (batchBytes > 0x100000) batchBytes = 0x100000;   // 1 MB cap
    if (delayMs < 20) delayMs = 250;

    const UINT32 pagesPerBatch = (UINT32)(batchBytes / kPageSize);
    const size_t span = (size_t)pagesPerBatch * kPageSize;

    std::vector<BatchReadRequest> reqs(pagesPerBatch);
    std::vector<uint8_t> a(span), b(span);

    printf("[*] diffscan %016llX - %016llX  batch=%zuKB delay=%dms\n",
           (unsigned long long)start, (unsigned long long)end,
           batchBytes / 1024, delayMs);
    fflush(stdout);

    uint64_t movedPages = 0, total = 0, hits = 0;
    double t0 = Now();

    for (uint64_t base = start; base < end; base += batchBytes) {
        UINT32 np = 0;
        for (; np < pagesPerBatch && base + np * kPageSize < end; ++np) {
            reqs[np].address          = base + np * kPageSize;
            reqs[np].size             = kPageSize;
            reqs[np].offset_in_buffer = (SIZE_T)np * kPageSize;
        }
        if (!np) break;
        size_t used = (size_t)np * kPageSize;

        kd.BatchRead(pid, reqs.data(), np, a.data(), used);
        Sleep(delayMs);
        kd.BatchRead(pid, reqs.data(), np, b.data(), used);

        bool pageMoved[4096] = {};
        uint32_t pages = (UINT32)(used / kPageSize);

        for (size_t o = 0; o + 4 <= used; o += 4) {
            uint32_t x, y;
            memcpy(&x, a.data() + o, 4);
            memcpy(&y, b.data() + o, 4);
            if (x == y) continue;

            float fx, fy;
            memcpy(&fx, &x, 4);
            memcpy(&fy, &y, 4);

            bool floatish = std::isfinite(fx) && std::isfinite(fy) &&
                            (fabs(fx) < 100000.0f || fabs(fy) < 100000.0f);
            bool smallish = (x < 1000000u) && (y < 1000000u);
            if (!floatish && !smallish) continue;

            size_t pageIdx = o / kPageSize;
            if (pageIdx < pages) pageMoved[pageIdx] = true;

            if (hits < 4000) {
                printf("  CHG %016llX  %10.4f -> %10.4f   (0x%08X -> 0x%08X)\n",
                       (unsigned long long)(base + o), (double)fx, (double)fy, x, y);
            }
            ++hits;
        }

        for (uint32_t p = 0; p < pages; ++p)
            if (pageMoved[p]) ++movedPages;
        total += pages;

        if (((base - start) & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            double mb = (double)(base - start) / 1048576.0;
            printf("   %7.1f MB  movedPages=%llu hits=%llu  %5.1f MB/s\n",
                   mb, (unsigned long long)movedPages, (unsigned long long)hits,
                   el > 0 ? mb / el : 0);
            fflush(stdout);
        }
    }

    printf("[=] done in %.1fs: %llu pages scanned, %llu moved, %llu slot changes\n",
           Now() - t0, (unsigned long long)total,
           (unsigned long long)movedPages, (unsigned long long)hits);
    return 0;
}

// ------------------------------------------------------------
// findpos <start> <end> [minVal] [maxVal]
//
// Hunt for entity position triples. Every pawn in this build keeps its world
// position as a float3 whose Y component is always 0 (top-down world space),
// with X and Z inside the 9167-unit map. That signature is specific enough to
// sweep the whole address space for without needing any class knowledge.
//
// Layouts matched, at 4-byte alignment:
//     [X][0][Z]      [0][X][Z]      [X][Z][0]      [X][0][Z][pad]
//
// ------------------------------------------------------------
static int CmdFindPos(KernelDriver& kd, DWORD pid, uint64_t start, uint64_t end,
                      float minV, float maxV,
                      bool useRef, float refX, float refZ, float maxDist) {
    const uint64_t span = kPageSize + kPageOverlap;
    printf("[*] findpos %016llX - %016llX  range [%.0f, %.0f]",
           (unsigned long long)start, (unsigned long long)end, minV, maxV);
    if (useRef)
        printf("  ref=(%.1f, %.1f) maxDist=%.1f", refX, refZ, maxDist);
    printf("\n");
    fflush(stdout);

    std::vector<BatchReadRequest> reqs(kBatchPages);
    std::vector<uint8_t> buf((size_t)kBatchPages * span);

    uint64_t hits = 0, scanned = 0;
    double  t0 = Now();

    for (uint64_t base = start; base < end; base += (uint64_t)kBatchPages * kPageSize) {
        UINT32 np = 0;
        for (; np < kBatchPages; ++np) {
            uint64_t a = base + (uint64_t)np * kPageSize;
            if (a >= end) break;
            reqs[np].address          = a;
            reqs[np].size             = span;
            reqs[np].offset_in_buffer = (SIZE_T)np * span;
        }
        if (!np) break;

        kd.BatchRead(pid, reqs.data(), np, buf.data(), (size_t)np * span);
        size_t used = (size_t)np * span;

        for (size_t o = 0; o + 12 <= used; o += 4) {
            float a, b, c;
            memcpy(&a, buf.data() + o, 4);
            memcpy(&b, buf.data() + o + 4, 4);
            memcpy(&c, buf.data() + o + 8, 4);

            // Only the strict (X, 0, Z) layout: a genuine world position has
            // a zero height, and the two horizontal components differ.
            // NB: the "zero" components are frequently tiny denormals, not a clean
            // 0.0f (leftovers from a subtraction), so an exact == 0.0f test
            // rejects everything. Use an epsilon.
            const float kZero = 1e-3f;
            if (!(fabsf(a) > 1.0f && fabsf(b) <= kZero && fabsf(c) > 1.0f)) continue;
            if (!(a >= minV && a <= maxV)) continue;
            if (!(c >= minV && c <= maxV)) continue;
            if (fabsf(a - c) < 1.0f) continue;          // reject (r, 0, r)

            if (useRef) {
                float dx = a - refX, dz = c - refZ;
                float dist = sqrtf(dx * dx + dz * dz);
                if (dist > maxDist || dist < 0.5f) continue;
                printf("  POS %016llX  (%9.2f, %9.2f, %9.2f)  dist=%.2f\n",
                       (unsigned long long)(base + o), a, b, c, dist);
            } else {
                printf("  POS %016llX  (%9.2f, %9.2f, %9.2f)\n",
                       (unsigned long long)(base + o), a, b, c);
            }
            fflush(stdout);
            ++hits;
        }

        scanned += (uint64_t)np * kPageSize;
        if (((base - start) & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            double mb = (double)(base - start) / 1048576.0;
            printf("   %8.1f MB  hits=%llu  %6.1f MB/s\n",
                   mb, (unsigned long long)hits, el > 0 ? mb / el : 0);
            fflush(stdout);
        }
    }

    printf("[=] done in %.1fs: %llu candidates\n", Now() - t0, (unsigned long long)hits);
    return 0;
}

// ------------------------------------------------------------
// IL2CPP global-metadata header
// ------------------------------------------------------------
struct MetaHeader {
    uint32_t sanity;
    int32_t  version;
};

// Parse the fixed (offset,count) table pairs that start at byte 8 of the header.
struct TablePair { uint32_t offset; uint32_t count; };

static std::vector<TablePair> ReadTablePairs(const uint8_t* hdr, size_t hdrLen) {
    std::vector<TablePair> tables;
    size_t words = hdrLen / 4;
    for (size_t i = 2; i + 1 < words; i += 2)
        tables.push_back({ *(const uint32_t*)(hdr + i * 4),
                           *(const uint32_t*)(hdr + (i + 1) * 4) });
    return tables;
}

// Rough blob size from the header tables (assumes <=4 bytes per element,
// which under-estimates wide structs; the growing dump below fixes that).
static uint64_t EstimateMetaSize(const uint8_t* hdr, size_t hdrLen) {
    uint64_t end = 0;
    for (const auto& t : ReadTablePairs(hdr, hdrLen)) {
        if (t.offset > 0x400 && t.offset < 0x40000000ull && t.count < 0x40000000u)
            end = std::max<uint64_t>(end, (uint64_t)t.offset + (uint64_t)t.count * 4ull);
    }
    return end ? end + 0x1000 : 0x4000;
}

// Dump the metadata blob starting at `addr`, growing page by page until we
// hit K consecutive unreadable pages (i.e. the end of the mapping).
static bool DumpMetadataBlob(KernelDriver& kd, DWORD pid, uint64_t addr,
                             const std::string& path) {
    std::vector<uint8_t> head(0x400);
    if (!ReadBlock(kd, pid, addr, head.data(), head.size())) {
        printf("[!] Cannot read metadata header at %016llX\n", (unsigned long long)addr);
        return false;
    }

    MetaHeader mh = {};
    memcpy(&mh, head.data(), sizeof(mh));

    uint64_t want = EstimateMetaSize(head.data(), head.size());
    const uint64_t kMaxBlob = 128ull * 1024 * 1024;

    std::vector<uint8_t> blob;
    blob.reserve((size_t)std::min<uint64_t>(want + (4ull << 20), kMaxBlob));

    const int kMaxMisses = 2;
    int misses = 0;
    uint64_t off = 0;

    std::vector<uint8_t> page(kPageSize);

    while (off < kMaxBlob) {
        if (!kd.Read(pid, addr + off, page.data(), (SIZE_T)kPageSize)) {
            if (++misses >= kMaxMisses) break;
            blob.insert(blob.end(), kPageSize, 0);
            off += kPageSize;
            continue;
        }
        // trailing zero page usually means padding / end of section
        bool allZero = true;
        for (size_t i = 0; i < kPageSize; ++i) {
            if (page[i]) { allZero = false; break; }
        }
        if (allZero && off > want) break;

        blob.insert(blob.end(), page.begin(), page.end());
        misses = 0;
        off += kPageSize;
    }

    if (blob.empty()) return false;

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        printf("[!] Cannot open %s for writing\n", path.c_str());
        return false;
    }
    fwrite(blob.data(), 1, blob.size(), f);
    fclose(f);

    printf("[+] Dumped metadata v%d (%llu tables) -> %s  (%zu bytes)\n",
           mh.version,
           (unsigned long long)ReadTablePairs(head.data(), head.size()).size(),
           path.c_str(), blob.size());
    return true;
}

// ------------------------------------------------------------
// Commands
// ------------------------------------------------------------
static DWORD FindTargetPid(KernelDriver& kd) {
    static const wchar_t* kNames[] = {
        L"CODMGameApps.exe", L"CODM.exe", L"CODMLauncher.exe",
        L"CODMGame.exe", L"GameAssembly.exe", L"UnityPlayer.exe"
    };
    for (const wchar_t* n : kNames) {
        DWORD pid = kd.GetPID(n);
        if (pid) {
            printf("[+] Target process: %ls (PID %u)\n", n, pid);
            return pid;
        }
    }
    return 0;
}

static int CmdModules(KernelDriver& kd, DWORD pid) {
    std::vector<MODULE_PACK_KM> mods;
    if (!kd.EnumModules(pid, &mods)) {
        printf("[!] EnumModules failed\n");
        return 2;
    }

    printf("\n%-34s %-18s %-12s\n", "MODULE", "BASE", "SIZE");
    printf("%-34s %-18s %-12s\n", "----------------------------------",
           "------------------", "------------");
    for (auto& m : mods)
        printf("%-34ws %016llX   %8.2f KB\n", m.moduleName,
               (unsigned long long)m.baseAddress, m.size / 1024.0);
    printf("\n[+] %zu modules\n", mods.size());
    return 0;
}

static int CmdScan(KernelDriver& kd, DWORD pid, bool deep,
                   const std::vector<Range>& extra) {
    std::vector<MODULE_PACK_KM> mods;
    if (kd.EnumModules(pid, &mods)) {
        for (const auto& m : mods) {
            if (m.size && m.size < 512ull * 1024 * 1024)
                ScanModule(kd, pid, m);
        }
    } else {
        printf("[!] EnumModules failed, falling back to range scan only\n");
    }

    for (size_t i = 0; i < kDefaultRangeCount; ++i)
        ScanRange(kd, pid, kDefaultRanges[i].start, kDefaultRanges[i].end,
                  kDefaultRanges[i].label);

    for (const auto& r : extra)
        ScanRange(kd, pid, r.start, r.end, "custom");

    if (deep) {
        for (size_t i = 0; i < kDeepRangeCount; ++i)
            ScanRange(kd, pid, kDeepRanges[i].start, kDeepRanges[i].end,
                      kDeepRanges[i].label);
    }

    printf("[=] Total hits: %zu\n", g_hits.size());
    for (const auto& h : g_hits)
        printf("    %016llX  %s\n", (unsigned long long)h.address, h.kind);
    return 0;
}

static int CmdDump(KernelDriver& kd, DWORD pid, uint64_t addr, uint64_t size,
                   const std::string& path) {
    std::vector<uint8_t> buf((size_t)size);
    if (!ReadBlock(kd, pid, addr, buf.data(), (size_t)size)) {
        printf("[!] Read failed at %016llX\n", (unsigned long long)addr);
        return 2;
    }
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { printf("[!] Cannot write %s\n", path.c_str()); return 2; }
    fwrite(buf.data(), 1, buf.size(), f);
    fclose(f);
    printf("[+] Dumped %llu bytes @ %016llX -> %s\n",
           (unsigned long long)size, (unsigned long long)addr, path.c_str());
    return 0;
}

static int CmdRead(KernelDriver& kd, DWORD pid, uint64_t addr, uint64_t size) {
    uint8_t buf[512];
    if (size > sizeof(buf)) size = sizeof(buf);
    if (!ReadBlock(kd, pid, addr, buf, (size_t)size)) {
        printf("[!] Read failed at %016llX\n", (unsigned long long)addr);
        return 2;
    }
    printf("read %llu bytes @ %016llX:\n", (unsigned long long)size,
           (unsigned long long)addr);
    for (size_t i = 0; i < size; i += 16) {
        printf("%08llX  ", (unsigned long long)(addr + i));
        for (size_t j = 0; j < 16 && i + j < size; ++j)
            printf("%02X ", buf[i + j]);
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; ++j) {
            uint8_t c = buf[i + j];
            putchar((c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
    return 0;
}

static int CmdPe(KernelDriver& kd, DWORD pid, const wchar_t* mod, const std::string& path) {
    UINT64 base = 0;
    SIZE_T size = 0;
    if (!kd.GetModuleInfo(pid, mod, &base, &size)) {
        printf("[!] Module not found: %ls\n", mod);
        return 2;
    }
    return CmdDump(kd, pid, base, size, path);
}

// Full pipeline: modules -> scan -> dump every metadata blob found
static int CmdMeta(KernelDriver& kd, DWORD pid, bool deep) {
    std::string dir = "out";
    CreateDirectoryA(dir.c_str(), nullptr);

    std::vector<MODULE_PACK_KM> mods;
    if (kd.EnumModules(pid, &mods)) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s/modules.txt", dir.c_str());
        FILE* f = fopen(buf, "w");
        if (f) {
            for (auto& m : mods)
                fprintf(f, "%016llX\t%llu\t%ls\n",
                        (unsigned long long)m.baseAddress,
                        (unsigned long long)m.size, m.moduleName);
            fclose(f);
            printf("[+] Module list -> %s\n", buf);
        }
        for (const auto& m : mods) {
            if (m.size && m.size < 512ull * 1024 * 1024)
                ScanModule(kd, pid, m);
        }
    }

    for (size_t i = 0; i < kDefaultRangeCount; ++i)
        ScanRange(kd, pid, kDefaultRanges[i].start, kDefaultRanges[i].end,
                  kDefaultRanges[i].label);

    if (deep) {
        for (size_t i = 0; i < kDeepRangeCount; ++i)
            ScanRange(kd, pid, kDeepRanges[i].start, kDeepRanges[i].end,
                      kDeepRanges[i].label);
    }

    printf("\n[=] %zu hits total\n", g_hits.size());
    int dumped = 0;
    for (const auto& h : g_hits) {
        if (strcmp(h.kind, "il2cpp-global-metadata") != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/metadata_%u_%016llX.bin",
                 dir.c_str(), pid, (unsigned long long)h.address);
        if (DumpMetadataBlob(kd, pid, h.address, path))
            ++dumped;
    }

    // Report interesting module names for the ESP work
    if (kd.EnumModules(pid, &mods)) {
        static const char* kInteresting[] = {
            "GameAssembly", "UnityPlayer", "il2cpp", "Ace", "ACE", "tvm",
            "anticheat", "TP2", "tersafe", "codm", "CODM"
        };
        printf("\n[=] Interesting modules:\n");
        for (const auto& m : mods) {
            std::string n;
            for (const wchar_t* p = m.moduleName; *p; ++p) n.push_back((char)*p);
            std::string low = n;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            for (const char* key : kInteresting) {
                if (low.find(key) != std::string::npos) {
                    printf("    %-40ws %016llX %8.2f KB\n", m.moduleName,
                           (unsigned long long)m.baseAddress, m.size / 1024.0);
                    break;
                }
            }
        }
    }

    printf("\n[=] metadata blobs dumped: %d\n", dumped);
    return dumped ? 0 : 1;
}

// ------------------------------------------------------------
// Self test: plant a synthetic IL2CPP metadata header in our own
// address space, then run the real scan/dump path against it. This
// validates driver IOCTLs, module enumeration, page scanning and the
// blob dumper without needing the game running.
//
//   scanner.exe selftest
// ------------------------------------------------------------
static int CmdSelfTest(KernelDriver& kd, DWORD pid) {
    const size_t kSize = 0x20000;                 // 128 KB "blob"
    uint8_t* blob = (uint8_t*)VirtualAlloc(nullptr, kSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!blob) { printf("[!] VirtualAlloc failed\n"); return 2; }

    memset(blob, 0xCC, kSize);                     // poison
    const uint32_t sanity = 0xFAB11BAF;
    const int32_t  version = 29;
    memcpy(blob, &sanity, 4);
    memcpy(blob + 4, &version, 4);
    // one populated table so the parser has something to chew on
    uint32_t strOff = 0x100, strCount = 16;
    memcpy(blob + 8, &strOff, 4);
    memcpy(blob + 12, &strCount, 4);
    const char* s = "SELFTEST_STRING";
    memcpy(blob + strOff, s, strlen(s) + 1);
    // filler tail (zeros) so the dumper terminates the blob
    memset(blob + 0x1000, 0, kSize - 0x1000);

    uint64_t addr = (uint64_t)blob;
    printf("[+] Planted synthetic metadata at %016llX (%zu bytes)\n",
           (unsigned long long)addr, kSize);

    // 1) module enumeration must work
    std::vector<MODULE_PACK_KM> mods;
    if (kd.EnumModules(pid, &mods))
        printf("[+] EnumModules OK: %zu modules\n", mods.size());
    else
        printf("[!] EnumModules FAILED\n");

    // 2) single read back
    uint32_t check = 0;
    if (kd.Read(pid, addr, &check, 4) && check == sanity)
        printf("[+] Read OK (sanity 0x%08X)\n", check);
    else
        printf("[!] Read FAILED\n");

    // 3) batch read path
    BatchReadRequest br = {};
    uint8_t page[0x1010] = {};
    br.address = addr; br.size = sizeof(page); br.offset_in_buffer = 0;
    if (kd.BatchRead(pid, &br, 1, page, sizeof(page)) && page[0] == 0xAF)
        printf("[+] BatchRead OK (first byte 0x%02X)\n", page[0]);
    else
        printf("[!] BatchRead FAILED (first byte 0x%02X)\n", page[0]);

    // 4) magic scan over a window that definitely covers the planted blob
    //    (VirtualAlloc under ASLR can land anywhere in the 128 TB range,
    //     so scan around the actual address rather than a fixed window)
    uint64_t winStart = (addr & ~0xFFFFull) - 0x100000ull;
    uint64_t winEnd   = winStart + 0x200000ull;
    printf("[*] Scanning around the blob for the magic ...\n");
    ScanRange(kd, pid, winStart, winEnd, "selftest");

    // 5) dump the blob through the normal dumper
    CreateDirectoryA("out", nullptr);
    if (DumpMetadataBlob(kd, pid, addr, "out/selftest_meta.bin"))
        printf("[+] selftest blob -> out/selftest_meta.bin\n");

    VirtualFree(blob, 0, MEM_RELEASE);

    printf("\n[=] hits: %zu\n", g_hits.size());
    return g_hits.size() ? 0 : 1;
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) {
        printf("CODM IL2CPP scanner\n");
        printf("  scanner modules\n");
        printf("  scanner scan   [--deep] [--range START:END]\n");
        printf("  scanner meta   [--deep]\n");
        printf("  scanner dump   <addr> <size> <file>\n");
        printf("  scanner read   <addr> <size>\n");
        printf("  scanner pe     <moduleName> <file>\n");
        printf("  scanner selftest           validate the whole chain on this process\n");
        printf("  scanner findptr <hexValue> scan for 8-byte pointers to a value\n");
        printf("  scanner findstr <text>      scan for ASCII copies of a string\n");
        printf("  scanner probe <addr> [n]   dump n bytes as qwords, render strings\n");
        printf("  scanner findclass <name>   name string -> referrers -> structure probe\n");
        printf("  common: --pid <n>   --self   --deep   --range START:END\n");
        return 1;
    }

    KernelDriver kd;
    if (!kd.Connect()) {
        printf("[!] Cannot open \\\\.\\laithdriver (is km.sys mapped?)\n");
        return 2;
    }
    printf("[+] Driver connected: %ls\n", kd.activePath);

    // Option parsing happens before target resolution so that --pid/--self
    // can override the default CODM process lookup.
    std::string cmd = argv[1];
    bool   deep = false;
    bool   self = false;
    DWORD  forcedPid = 0;
    std::vector<Range> extra;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--deep") {
            deep = true;
        } else if (a == "--self") {
            self = true;
        } else if (a == "--pid" && i + 1 < argc) {
            forcedPid = (DWORD)strtoul(argv[++i], nullptr, 0);
        } else if (a == "--range" && i + 1 < argc) {
            unsigned long long s = 0, e = 0;
            if (sscanf(argv[++i], "%llx:%llx", &s, &e) == 2) {
                extra.push_back({ s, e, "custom" });
            } else {
                printf("[!] bad --range (use hexstart:hexend)\n");
            }
        }
    }

    DWORD pid;
    if (self) {
        pid = GetCurrentProcessId();
        printf("[+] Target process: self (PID %u)\n", pid);
    } else if (forcedPid) {
        pid = forcedPid;
        printf("[+] Target process: forced PID %u\n", pid);
    } else {
        pid = FindTargetPid(kd);
        if (!pid) {
            if (cmd == "selftest") {
                pid = GetCurrentProcessId();
                printf("[+] CODM not running; selftest targets self (PID %u)\n", pid);
            } else {
                printf("[!] CODM process not found. Launch the game first.\n");
                printf("    (use --pid <n> or --self to target another process)\n");
                return 3;
            }
        }
    }
    kd.Attach(pid);

    int rc = 0;
    if (cmd == "modules") {
        rc = CmdModules(kd, pid);
    } else if (cmd == "scan") {
        rc = CmdScan(kd, pid, deep, extra);
    } else if (cmd == "meta") {
        rc = CmdMeta(kd, pid, deep);
    } else if (cmd == "dump" && argc >= 5) {
        rc = CmdDump(kd, pid, strtoull(argv[2], nullptr, 16),
                     strtoull(argv[3], nullptr, 0), argv[4]);
    } else if (cmd == "read" && argc >= 4) {
        rc = CmdRead(kd, pid, strtoull(argv[2], nullptr, 16),
                     strtoull(argv[3], nullptr, 0));
    } else if (cmd == "pe" && argc >= 4) {
        wchar_t wmod[260];
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, wmod, 260);
        rc = CmdPe(kd, pid, wmod, argv[3]);
    } else if (cmd == "selftest") {
        rc = CmdSelfTest(kd, pid);
    } else if (cmd == "findptr" && argc >= 3) {
        uint64_t target = strtoull(argv[2], nullptr, 16);
        std::vector<Range> deepRanges;
        if (deep) {
            for (size_t i = 0; i < kDeepRangeCount; ++i)
                deepRanges.push_back(kDeepRanges[i]);
        }
        for (const auto& r : deepRanges) extra.push_back(r);
        rc = CmdFindPtr(kd, pid, target, extra);
    } else if (cmd == "probeobj" && argc >= 3) {
        uint64_t a = strtoull(argv[2], nullptr, 16);
        uint64_t n = argc >= 4 ? strtoull(argv[3], nullptr, 0) : 0x1000;
        rc = CmdProbeObj(kd, pid, a, (size_t)n);
    } else if (cmd == "findobj" && argc >= 3) {
        uint64_t a = strtoull(argv[2], nullptr, 16);
        uint64_t n = argc >= 4 ? strtoull(argv[3], nullptr, 0) : 0x100;
        rc = CmdFindObj(kd, pid, a, (size_t)n);
    } else if (cmd == "findpos" && argc >= 3) {
        uint64_t s = strtoull(argv[2], nullptr, 16);
        uint64_t e = strtoull(argv[3], nullptr, 16);
        float    lo = 20.0f, hi = 9300.0f;
        bool     useRef = false;
        float    refX = 0, refZ = 0, maxDist = 100.0f;

        for (int i = 4; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--px" && i + 1 < argc)      { refX = (float)atof(argv[++i]); useRef = true; }
            else if (a == "--pz" && i + 1 < argc) { refZ = (float)atof(argv[++i]); useRef = true; }
            else if (a == "--maxdist" && i + 1 < argc) { maxDist = (float)atof(argv[++i]); }
            else if (a.size() > 1 && a[0] == '-' && a[1] == '-') {
                // some other option - not a number
            } else if (a.size() && (isdigit((unsigned char)a[0]) || a[0] == '.')) {
                float v = (float)atof(argv[i]);
                if (v >= 100.0f) hi = v; else lo = v;
            }
        }
        rc = CmdFindPos(kd, pid, s, e, lo, hi, useRef, refX, refZ, maxDist);
    } else if (cmd == "diffscan" && argc >= 3) {
        uint64_t s = strtoull(argv[2], nullptr, 16);
        uint64_t e = strtoull(argv[3], nullptr, 16);
        size_t    b = argc >= 4 ? (size_t)strtoull(argv[4], nullptr, 0) : 0x40000;
        int       d = argc >= 5 ? atoi(argv[5]) : 250;
        rc = CmdDiffScan(kd, pid, s, e, b, d);
    } else if (cmd == "findoffsets" && argc >= 3) {
        rc = CmdFindOffsets(kd, pid, strtoull(argv[2], nullptr, 16));
    } else if (cmd == "findclass" && argc >= 3) {
        rc = CmdFindClass(kd, pid, argv[2], extra);
    } else if (cmd == "findstr" && argc >= 3) {
        rc = CmdFindStr(kd, pid, argv[2], extra);
    } else if (cmd == "probe" && argc >= 3) {
        uint64_t a = strtoull(argv[2], nullptr, 16);
        uint64_t n = argc >= 4 ? strtoull(argv[3], nullptr, 0) : 0x100;
        rc = CmdProbe(kd, pid, a, (size_t)n);
    } else {
        printf("[!] unknown command '%s'\n", cmd.c_str());
        rc = 1;
    }

    kd.Disconnect();
    return rc;
}