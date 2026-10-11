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
            printf("[+] Target process: %s (PID %u)\n", n, pid);
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
        return 1;
    }

    KernelDriver kd;
    if (!kd.Connect()) {
        printf("[!] Cannot open \\\\.\\laithdriver (is km.sys mapped?)\n");
        return 2;
    }
    printf("[+] Driver connected\n");

    DWORD pid = FindTargetPid(kd);
    if (!pid) {
        printf("[!] CODM process not found. Launch the game first.\n");
        return 3;
    }
    kd.Attach(pid);

    std::string cmd = argv[1];
    bool deep = false;
    std::vector<Range> extra;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--deep") {
            deep = true;
        } else if (a == "--range" && i + 1 < argc) {
            unsigned long long s = 0, e = 0;
            if (sscanf(argv[++i], "%llx:%llx", &s, &e) == 2) {
                extra.push_back({ s, e, "custom" });
            } else {
                printf("[!] bad --range (use hexstart:hexend)\n");
            }
        }
    }

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
    } else {
        printf("[!] unknown command '%s'\n", cmd.c_str());
        rc = 1;
    }

    kd.Disconnect();
    return rc;
}