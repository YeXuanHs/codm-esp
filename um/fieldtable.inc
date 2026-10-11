// ------------------------------------------------------------
// fieldtable <classAddr> <strtabStart> <strtabSize>
//
// Locate a class's field-info table at runtime and dump it. A record is 32
// bytes: { Il2CppClass*, uint32 id, uint64 pad, const char* name, uint64 pad }.
// We only need to confirm (a) the class pointer and (b) that the name pointer
// lands inside the metadata string table, which is a very tight filter.
//
// This makes the whole "class -> field offsets -> instance" chain re-derivable
// after every match change instead of relying on addresses observed once.
//
//   scanner fieldtable 0x2E643028 0x2A08B004 9758944
// ------------------------------------------------------------
static int CmdFieldTable(KernelDriver& kd, DWORD pid, uint64_t classAddr,
                         uint64_t strtab, uint64_t strsz) {
    const uint64_t span = kPageSize + kPageOverlap;
    printf("[*] fieldtable class=0x%llX strtab=0x%llX..0x%llX\n",
           (unsigned long long)classAddr, (unsigned long long)strtab,
           (unsigned long long)(strtab + strsz));
    fflush(stdout);

    std::vector<BatchReadRequest> reqs(kBatchPages);
    std::vector<uint8_t> buf((size_t)kBatchPages * span);

    UINT64 runs = 0, bestLen = 0, bestStart = 0;
    double t0 = Now();

    for (uint64_t base = 0x10000000ull; base < 0x44000000ull;
         base += (uint64_t)kBatchPages * kPageSize) {
        UINT32 np = 0;
        for (; np < kBatchPages; ++np) {
            uint64_t a = base + (uint64_t)np * kPageSize;
            reqs[np].address          = a;
            reqs[np].size             = span;
            reqs[np].offset_in_buffer = (SIZE_T)np * span;
        }
        size_t used = (size_t)np * span;
        kd.BatchRead(pid, reqs.data(), np, buf.data(), used);

        UINT64 run = 0, runStart = 0;
        for (size_t o = 0; o + 32 <= used; o += 32) {
            UINT64 cls, nptr;
            memcpy(&cls, buf.data() + o, 8);
            memcpy(&nptr, buf.data() + o + 16, 8);
            bool ok = (cls == classAddr) && nptr >= strtab && nptr < strtab + strsz;
            if (ok) {
                if (!run) runStart = base + o;
                ++run;
            } else {
                if (run >= 16) {
                    printf("  TABLE %llu records @ 0x%llX\n",
                           (unsigned long long)run, (unsigned long long)runStart);
                    if (run > bestLen) { bestLen = run; bestStart = runStart; }
                    ++runs;
                    fflush(stdout);
                }
                run = 0;
            }
        }
        if (((base - 0x10000000ull) & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            printf("   scanned %6.1f MB  runs=%llu best=%llu  %5.1f MB/s\n",
                   (double)(base - 0x10000000ull) / 1048576.0,
                   (unsigned long long)runs, (unsigned long long)bestLen,
                   el > 0 ? ((double)(base - 0x10000000ull) / 1048576.0) / el : 0);
            fflush(stdout);
        }
    }

    if (!bestLen) { printf("[=] 未找到字段表\n"); return 1; }

    // dump the best run
    printf("[+] 最佳: %llu 条 @ 0x%llX\n",
           (unsigned long long)bestLen, (unsigned long long)bestStart);
    std::vector<uint8_t> body((size_t)bestLen * 32);
    if (ReadBlock(kd, pid, bestStart, body.data(), body.size())) {
        FILE* f = fopen("fieldtable.bin", "wb");
        if (f) { fwrite(body.data(), 1, body.size(), f); fclose(f); }
        printf("[+] 已保存 fieldtable.bin (%zu 字节)\n", body.size());
    }
    return 0;
}
