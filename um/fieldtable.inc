// ------------------------------------------------------------
// fieldtable <classAddr> <strtabStart> <strtabSize>
//
// Locate a class's field-info table at runtime. A record is 32 bytes:
//     +0x00 Il2CppClass*
//     +0x08 uint32 id
//     +0x10 const char* name   (points into the metadata string table)
//     +0x18 native pointer
//
// This build does NOT lay the table out contiguously, so we collect every
// record whose first qword equals the class and then cluster them by address
// proximity. Continuity is judged by the class pointer alone: a handful of
// records carry a name pointer outside the string table, and using that as a
// break condition chops the table into fragments.
//
//   scanner fieldtable 0x2E643028 0x2A095004 9758944
// ------------------------------------------------------------
static int CmdFieldTable(KernelDriver& kd, DWORD pid, uint64_t classAddr,
                         uint64_t strtab, uint64_t strsz) {
    (void)strtab; (void)strsz;
    const uint64_t span = kPageSize + kPageOverlap;
    printf("[*] fieldtable class=0x%llX\n", (unsigned long long)classAddr);
    fflush(stdout);

    std::vector<BatchReadRequest> reqs(kBatchPages);
    std::vector<uint8_t> buf((size_t)kBatchPages * span);
    std::vector<uint64_t> hits;
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

        for (size_t o = 0; o + 32 <= used; o += 32) {
            UINT64 cls;
            memcpy(&cls, buf.data() + o, 8);
            if (cls == classAddr) hits.push_back(base + o);
        }

        if (((base - 0x10000000ull) & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            double mb = (double)(base - 0x10000000ull) / 1048576.0;
            printf("   %7.1f MB  hits=%zu  %5.1f MB/s\n", mb, hits.size(),
                   el > 0 ? mb / el : 0);
            fflush(stdout);
        }
    }

    if (hits.empty()) { printf("[=] no records matched\n"); return 1; }
    printf("[+] %zu records matched the class pointer\n", hits.size());

    const UINT64 GAP = 0x20000;
    size_t bestLen = 0, bestI = 0;
    for (size_t i = 0; i < hits.size(); ) {
        size_t j = i + 1;
        while (j < hits.size() && hits[j] - hits[j - 1] < GAP) ++j;
        printf("   cluster %zu  0x%llX..0x%llX\n", j - i,
               (unsigned long long)hits[i], (unsigned long long)hits[j - 1]);
        if (j - i > bestLen) { bestLen = j - i; bestI = i; }
        i = j;
    }

    uint64_t lo = hits[bestI], hi = hits[bestI + bestLen - 1];
    size_t body_size = (size_t)(hi - lo) + 32;
    printf("[+] best cluster: %zu records, 0x%llX..0x%llX\n", bestLen,
           (unsigned long long)lo, (unsigned long long)hi);

    std::vector<uint8_t> body(body_size);
    if (!ReadBlock(kd, pid, lo, body.data(), body_size)) {
        printf("[!] read of cluster span failed\n"); return 1;
    }
    FILE* f = fopen("fieldtable.bin", "wb");
    if (!f) { printf("[!] cannot write fieldtable.bin\n"); return 1; }
    fwrite(body.data(), 1, body.size(), f);
    fclose(f);
    printf("[+] saved fieldtable.bin (%zu bytes)\n", body_size);
    return 0;
}
