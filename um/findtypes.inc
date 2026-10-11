// findtypes: locate the IL2CPP `types` array at runtime.
//
// Every entry of that array is an Il2CppType*. For class types the first
// qword of an Il2CppType points at the Il2CppClass, whose +0x10 / +0x18 are
// the name / namespace strings. So a slot qualifies when its value is a
// readable pointer and both [value+0x10] and [value+0x18] read back as
// printable ASCII. The genuine types array shows up as a very long run of
// consecutive qualifying slots.
//
//   scanner findtypes <start> <end> [minRun]
static bool ProbeStr(KernelDriver& kd, DWORD pid, uint64_t a, char* out, size_t outSz) {
    uint8_t t[24] = {};
    if (!kd.Read(pid, a, t, 24)) return false;
    size_t n = 0;
    for (; n < 24 && t[n]; ++n) {
        if (t[n] < 0x20 || t[n] > 0x7E) return false;
        out[n] = (char)t[n];
    }
    if (n < 2 || n >= outSz) return false;
    out[n] = 0;
    return true;
}

static int CmdFindTypes(KernelDriver& kd, DWORD pid, uint64_t start, uint64_t end,
                        UINT32 minRun) {
    const uint64_t span = kPageSize + kPageOverlap;
    printf("[*] findtypes %016llX - %016llX  minRun=%u\n",
           (unsigned long long)start, (unsigned long long)end, minRun);
    fflush(stdout);

    std::vector<BatchReadRequest> reqs(kBatchPages);
    std::vector<uint8_t> buf((size_t)kBatchPages * span);

    UINT64 bestRun = 0;
    double t0 = Now();

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
        size_t used = (size_t)np * span;
        kd.BatchRead(pid, reqs.data(), np, buf.data(), used);

        UINT64 run = 0, runStart = 0;
        for (size_t o = 0; o + 8 <= used; o += 8) {
            UINT64 v;
            memcpy(&v, buf.data() + o, 8);
            bool ok = false;
            if (v >= 0x10000 && v < 0x7FFFFFFF00000000ull) {
                char nm[40], ns[40];
                ok = ProbeStr(kd, pid, v + 0x10, nm, sizeof(nm)) &&
                     ProbeStr(kd, pid, v + 0x18, ns, sizeof(ns));
            }
            if (ok) {
                if (run == 0) runStart = base + o;
                ++run;
            } else {
                if (run >= minRun) {
                    printf("  RUN %llu entries @ 0x%llX\n",
                           (unsigned long long)run, (unsigned long long)runStart);
                    for (UINT64 i = 0; i < run && i < 10; ++i) {
                        UINT64 v2;
                        kd.Read(pid, runStart + i * 8, &v2, 8);
                        char nm[40] = {}, ns[40] = {};
                        ProbeStr(kd, pid, v2 + 0x10, nm, sizeof(nm));
                        ProbeStr(kd, pid, v2 + 0x18, ns, sizeof(ns));
                        printf("       [%llu] type=0x%llX  %s.%s\n",
                               (unsigned long long)i, (unsigned long long)v2, ns, nm);
                    }
                    fflush(stdout);
                }
                if (run > bestRun) bestRun = run;
                run = 0;
            }
        }

        if (((base - start) & 0x3FFF000ull) == 0) {
            double el = Now() - t0;
            double mb = (double)(base - start) / 1048576.0;
            printf("   %8.1f MB  bestRun=%llu  %6.1f MB/s\n",
                   mb, (unsigned long long)bestRun, el > 0 ? mb / el : 0);
            fflush(stdout);
        }
    }

    printf("[=] done. 最长连续命中 = %llu\n", (unsigned long long)bestRun);
    return 0;
}