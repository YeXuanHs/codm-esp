// ============================================================
// um/test_read.cpp — basic read test against CODMGameApps.exe
// Compile: cl /EHsc /std:c++17 test_read.cpp /link
// Usage:   test_read.exe [process_name]
// ============================================================

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include "client.h"

int wmain(int argc, wchar_t* argv[]) {
    const wchar_t* target = (argc > 1) ? argv[1] : L"CODMGameApps.exe";

    printf("=== CODM ESP — Read Test ===\n\n");

    KernelDriver drv;
    if (!drv.Connect()) {
        printf("[!] Failed to open device: %s\n", DEVICE_PATH);
        printf("    Is the driver loaded? (check kdmapper output)\n");
        return 1;
    }
    printf("[+] Connected to driver: %s\n", DEVICE_PATH);

    // Step 1: Get PID
    printf("\n[*] Looking for process: %ls\n", target);
    DWORD pid = drv.GetPID(target);
    if (!pid) {
        printf("[-] Process not found.\n");
        return 1;
    }
    printf("[+] PID: %lu\n", pid);

    // Step 2: Attach
    if (!drv.Attach(pid)) {
        printf("[-] Attach failed.\n");
        return 1;
    }
    printf("[+] Attached to process.\n");

    // Step 3: Get module base (try main executable and Unity DLLs)
    struct { const wchar_t* name; } modules[] = {
        { L"CODMGameApps.exe" },
        { L"GameAssembly.dll" },
        { L"UnityPlayer.dll" },
        { L"ntdll.dll" },
        { L"kernel32.dll" },
    };

    for (auto& mod : modules) {
        UINT64 base = drv.GetModuleBase(pid, mod.name);
        if (base) {
            printf("[+] %-20ls  base = 0x%llX\n", mod.name, base);
        } else {
            printf("    %-20ls  not found\n", mod.name);
        }
    }

    // Step 4: Read MZ header from main module
    UINT64 mainBase = drv.GetModuleBase(pid, L"CODMGameApps.exe");
    if (!mainBase) {
        printf("[-] Could not get main module base.\n");
        return 1;
    }

    printf("\n[*] Reading MZ header from CODMGameApps.exe @ 0x%llX\n", mainBase);
    BYTE header[0x200] = {};
    if (drv.Read(pid, mainBase, header, sizeof(header))) {
        printf("[+] Read %zu bytes.\n", sizeof(header));
        printf("    MZ signature: %02X %02X (expect 4D 5A)\n", header[0], header[1]);

        if (header[0] == 0x4D && header[1] == 0x5A) {
            DWORD pe_offset = *(DWORD*)(header + 0x3C);
            printf("    PE offset: 0x%X\n", pe_offset);

            if (pe_offset + 4 < sizeof(header)) {
                DWORD pe_sig = *(DWORD*)(header + pe_offset);
                printf("    PE signature: %08X (expect 00004550 = PE\\0\\0)\n", pe_sig);
            }
        }
    } else {
        printf("[-] Read failed.\n");
    }

    // Step 5: Test batch read
    printf("\n[*] Testing batch read (3 reads)...\n");
    BatchReadRequest batch_reqs[3] = {};
    batch_reqs[0] = { mainBase, 0x100, 0 };
    batch_reqs[1] = { mainBase + 0x100, 0x100, 0x100 };
    batch_reqs[2] = { mainBase + 0x400, 0x100, 0x200 };

    BYTE batch_out[0x300] = {};
    if (drv.BatchRead(pid, batch_reqs, 3, batch_out, sizeof(batch_out))) {
        printf("[+] Batch read OK.\n");
        printf("    First 16 bytes of chunk 1: ");
        for (int i = 0; i < 16; i++) printf("%02X ", batch_out[i]);
        printf("\n");
    } else {
        printf("[-] Batch read failed.\n");
    }

    printf("\n[+] All tests complete.\n");
    return 0;
}
