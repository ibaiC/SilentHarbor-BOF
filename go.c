#include <windows.h>
#include "beacon.h"
#include "syscalls.c"
#include "bofdefs.h"

#define STATUS_SUCCESS                   0x00000000L
#define STATUS_INFO_LENGTH_MISMATCH      0xC0000004L

#include <stdbool.h>

// SYSCALLS USED:
// Sw3NtAllocateVirtualMemory
// Sw3NtFreeVirtualMemory
// Sw3NtQueryVirtualMemory
// Sw3NtOpenProcessToken
// Sw3NtQueryInformationToken
// Sw3NtOpenProcess
// Sw3NtClose

// Helpers
void* MyAlloc(SIZE_T size) {
    PVOID baseAddress = NULL;
    SIZE_T regionSize = size;
    
    NTSTATUS status = Sw3NtAllocateVirtualMemory(
        KERNEL32$GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (status < 0 || baseAddress == NULL) {
        return NULL;
    }
    
    return baseAddress;
}

void MyFree(void* ptr) {
    if (ptr) {
        PVOID baseAddress = ptr;
        SIZE_T regionSize = 0;
        
        NTSTATUS status = Sw3NtFreeVirtualMemory(
            KERNEL32$GetCurrentProcess(),
            &baseAddress,
            &regionSize,
            MEM_RELEASE
        );
    }
}

SIZE_T my_strlen(const char* str) {
    SIZE_T len = 0;
    while (str && str[len]) len++;
    return len;
}

void my_strcat(char* dest, const char* src) {
    SIZE_T dlen = my_strlen(dest);
    SIZE_T i = 0;
    while (src && src[i]) {
        dest[dlen + i] = src[i];
        i++;
    }
    dest[dlen + i] = '\0';
}

void my_strcpy(char* dest, const char* src) {
    while (src && *src) {
        *dest++ = *src++;
    }
    *dest = '\0';
}

WCHAR* my_alloc_wide(const char* str) {
    SIZE_T len = my_strlen(str);
    SIZE_T size = (len + 1) * sizeof(WCHAR);
    WCHAR* wstr = (WCHAR*)MyAlloc(size);
    if (!wstr) return NULL;
    for (SIZE_T i = 0; i < len; i++) {
        wstr[i] = (WCHAR)str[i];
    }
    wstr[len] = L'\0';
    return wstr;
}

void my_ptr_to_hex(void* ptr, char* buf, SIZE_T bufSize) {
    if (bufSize < 19) {
        if (bufSize > 0) buf[0] = '\0';
        return;
    }
    const char* hex = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    unsigned char* p = (unsigned char*)&ptr;
    for (int i = 0; i < 8; i++) {
        unsigned char byte = p[7 - i];
        buf[2 + i * 2] = hex[(byte >> 4) & 0xF];
        buf[3 + i * 2] = hex[byte & 0xF];
    }
    buf[18] = '\0';
}

void my_uint_to_str(SIZE_T value, char* buf, SIZE_T bufSize) {
    if (bufSize == 0) return;

    if (value == 0) {
        if (bufSize > 1) {
            buf[0] = '0';
            buf[1] = '\0';
        }
        else if (bufSize == 1) {
            buf[0] = '\0';
        }
        return;
    }

    SIZE_T pos = bufSize - 1;
    buf[pos] = '\0';

    while (value > 0 && pos > 0) {
        pos--;
        buf[pos] = (char)('0' + (value % 10));
        value /= 10;
    }

    if (pos > 0) {
        SIZE_T start = pos;
        SIZE_T len = (bufSize - 1) - start;
        for (SIZE_T i = 0; i < len; i++) {
            buf[i] = buf[start + i];
        }
        buf[len] = '\0';
    }
}

const char* custom_strstr(const char* haystack, const char* needle) {
    if (!*needle) return haystack;

    for (const char* h = haystack; *h; h++) {
        const char* h_iter = h;
        const char* n_iter = needle;

        while (*h_iter && *n_iter && (*h_iter == *n_iter)) {
            h_iter++;
            n_iter++;
        }

        if (!*n_iter) return h;
    }
    return NULL;
}

void my_memset(char* buf, char c, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        buf[i] = c;
    }
}

const char* ExtractProcessName(const char* fullPath) {
    const char* name = fullPath;
    for (const char* p = fullPath; *p; p++) {
        if (*p == '\\' || *p == '/') {
            name = p + 1;
        }
    }
    return name;
}

bool IsCurrentUserProcess(HANDLE hProcess, const char* currentUser) {
    HANDLE tokenHandle = NULL;
    
    NTSTATUS status = Sw3NtOpenProcessToken(
        hProcess,
        TOKEN_QUERY,
        &tokenHandle
    );
    
    if (status != STATUS_SUCCESS || tokenHandle == NULL) {
        return false;
    }

    char* buffer = (char*)MyAlloc(256);
    if (!buffer) {
        Sw3NtClose(tokenHandle);
        return false;
    }

    ULONG returnLength = 0;
    status = Sw3NtQueryInformationToken(
        tokenHandle,
        TokenUser,
        buffer,
        256,
        &returnLength
    );
    
    bool result = (status == STATUS_SUCCESS);

    MyFree(buffer);
    Sw3NtClose(tokenHandle);
    return result;
}

LONG CheckFileSignature(const char* filePath) {
    BOF_GUID PolicyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO FileData;
    WINTRUST_DATA WinTrustData;

    WCHAR* wFilePath = my_alloc_wide(filePath);
    if (!wFilePath) return E_OUTOFMEMORY;

    my_memset((char*)&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = wFilePath;

    my_memset((char*)&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &FileData;
    WinTrustData.dwStateAction = WTD_REVOCATION_CHECK_NONE;
    WinTrustData.dwProvFlags = 0;  

    LONG hr = WINTRUST$WinVerifyTrust(NULL, (GUID*)&PolicyGuid, &WinTrustData);

    MyFree(wFilePath);
    return hr;
}

void ScanForRWXRegions(HANDLE hProcess, void*** rwxBases, SIZE_T* rwxCount, SIZE_T* totalRWXSize) {
    *rwxBases = (void**)MyAlloc(sizeof(void*) * 256);
    *rwxCount = 0;
    *totalRWXSize = 0;
    
    if (!*rwxBases) {
        return;
    }
    
    my_memset((char*)*rwxBases, 0, sizeof(void*) * 256);
    
    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR addr = 0;
    SIZE_T returnLength = 0;
    
    while (addr < 0x7FFFFFFF0000ULL) {  // Stop at reasonable user-mode limit
        NTSTATUS status = Sw3NtQueryVirtualMemory(
            hProcess,
            (PVOID)addr,
            MemoryBasicInformation,
            &mbi,
            sizeof(MEMORY_BASIC_INFORMATION),
            &returnLength
        );
        
        if (status != STATUS_SUCCESS) {
            // If we get an error, try to skip ahead a bit
            addr += 0x1000;  // Skip 4KB page
            continue;
        }
        
        // Check for RWX memory
        if (mbi.State == MEM_COMMIT && 
            mbi.Type == MEM_PRIVATE && 
            mbi.Protect == PAGE_EXECUTE_READWRITE) {
            
            if (*rwxCount < 256) {
                (*rwxBases)[(*rwxCount)++] = mbi.BaseAddress;
            }
            *totalRWXSize += mbi.RegionSize;
        }
        
        // Move to next region
        DWORD_PTR nextAddr = addr + mbi.RegionSize;
        
        // Overflow protection
        if (nextAddr <= addr) {
            break;
        }
        
        addr = nextAddr;
    }
}

// Main
void go(char* args, int len) {

    DWORD* processes = (DWORD*)MyAlloc(sizeof(DWORD) * 1024);
    if (!processes) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure.");
        return;
    }

    DWORD cbNeeded;
    if (!PSAPI$EnumProcesses(processes, sizeof(DWORD) * 1024, &cbNeeded)) {
        MyFree(processes);
        BeaconPrintf(CALLBACK_ERROR, "Unable to enumerate processes.");
        return;
    }

    DWORD processCount = cbNeeded / sizeof(DWORD);

    char* currentUser = (char*)MyAlloc(256);
    if (!currentUser) {
        MyFree(processes);
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure.");
        return;
    }

    DWORD userLen = 256;
    if (!ADVAPI32$GetUserNameA(currentUser, &userLen)) {
        MyFree(currentUser);
        MyFree(processes);
        BeaconPrintf(CALLBACK_ERROR, "Unable to retrieve current user.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Silent Harbor: Process Information Findings\n");

    for (DWORD i = 0; i < processCount; i++) {
        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr,
                            NULL,       // no name
                            0,          // no flags
                            NULL,       // no root directory
                            NULL);      // no security descriptor

        DWORD pid = processes[i];
        if (pid == 0) continue;

        CLIENT_ID clientId = { 0 };
        clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        clientId.UniqueThread  = NULL;            
        
        NTSTATUS status = Sw3NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
        if (status != STATUS_SUCCESS)
            continue;

        if (!IsCurrentUserProcess(hProcess, currentUser)) {
                Sw3NtClose(hProcess);
                continue;
            }

        char* exePath = (char*)MyAlloc(MAX_PATH);
            if (!exePath) {
                Sw3NtClose(hProcess);
                continue;
            }

        if (!PSAPI$GetModuleFileNameExA(hProcess, NULL, exePath, MAX_PATH)) {
                MyFree(exePath);
                Sw3NtClose(hProcess);
                continue;
            }

        const char* processName = ExtractProcessName(exePath);
        
        HMODULE* modules = (HMODULE*)MyAlloc(sizeof(HMODULE) * 1024);
            bool foundWininet = false;
            bool foundWinhttp = false;
            bool isDotNet = false;

        if (modules) {
            DWORD cbModulesNeeded2;
            if (PSAPI$EnumProcessModules(hProcess, modules, sizeof(HMODULE) * 1024, &cbModulesNeeded2)) {
                DWORD moduleCount = cbModulesNeeded2 / sizeof(HMODULE);

                char* modulePath = (char*)MyAlloc(MAX_PATH);
                if (modulePath) {
                    for (DWORD j = 0; j < moduleCount; j++) {
                        if (PSAPI$GetModuleFileNameExA(hProcess, modules[j], modulePath, MAX_PATH)) {
                            if (!foundWininet && custom_strstr(modulePath, "wininet.dll")) {
                                foundWininet = true;
                            }
                            if (!foundWinhttp && custom_strstr(modulePath, "winhttp.dll")) {
                                foundWinhttp = true;
                            }
                            if (!isDotNet && (custom_strstr(modulePath, "mscoree.dll") || custom_strstr(modulePath, "clr.dll"))) {
                                isDotNet = true;
                            }
                            if (foundWininet && foundWinhttp && isDotNet) {
                                break;
                            }
                        }
                    }
                    MyFree(modulePath);
                }
            }
            MyFree(modules);
        }

        void** rwxBases = (void**)MyAlloc(sizeof(void*) * 256);
        SIZE_T rwxCount = 0;
        SIZE_T totalRWXSize = 0;
        
        ScanForRWXRegions(hProcess, &rwxBases, &rwxCount, &totalRWXSize);

        LONG sigResult = CheckFileSignature(exePath);
        bool isSigned = (sigResult == S_OK); 

        // Dynamically allocate large buffers instead of large stack arrays
            char* outBuf = (char*)MyAlloc(8192);
            if (!outBuf) {
                if (rwxBases) MyFree(rwxBases);
                MyFree(exePath);
                Sw3NtClose(hProcess);
                continue;
            }
            my_memset(outBuf, 0, 8192);

            char* line = (char*)MyAlloc(1024);
            if (!line) {
                MyFree(outBuf);
                if (rwxBases) MyFree(rwxBases);
                MyFree(exePath);
                Sw3NtClose(hProcess);
                continue;
            }
            my_memset(line, 0, 1024);

            char pidBuf[32];
            my_memset(pidBuf, 0, 32);
            my_uint_to_str(pid, pidBuf, 32);

            // Format PID & ProcessName line
            char pidLine[16];
            my_memset(pidLine, 0, 16);
            SIZE_T pidLen = my_strlen(pidBuf);
            SIZE_T pad = 6 > pidLen ? 6 - pidLen : 0;
            for (SIZE_T p = 0; p < pad; p++) my_strcat(pidLine, " ");
            my_strcat(pidLine, pidBuf);

            char nameLine[64];
            my_memset(nameLine, 0, 64);
            my_strcpy(nameLine, processName);
            SIZE_T nameLen = my_strlen(processName);
            for (SIZE_T n = nameLen; n < 30; n++) {
                my_strcat(nameLine, " ");
            }

            my_strcat(line, "  ");
            my_strcat(line, pidLine);
            my_strcat(line, "   ");
            my_strcat(line, nameLine);
            my_strcat(line, "\n");

            my_strcat(outBuf, line);

            bool anythingFound = false;

            // Signed
                if (isSigned) {
                    my_strcat(outBuf, "      Signed\n");
                    anythingFound = true;
                }

            // .NET
            if (isDotNet) {
                my_strcat(outBuf, "      .NET process\n");
                anythingFound = true;
            }

            // Modules
            if (foundWininet || foundWinhttp || isDotNet || isSigned || totalRWXSize > 0) {
                if (foundWininet || foundWinhttp) {
                    char* modLine = (char*)MyAlloc(512);
                    if (modLine) {
                        my_memset(modLine, 0, 512);
                        my_strcat(modLine, "      Modules: ");
                        if (foundWininet) {
                            my_strcat(modLine, "wininet.dll");
                            if (foundWinhttp) {
                                my_strcat(modLine, ", winhttp.dll");
                            }
                        }
                        else {
                            my_strcat(modLine, "winhttp.dll");
                        }
                        my_strcat(modLine, "\n");
                        my_strcat(outBuf, modLine);
                        MyFree(modLine);
                    }
                    anythingFound = true;
                }

                // RWX
                if (totalRWXSize > 0) {
                    char* rwxLine = (char*)MyAlloc(512);
                    if (rwxLine) {
                        my_memset(rwxLine, 0, 512);
                        my_strcat(rwxLine, "      RWX: ");
                        char sizeBuf[64];
                        my_memset(sizeBuf, 0, 64);
                        my_uint_to_str(totalRWXSize, sizeBuf, 64);
                        my_strcat(rwxLine, sizeBuf);
                        my_strcat(rwxLine, " bytes\n");
                        my_strcat(outBuf, rwxLine);
                        MyFree(rwxLine);
                    }
                    anythingFound = true;
                }

            }
            else {
                my_strcat(outBuf, "      No special findings\n");
            }

            // RWX Segments
            if (rwxCount > 0) {
                my_strcat(outBuf, "      RWX Segments:\n");
                for (SIZE_T k = 0; k < rwxCount; k++) {
                    char addrBuf[32];
                    my_memset(addrBuf, 0, 32);
                    my_ptr_to_hex(rwxBases[k], addrBuf, 32);
                    my_strcat(outBuf, "        ");
                    my_strcat(outBuf, addrBuf);
                    my_strcat(outBuf, "\n");
                }
            }

            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", outBuf);

            MyFree(line);
            MyFree(outBuf);
            if (rwxBases) MyFree(rwxBases);
            MyFree(exePath);
            Sw3NtClose(hProcess);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "------------------------------------------------------------\n");

        MyFree(currentUser);
        MyFree(processes);
}
