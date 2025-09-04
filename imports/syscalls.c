#include "syscalls.h"
#include "bofdefs.h"
//#include <stdio.h>

//#define DEBUG

#define JUMPER

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
    return (PVOID)__readfsdword(0xC0);
}

__declspec(naked) BOOL local_is_wow64(void)
{
    asm(
        "mov eax, fs:[0xc0] \n"
        "test eax, eax \n"
        "jne wow64 \n"
        "mov eax, 0 \n"
        "ret \n"
        "wow64: \n"
        "mov eax, 1 \n"
        "ret \n"
    );
}

#endif

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW3_SYSCALL_LIST SW3_SyscallList;

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }

    return Hash;
}

#ifndef JUMPER
PVOID SC_Address(PVOID NtApiAddress)
{
    return NULL;
}
#else
PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;

   #ifdef _WIN64
    // If the process is 64-bit on a 64-bit OS, we need to search for syscall
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
   #else
    // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
    ULONG distance_to_syscall = 0x0f;
   #endif

  #ifdef _M_IX86
    // If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
    if (local_is_wow64())
    {
    #ifdef DEBUG
        printf("[+] Running 32-bit app on x64 (WOW64)\n");
    #endif
        return NULL;
    }
  #endif

    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

    if (!MSVCRT$memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
        return SyscallAddress;
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!MSVCRT$memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }

        // let's try with an Nt* API above our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!MSVCRT$memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }
    }

#ifdef DEBUG
    printf("Syscall Opcodes not found!\n");
#endif

    return NULL;
}
#endif


BOOL SW3_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW3_SyscallList.Count) return TRUE;

    #ifdef _WIN64
    PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
    #else
    PSW3_PEB Peb = (PSW3_PEB)__readfsdword(0x30);
    #endif
    PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == SW3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW3_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW3_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

// EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
// {
//     // Ensure SW3_SyscallList is populated.
//     if (!SW3_PopulateSyscallList()) return NULL;

//     DWORD index = ((DWORD) rand()) % SW3_SyscallList.Count;

//     while (FunctionHash == SW3_SyscallList.Entries[index].Hash){
//         // Spoofing the syscall return address
//         index = ((DWORD) rand()) % SW3_SyscallList.Count;
//     }
//     return SW3_SyscallList.Entries[index].SyscallAddress;
// }
#if defined(__GNUC__)

__declspec(naked) NTSTATUS Sw3NtAccessCheck(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiaredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAC936DCF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAC936DCF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAC936DCF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAC936DCF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_AC936DCF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AC936DCF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AC936DCF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AC936DCF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AC936DCF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AC936DCF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWorkerFactoryWorkerReady(
	IN HANDLE WorkerFactoryHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x97A57DDB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x97A57DDB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x97A57DDB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x97A57DDB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_97A57DDB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_97A57DDB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_97A57DDB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_97A57DDB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_97A57DDB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_97A57DDB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAcceptConnectPort(
	OUT PHANDLE ServerPortHandle,
	IN ULONG AlternativeReceivePortHandle OPTIONAL,
	IN PPORT_MESSAGE ConnectionReply,
	IN BOOLEAN AcceptConnection,
	IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
	OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x22F4471E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22F4471E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22F4471E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22F4471E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_22F4471E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22F4471E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22F4471E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22F4471E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22F4471E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22F4471E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapUserPhysicalPagesScatter(
	IN PVOID VirtualAddresses,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDB60EDC1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB60EDC1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB60EDC1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB60EDC1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DB60EDC1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB60EDC1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB60EDC1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB60EDC1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB60EDC1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB60EDC1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA937B7AA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA937B7AA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA937B7AA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA937B7AA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_A937B7AA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A937B7AA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A937B7AA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A937B7AA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A937B7AA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A937B7AA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCallbackReturn(
	IN PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputLength,
	IN NTSTATUS Status)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x18837F96 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x18837F96 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x18837F96 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x18837F96 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_18837F96: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_18837F96 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_18837F96] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_18837F96 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_18837F96: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_18837F96: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x82D5AC9E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x82D5AC9E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x82D5AC9E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x82D5AC9E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_82D5AC9E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_82D5AC9E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_82D5AC9E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_82D5AC9E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_82D5AC9E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_82D5AC9E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD559FDD1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD559FDD1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD559FDD1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD559FDD1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_D559FDD1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D559FDD1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D559FDD1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D559FDD1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D559FDD1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D559FDD1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDE7C367A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE7C367A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE7C367A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE7C367A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_DE7C367A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE7C367A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE7C367A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE7C367A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE7C367A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE7C367A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRemoveIoCompletion(
	IN HANDLE IoCompletionHandle,
	OUT PULONG KeyContext,
	OUT PULONG ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0EA80E3F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0EA80E3F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0EA80E3F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0EA80E3F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0EA80E3F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0EA80E3F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0EA80E3F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0EA80E3F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0EA80E3F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0EA80E3F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseSemaphore(
	IN HANDLE SemaphoreHandle,
	IN LONG ReleaseCount,
	OUT PLONG PreviousCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF4AAA88D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF4AAA88D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF4AAA88D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF4AAA88D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F4AAA88D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F4AAA88D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F4AAA88D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F4AAA88D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F4AAA88D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F4AAA88D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyWaitReceivePort(
	IN HANDLE PortHandle,
	OUT PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2471072E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2471072E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2471072E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2471072E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_2471072E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2471072E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2471072E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2471072E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2471072E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2471072E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x268C3EE0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x268C3EE0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x268C3EE0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x268C3EE0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_268C3EE0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_268C3EE0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_268C3EE0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_268C3EE0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_268C3EE0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_268C3EE0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04B85407 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04B85407 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04B85407 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04B85407 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_04B85407: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04B85407 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04B85407] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04B85407 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04B85407: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04B85407: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00A3251A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00A3251A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00A3251A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00A3251A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_00A3251A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00A3251A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00A3251A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00A3251A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00A3251A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00A3251A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClose(
	IN HANDLE Handle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCA9BC732 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCA9BC732 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCA9BC732 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCA9BC732 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_CA9BC732: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CA9BC732 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CA9BC732] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CA9BC732 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CA9BC732: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CA9BC732: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x082778DB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x082778DB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x082778DB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x082778DB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_082778DB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_082778DB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_082778DB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_082778DB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_082778DB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_082778DB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x98016602 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x98016602 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x98016602 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x98016602 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_98016602: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_98016602 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_98016602] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_98016602 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_98016602: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_98016602: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x66E70B0D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x66E70B0D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x66E70B0D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x66E70B0D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_66E70B0D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_66E70B0D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_66E70B0D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_66E70B0D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_66E70B0D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_66E70B0D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3DC10670 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3DC10670 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3DC10670 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3DC10670 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_3DC10670: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3DC10670 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3DC10670] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3DC10670 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3DC10670: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3DC10670: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFindAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB4E64FE0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB4E64FE0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB4E64FE0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB4E64FE0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_B4E64FE0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B4E64FE0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B4E64FE0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B4E64FE0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B4E64FE0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B4E64FE0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDefaultLocale(
	IN BOOLEAN UserProfile,
	OUT PLCID DefaultLocaleId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB12D7B0B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB12D7B0B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB12D7B0B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB12D7B0B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B12D7B0B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B12D7B0B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B12D7B0B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B12D7B0B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B12D7B0B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B12D7B0B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryKey(
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D8544C2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D8544C2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D8544C2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D8544C2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_9D8544C2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D8544C2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D8544C2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D8544C2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D8544C2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D8544C2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8E1AE981 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8E1AE981 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8E1AE981 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8E1AE981 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8E1AE981: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8E1AE981 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8E1AE981] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8E1AE981 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8E1AE981: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8E1AE981: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x07BD1D3F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x07BD1D3F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x07BD1D3F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x07BD1D3F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_07BD1D3F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_07BD1D3F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_07BD1D3F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_07BD1D3F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_07BD1D3F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_07BD1D3F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E1475DC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E1475DC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E1475DC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E1475DC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0E1475DC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E1475DC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E1475DC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E1475DC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E1475DC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E1475DC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForMultipleObjects32(
	IN ULONG ObjectCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x009BBC15 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x009BBC15 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x009BBC15 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x009BBC15 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_009BBC15: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_009BBC15 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_009BBC15] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_009BBC15 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_009BBC15: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_009BBC15: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteFileGather(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8C68FC8A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8C68FC8A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8C68FC8A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8C68FC8A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_8C68FC8A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8C68FC8A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8C68FC8A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8C68FC8A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8C68FC8A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8C68FC8A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xABFEB669 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xABFEB669 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xABFEB669 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xABFEB669 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_ABFEB669: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ABFEB669 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ABFEB669] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ABFEB669 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ABFEB669: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ABFEB669: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D9116F3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D9116F3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D9116F3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D9116F3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0D9116F3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D9116F3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D9116F3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D9116F3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D9116F3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D9116F3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x78EC717E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x78EC717E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x78EC717E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x78EC717E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_78EC717E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_78EC717E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_78EC717E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_78EC717E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_78EC717E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_78EC717E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseMutant(
	IN HANDLE MutantHandle,
	OUT PULONG PreviousCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x309C1CC4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x309C1CC4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x309C1CC4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x309C1CC4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_309C1CC4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_309C1CC4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_309C1CC4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_309C1CC4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_309C1CC4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_309C1CC4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA393C100 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA393C100 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA393C100 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA393C100 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A393C100: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A393C100 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A393C100] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A393C100 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A393C100: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A393C100: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestWaitReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2CB62926 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2CB62926 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2CB62926 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2CB62926 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_2CB62926: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2CB62926 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2CB62926] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2CB62926 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2CB62926: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2CB62926: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x099524C1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x099524C1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x099524C1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x099524C1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_099524C1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_099524C1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_099524C1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_099524C1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_099524C1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_099524C1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x17A98EA2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x17A98EA2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x17A98EA2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x17A98EA2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_17A98EA2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_17A98EA2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_17A98EA2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_17A98EA2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_17A98EA2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_17A98EA2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1C47C106 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C47C106 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C47C106 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C47C106 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1C47C106: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C47C106 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C47C106] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C47C106 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C47C106: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C47C106: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4A1F7BB0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4A1F7BB0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4A1F7BB0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4A1F7BB0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_4A1F7BB0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4A1F7BB0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4A1F7BB0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4A1F7BB0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4A1F7BB0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4A1F7BB0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x25B51525 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x25B51525 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x25B51525 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x25B51525 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_25B51525: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_25B51525 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_25B51525] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_25B51525 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_25B51525: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_25B51525: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F5C3207 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F5C3207 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F5C3207 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F5C3207 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_1F5C3207: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F5C3207 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F5C3207] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F5C3207 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F5C3207: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F5C3207: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus,
	OUT PBOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x11ACFDED \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x11ACFDED \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x11ACFDED \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x11ACFDED \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_11ACFDED: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_11ACFDED \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_11ACFDED] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_11ACFDED \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_11ACFDED: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_11ACFDED: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF830F6AD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF830F6AD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF830F6AD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF830F6AD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F830F6AD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F830F6AD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F830F6AD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F830F6AD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F830F6AD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F830F6AD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyWaitReceivePortEx(
	IN HANDLE PortHandle,
	OUT PULONG PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA15FFF8A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA15FFF8A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA15FFF8A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA15FFF8A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A15FFF8A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A15FFF8A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A15FFF8A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A15FFF8A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A15FFF8A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A15FFF8A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x19B61828 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x19B61828 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x19B61828 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x19B61828 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_19B61828: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_19B61828 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_19B61828] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_19B61828 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_19B61828: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_19B61828: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetEventBoostPriority(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x10B61C3C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x10B61C3C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x10B61C3C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x10B61C3C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_10B61C3C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_10B61C3C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_10B61C3C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_10B61C3C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_10B61C3C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_10B61C3C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadFileScatter(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x23822D1B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x23822D1B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x23822D1B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x23822D1B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_23822D1B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_23822D1B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_23822D1B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_23822D1B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_23822D1B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_23822D1B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThreadTokenEx(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x190459CF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x190459CF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x190459CF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x190459CF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_190459CF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_190459CF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_190459CF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_190459CF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_190459CF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_190459CF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcessTokenEx(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF41EBEEC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF41EBEEC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF41EBEEC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF41EBEEC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F41EBEEC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F41EBEEC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F41EBEEC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F41EBEEC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F41EBEEC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F41EBEEC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x074A31CB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x074A31CB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x074A31CB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x074A31CB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_074A31CB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_074A31CB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_074A31CB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_074A31CB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_074A31CB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_074A31CB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1ECB7F51 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1ECB7F51 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1ECB7F51 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1ECB7F51 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1ECB7F51: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1ECB7F51 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1ECB7F51] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1ECB7F51 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1ECB7F51: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1ECB7F51: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x28B859AC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x28B859AC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x28B859AC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x28B859AC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_28B859AC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_28B859AC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_28B859AC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_28B859AC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_28B859AC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_28B859AC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38921FC3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38921FC3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38921FC3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38921FC3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_38921FC3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38921FC3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38921FC3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38921FC3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38921FC3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38921FC3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBC3BCCA0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC3BCCA0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC3BCCA0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC3BCCA0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_BC3BCCA0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC3BCCA0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC3BCCA0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC3BCCA0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC3BCCA0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC3BCCA0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDC31DCA3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC31DCA3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC31DCA3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC31DCA3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_DC31DCA3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC31DCA3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC31DCA3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC31DCA3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC31DCA3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC31DCA3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x74ED5275 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x74ED5275 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x74ED5275 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x74ED5275 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_74ED5275: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_74ED5275 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_74ED5275] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_74ED5275 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_74ED5275: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_74ED5275: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryTimer(
	IN HANDLE TimerHandle,
	IN TIMER_INFORMATION_CLASS TimerInformationClass,
	OUT PVOID TimerInformation,
	IN ULONG TimerInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1737C716 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1737C716 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1737C716 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1737C716 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1737C716: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1737C716 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1737C716] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1737C716 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1737C716: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1737C716: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFsControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FsControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x909808AE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x909808AE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x909808AE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x909808AE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_909808AE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_909808AE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_909808AE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_909808AE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_909808AE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_909808AE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0594031B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0594031B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0594031B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0594031B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0594031B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0594031B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0594031B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0594031B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0594031B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0594031B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCloseObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC03F3C70 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC03F3C70 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC03F3C70 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC03F3C70 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_C03F3C70: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C03F3C70 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C03F3C70] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C03F3C70 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C03F3C70: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C03F3C70: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x732963B4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x732963B4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x732963B4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x732963B4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_732963B4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_732963B4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_732963B4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_732963B4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_732963B4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_732963B4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_BASIC_INFORMATION FileInformation)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x60D67864 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x60D67864 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x60D67864 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x60D67864 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_60D67864: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_60D67864 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_60D67864] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_60D67864 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_60D67864: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_60D67864: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClearEvent(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02903728 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02903728 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02903728 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02903728 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_02903728: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02903728 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02903728] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02903728 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02903728: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02903728: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x17991117 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x17991117 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x17991117 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x17991117 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_17991117: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_17991117 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_17991117] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_17991117 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_17991117: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_17991117: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8181E69A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8181E69A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8181E69A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8181E69A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8181E69A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8181E69A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8181E69A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8181E69A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8181E69A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8181E69A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x35812520 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x35812520 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x35812520 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x35812520 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_35812520: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_35812520 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_35812520] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_35812520 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_35812520: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_35812520: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDuplicateToken(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x85D1B379 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x85D1B379 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x85D1B379 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x85D1B379 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_85D1B379: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_85D1B379 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_85D1B379] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_85D1B379 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_85D1B379: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_85D1B379: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtContinue(
	IN PCONTEXT ContextRecord,
	IN BOOLEAN TestAlert)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x22AF3124 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22AF3124 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22AF3124 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22AF3124 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_22AF3124: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22AF3124 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22AF3124] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22AF3124 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22AF3124: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22AF3124: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDefaultUILanguage(
	OUT PLANGID DefaultUILanguageId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDF092454 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDF092454 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDF092454 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDF092454 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_DF092454: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DF092454 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DF092454] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DF092454 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DF092454: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DF092454: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE6527B64 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE6527B64 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE6527B64 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE6527B64 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E6527B64: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E6527B64 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E6527B64] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E6527B64 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E6527B64: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E6527B64: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtYieldExecution()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDB50FFDA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB50FFDA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB50FFDA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB50FFDA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_DB50FFDA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB50FFDA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB50FFDA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB50FFDA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB50FFDA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB50FFDA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x94C3B351 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x94C3B351 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x94C3B351 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x94C3B351 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_94C3B351: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_94C3B351 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_94C3B351] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_94C3B351 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_94C3B351: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_94C3B351: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN EVENT_TYPE EventType,
	IN BOOLEAN InitialState)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4CD3494A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4CD3494A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4CD3494A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4CD3494A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_4CD3494A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4CD3494A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4CD3494A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4CD3494A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4CD3494A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4CD3494A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FsInformation,
	IN ULONG Length,
	IN FSINFOCLASS FsInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF9C0F864 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF9C0F864 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF9C0F864 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF9C0F864 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_F9C0F864: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F9C0F864 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F9C0F864] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F9C0F864 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F9C0F864: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F9C0F864: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAB68EFBA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB68EFBA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB68EFBA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB68EFBA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_AB68EFBA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB68EFBA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB68EFBA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB68EFBA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB68EFBA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB68EFBA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushBuffersFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x24A3D2BF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24A3D2BF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24A3D2BF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24A3D2BF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_24A3D2BF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24A3D2BF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24A3D2BF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24A3D2BF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24A3D2BF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24A3D2BF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtApphelpCacheControl(
	IN APPHELPCACHESERVICECLASS Service,
	IN PVOID ServiceData)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0752C604 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0752C604 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0752C604 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0752C604 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0752C604: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0752C604 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0752C604] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0752C604 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0752C604: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0752C604: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB1524D26 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB1524D26 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB1524D26 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB1524D26 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_B1524D26: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B1524D26 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B1524D26] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B1524D26 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B1524D26: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B1524D26: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PUSER_STACK InitialTeb,
	IN BOOLEAN CreateSuspended)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB08CBE26 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB08CBE26 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB08CBE26 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB08CBE26 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_B08CBE26: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B08CBE26 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B08CBE26] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B08CBE26 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B08CBE26: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B08CBE26: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtIsProcessInJob(
	IN HANDLE ProcessHandle,
	IN HANDLE JobHandle OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9E2B4F98 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9E2B4F98 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9E2B4F98 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9E2B4F98 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_9E2B4F98: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9E2B4F98 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9E2B4F98] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9E2B4F98 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9E2B4F98: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9E2B4F98: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCFD8D14F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCFD8D14F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCFD8D14F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCFD8D14F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_CFD8D14F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CFD8D14F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CFD8D14F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CFD8D14F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CFD8D14F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CFD8D14F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySection(
	IN HANDLE SectionHandle,
	IN SECTION_INFORMATION_CLASS SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD84FC4C5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD84FC4C5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD84FC4C5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD84FC4C5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_D84FC4C5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D84FC4C5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D84FC4C5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D84FC4C5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D84FC4C5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D84FC4C5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x103F5685 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x103F5685 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x103F5685 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x103F5685 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_103F5685: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_103F5685 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_103F5685] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_103F5685 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_103F5685: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_103F5685: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateThread(
	IN HANDLE ThreadHandle,
	IN NTSTATUS ExitStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x12B20813 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12B20813 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12B20813 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12B20813 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_12B20813: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12B20813 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12B20813] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12B20813 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12B20813: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12B20813: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG DataEntryIndex,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x64F9B24E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64F9B24E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64F9B24E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64F9B24E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_64F9B24E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64F9B24E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64F9B24E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64F9B24E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64F9B24E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64F9B24E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFF66ADD3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFF66ADD3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFF66ADD3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFF66ADD3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_FF66ADD3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FF66ADD3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FF66ADD3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FF66ADD3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FF66ADD3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FF66ADD3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryEvent(
	IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA6333534 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA6333534 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA6333534 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA6333534 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A6333534: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A6333534 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A6333534] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A6333534 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A6333534: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A6333534: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Request,
	IN ULONG DataIndex,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1ED66A00 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1ED66A00 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1ED66A00 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1ED66A00 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1ED66A00: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1ED66A00 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1ED66A00] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1ED66A00 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1ED66A00: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1ED66A00: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x14B72817 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x14B72817 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14B72817 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14B72817 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_14B72817: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14B72817 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14B72817] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14B72817 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14B72817: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14B72817: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PBOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x12913444 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12913444 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12913444 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12913444 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_12913444: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12913444 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12913444] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12913444 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12913444: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12913444: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x13AF3F35 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x13AF3F35 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x13AF3F35 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x13AF3F35 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_13AF3F35: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_13AF3F35 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_13AF3F35] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_13AF3F35 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_13AF3F35: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_13AF3F35: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02866E59 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02866E59 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02866E59 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02866E59 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_02866E59: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02866E59 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02866E59] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02866E59 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02866E59: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02866E59: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelIoFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D4495D1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D4495D1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D4495D1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D4495D1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_9D4495D1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D4495D1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D4495D1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D4495D1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D4495D1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D4495D1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTraceEvent(
	IN HANDLE TraceHandle,
	IN ULONG Flags,
	IN ULONG FieldSize,
	IN PVOID Fields)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x766B0F8E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x766B0F8E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x766B0F8E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x766B0F8E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_766B0F8E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_766B0F8E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_766B0F8E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_766B0F8E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_766B0F8E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_766B0F8E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPowerInformation(
	IN POWER_INFORMATION_LEVEL InformationLevel,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2A6A2CFF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2A6A2CFF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2A6A2CFF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2A6A2CFF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_2A6A2CFF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2A6A2CFF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2A6A2CFF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2A6A2CFF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2A6A2CFF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2A6A2CFF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID SystemData,
	IN ULONG DataSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2B9F063D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B9F063D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B9F063D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B9F063D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2B9F063D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B9F063D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B9F063D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B9F063D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B9F063D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B9F063D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelTimer(
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB7218188 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB7218188 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB7218188 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB7218188 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B7218188: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B7218188 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B7218188] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B7218188 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B7218188: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B7218188: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN ResumeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE3B8FF33 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE3B8FF33 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE3B8FF33 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE3B8FF33 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_E3B8FF33: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E3B8FF33 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E3B8FF33] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E3B8FF33 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E3B8FF33: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E3B8FF33: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByType(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ULONG DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDE87D426 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE87D426 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE87D426 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE87D426 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_DE87D426: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE87D426 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE87D426] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE87D426 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE87D426: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE87D426: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeResultList(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06B20A35 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06B20A35 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06B20A35 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06B20A35 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_06B20A35: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06B20A35 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06B20A35] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06B20A35 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06B20A35: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06B20A35: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeResultListAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5ADC3A4A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5ADC3A4A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5ADC3A4A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5ADC3A4A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_5ADC3A4A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5ADC3A4A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5ADC3A4A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5ADC3A4A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5ADC3A4A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5ADC3A4A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x65D96F68 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x65D96F68 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x65D96F68 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x65D96F68 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x11 \n"
	"push_argument_65D96F68: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_65D96F68 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_65D96F68] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_65D96F68 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_65D96F68: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_65D96F68: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAcquireProcessActivityReference()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x72AB3C8E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x72AB3C8E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x72AB3C8E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x72AB3C8E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_72AB3C8E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_72AB3C8E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_72AB3C8E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_72AB3C8E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_72AB3C8E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_72AB3C8E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddAtomEx(
	IN PWSTR AtomName,
	IN ULONG Length,
	IN PRTL_ATOM Atom,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9993A330 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9993A330 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9993A330 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9993A330 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_9993A330: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9993A330 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9993A330] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9993A330 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9993A330: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9993A330: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddBootEntry(
	IN PBOOT_ENTRY BootEntry,
	OUT PULONG Id OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x199432C6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x199432C6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x199432C6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x199432C6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_199432C6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_199432C6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_199432C6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_199432C6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_199432C6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_199432C6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry,
	OUT PULONG Id OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0FD66534 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FD66534 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FD66534 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FD66534 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0FD66534: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FD66534 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FD66534] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FD66534 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FD66534: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FD66534: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAdjustGroupsToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN ResetToDefault,
	IN PTOKEN_GROUPS NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_GROUPS PreviousState OPTIONAL,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2D98FE35 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2D98FE35 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2D98FE35 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2D98FE35 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2D98FE35: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2D98FE35 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2D98FE35] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2D98FE35 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2D98FE35: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2D98FE35: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAdjustTokenClaimsAndDeviceGroups(
	IN HANDLE TokenHandle,
	IN BOOLEAN UserResetToDefault,
	IN BOOLEAN DeviceResetToDefault,
	IN BOOLEAN DeviceGroupsResetToDefault,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
	IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
	IN ULONG UserBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
	IN ULONG DeviceBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
	IN ULONG DeviceGroupsBufferLength,
	OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
	OUT PULONG UserReturnLength OPTIONAL,
	OUT PULONG DeviceReturnLength OPTIONAL,
	OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3BA92521 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3BA92521 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3BA92521 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3BA92521 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_3BA92521: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3BA92521 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3BA92521] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3BA92521 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3BA92521: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3BA92521: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlertResumeThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x694FB57F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x694FB57F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x694FB57F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x694FB57F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_694FB57F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_694FB57F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_694FB57F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_694FB57F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_694FB57F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_694FB57F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlertThread(
	IN HANDLE ThreadHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF4DF73E5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF4DF73E5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF4DF73E5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF4DF73E5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_F4DF73E5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F4DF73E5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F4DF73E5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F4DF73E5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F4DF73E5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F4DF73E5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlertThreadByThreadId(
	IN ULONG ThreadId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x49508C28 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x49508C28 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x49508C28 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x49508C28 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_49508C28: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_49508C28 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_49508C28] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_49508C28 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_49508C28: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_49508C28: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateLocallyUniqueId(
	OUT PLUID Luid)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x052D2D98 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x052D2D98 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x052D2D98 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x052D2D98 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_052D2D98: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_052D2D98 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_052D2D98] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_052D2D98 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_052D2D98: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_052D2D98: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateReserveObject(
	OUT PHANDLE MemoryReserveHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN MEMORY_RESERVE_TYPE Type)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8211EA8D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8211EA8D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8211EA8D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8211EA8D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8211EA8D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8211EA8D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8211EA8D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8211EA8D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8211EA8D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8211EA8D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	OUT PULONG UserPfnArray)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F86301A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F86301A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F86301A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F86301A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1F86301A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F86301A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F86301A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F86301A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F86301A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F86301A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateUuids(
	OUT PLARGE_INTEGER Time,
	OUT PULONG Range,
	OUT PULONG Sequence,
	OUT PUCHAR Seed)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0BA92935 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BA92935 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BA92935 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BA92935 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0BA92935: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BA92935 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BA92935] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BA92935 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BA92935: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BA92935: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateVirtualMemoryEx(
	IN HANDLE ProcessHandle,
	IN OUT PPVOID lpAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T pSize,
	IN ULONG flAllocationType,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x008E4255 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x008E4255 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x008E4255 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x008E4255 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_008E4255: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_008E4255 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_008E4255] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_008E4255 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_008E4255: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_008E4255: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcAcceptConnectPort(
	OUT PHANDLE PortHandle,
	IN HANDLE ConnectionPortHandle,
	IN ULONG Flags,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ConnectionRequest,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
	IN BOOLEAN AcceptConnection)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x66816D1E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x66816D1E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x66816D1E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x66816D1E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_66816D1E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_66816D1E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_66816D1E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_66816D1E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_66816D1E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_66816D1E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCancelMessage(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PALPC_CONTEXT_ATTR MessageContext)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFA5A1E5B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFA5A1E5B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFA5A1E5B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFA5A1E5B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FA5A1E5B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FA5A1E5B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FA5A1E5B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FA5A1E5B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FA5A1E5B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FA5A1E5B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x610C40A0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x610C40A0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x610C40A0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x610C40A0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_610C40A0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_610C40A0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_610C40A0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_610C40A0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_610C40A0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_610C40A0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcConnectPortEx(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x85AD76D6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x85AD76D6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x85AD76D6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x85AD76D6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_85AD76D6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_85AD76D6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_85AD76D6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_85AD76D6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_85AD76D6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_85AD76D6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE4B0FD3D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE4B0FD3D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE4B0FD3D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE4B0FD3D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_E4B0FD3D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E4B0FD3D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E4B0FD3D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E4B0FD3D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E4B0FD3D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E4B0FD3D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreatePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN SIZE_T SectionSize,
	OUT PHANDLE AlpcSectionHandle,
	OUT PSIZE_T ActualSectionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8A27CAF5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A27CAF5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A27CAF5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A27CAF5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8A27CAF5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A27CAF5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A27CAF5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A27CAF5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A27CAF5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A27CAF5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreateResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN SIZE_T MessageSize,
	OUT PHANDLE ResourceId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF45ED21F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF45ED21F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF45ED21F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF45ED21F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F45ED21F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F45ED21F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F45ED21F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F45ED21F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F45ED21F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F45ED21F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreateSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x14A4211B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x14A4211B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14A4211B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14A4211B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_14A4211B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14A4211B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14A4211B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14A4211B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14A4211B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14A4211B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreateSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_SECURITY_ATTR SecurityAttribute)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7EE27A92 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7EE27A92 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7EE27A92 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7EE27A92 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7EE27A92: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7EE27A92 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7EE27A92] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7EE27A92 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7EE27A92: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7EE27A92: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeletePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB46BD6BB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB46BD6BB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB46BD6BB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB46BD6BB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_B46BD6BB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B46BD6BB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B46BD6BB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B46BD6BB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B46BD6BB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B46BD6BB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeleteResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ResourceId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E8711E3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E8711E3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E8711E3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E8711E3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1E8711E3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E8711E3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E8711E3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E8711E3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E8711E3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E8711E3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeleteSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID ViewBase)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8C29FBD7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8C29FBD7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8C29FBD7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8C29FBD7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8C29FBD7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8C29FBD7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8C29FBD7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8C29FBD7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8C29FBD7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8C29FBD7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeleteSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFD48E8C9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFD48E8C9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFD48E8C9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFD48E8C9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FD48E8C9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FD48E8C9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FD48E8C9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FD48E8C9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FD48E8C9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FD48E8C9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDisconnectPort(
	IN HANDLE PortHandle,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02B3013C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02B3013C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02B3013C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02B3013C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_02B3013C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02B3013C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02B3013C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02B3013C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02B3013C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02B3013C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcImpersonateClientContainerOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xED76F8DF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xED76F8DF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xED76F8DF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xED76F8DF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_ED76F8DF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ED76F8DF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ED76F8DF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ED76F8DF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ED76F8DF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ED76F8DF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN PVOID Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA032CDAC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA032CDAC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA032CDAC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA032CDAC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_A032CDAC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A032CDAC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A032CDAC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A032CDAC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A032CDAC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A032CDAC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcOpenSenderProcess(
	OUT PHANDLE ProcessHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8456B41B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8456B41B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8456B41B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8456B41B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8456B41B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8456B41B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8456B41B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8456B41B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8456B41B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8456B41B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcOpenSenderThread(
	OUT PHANDLE ThreadHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBD1F61AF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBD1F61AF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBD1F61AF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBD1F61AF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_BD1F61AF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BD1F61AF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BD1F61AF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BD1F61AF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BD1F61AF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BD1F61AF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcQueryInformation(
	IN HANDLE PortHandle OPTIONAL,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8657E483 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8657E483 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8657E483 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8657E483 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8657E483: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8657E483 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8657E483] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8657E483 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8657E483: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8657E483: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcQueryInformationMessage(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
	OUT PVOID MessageInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x45570B72 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x45570B72 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x45570B72 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x45570B72 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_45570B72: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_45570B72 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_45570B72] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_45570B72 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_45570B72: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_45570B72: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcRevokeSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDF8AC203 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDF8AC203 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDF8AC203 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDF8AC203 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DF8AC203: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DF8AC203 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DF8AC203] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DF8AC203 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DF8AC203: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DF8AC203: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PPORT_MESSAGE SendMessage OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2CB1C3D2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2CB1C3D2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2CB1C3D2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2CB1C3D2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_2CB1C3D2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2CB1C3D2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2CB1C3D2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2CB1C3D2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2CB1C3D2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2CB1C3D2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcSetInformation(
	IN HANDLE PortHandle,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN PVOID PortInformation OPTIONAL,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x005F3E13 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x005F3E13 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x005F3E13 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x005F3E13 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_005F3E13: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_005F3E13 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_005F3E13] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_005F3E13 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_005F3E13: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_005F3E13: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAreMappedFilesTheSame(
	IN PVOID File1MappedAsAnImage,
	IN PVOID File2MappedAsFile)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x71D0E2E6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x71D0E2E6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x71D0E2E6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x71D0E2E6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_71D0E2E6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_71D0E2E6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_71D0E2E6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_71D0E2E6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_71D0E2E6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_71D0E2E6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x193977AB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x193977AB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x193977AB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x193977AB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_193977AB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_193977AB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_193977AB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_193977AB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_193977AB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_193977AB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAssociateWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN HANDLE IoCompletionHandle,
	IN HANDLE TargetObjectHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation,
	OUT PBOOLEAN AlreadySignaled OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x19CD2282 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x19CD2282 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x19CD2282 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x19CD2282 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_19CD2282: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_19CD2282 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_19CD2282] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_19CD2282 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_19CD2282: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_19CD2282: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCallEnclave(
	IN PENCLAVE_ROUTINE Routine,
	IN PVOID Parameter,
	IN BOOLEAN WaitForThread,
	IN OUT PVOID ReturnValue OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC736D7BD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC736D7BD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC736D7BD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC736D7BD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C736D7BD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C736D7BD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C736D7BD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C736D7BD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C736D7BD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C736D7BD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelIoFileEx(
	IN HANDLE FileHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E8A5A57 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E8A5A57 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E8A5A57 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E8A5A57 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0E8A5A57: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E8A5A57 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E8A5A57] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E8A5A57 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E8A5A57: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E8A5A57: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelSynchronousIoFile(
	IN HANDLE ThreadHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE950A387 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE950A387 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE950A387 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE950A387 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_E950A387: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E950A387 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E950A387] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E950A387 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E950A387: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E950A387: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelTimer2(
	IN HANDLE TimerHandle,
	IN PT2_CANCEL_PARAMETERS Parameters)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3F96FD99 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3F96FD99 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3F96FD99 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3F96FD99 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3F96FD99: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3F96FD99 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3F96FD99] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3F96FD99 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3F96FD99: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3F96FD99: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN BOOLEAN RemoveSignaledPacket)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB62286AF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB62286AF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB62286AF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB62286AF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B62286AF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B62286AF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B62286AF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B62286AF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B62286AF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B62286AF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x48D16E52 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48D16E52 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x48D16E52 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x48D16E52 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_48D16E52: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_48D16E52 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_48D16E52] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_48D16E52 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_48D16E52: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_48D16E52: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x189D7B0A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x189D7B0A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x189D7B0A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x189D7B0A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_189D7B0A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_189D7B0A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_189D7B0A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_189D7B0A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_189D7B0A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_189D7B0A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD942C5EC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD942C5EC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD942C5EC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD942C5EC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D942C5EC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D942C5EC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D942C5EC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D942C5EC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D942C5EC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D942C5EC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5ECB7C5F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5ECB7C5F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5ECB7C5F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5ECB7C5F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_5ECB7C5F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5ECB7C5F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5ECB7C5F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5ECB7C5F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5ECB7C5F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5ECB7C5F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompactKeys(
	IN ULONG Count,
	IN HANDLE KeyArray)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x59A4ACE2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x59A4ACE2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x59A4ACE2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x59A4ACE2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_59A4ACE2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_59A4ACE2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_59A4ACE2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_59A4ACE2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_59A4ACE2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_59A4ACE2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompareObjects(
	IN HANDLE FirstObjectHandle,
	IN HANDLE SecondObjectHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF4BACC16 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF4BACC16 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF4BACC16 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF4BACC16 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F4BACC16: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F4BACC16 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F4BACC16] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F4BACC16 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F4BACC16: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F4BACC16: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompareSigningLevels(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4A965212 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4A965212 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4A965212 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4A965212 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4A965212: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4A965212 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4A965212] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4A965212 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4A965212: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4A965212: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompareTokens(
	IN HANDLE FirstTokenHandle,
	IN HANDLE SecondTokenHandle,
	OUT PBOOLEAN Equal)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D55F51F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D55F51F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D55F51F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D55F51F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0D55F51F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D55F51F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D55F51F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D55F51F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D55F51F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D55F51F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompleteConnectPort(
	IN HANDLE PortHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDC36C1A6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC36C1A6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC36C1A6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC36C1A6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_DC36C1A6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC36C1A6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC36C1A6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC36C1A6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC36C1A6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC36C1A6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompressKey(
	IN HANDLE Key)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFB590F25 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFB590F25 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFB590F25 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFB590F25 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_FB590F25: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FB590F25 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FB590F25] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FB590F25 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FB590F25: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FB590F25: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38BE2530 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38BE2530 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38BE2530 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38BE2530 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_38BE2530: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38BE2530 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38BE2530] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38BE2530 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38BE2530: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38BE2530: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE79234D2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE79234D2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE79234D2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE79234D2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_E79234D2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E79234D2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E79234D2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E79234D2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E79234D2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E79234D2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1CB62E0B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1CB62E0B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1CB62E0B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1CB62E0B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1CB62E0B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1CB62E0B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1CB62E0B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1CB62E0B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1CB62E0B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1CB62E0B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF25CDCE1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF25CDCE1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF25CDCE1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF25CDCE1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F25CDCE1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F25CDCE1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F25CDCE1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F25CDCE1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F25CDCE1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F25CDCE1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateDirectoryObjectEx(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xACBD62FA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xACBD62FA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xACBD62FA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xACBD62FA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_ACBD62FA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ACBD62FA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ACBD62FA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ACBD62FA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ACBD62FA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ACBD62FA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEnclave(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T Size,
	IN SIZE_T InitialCommitment,
	IN ULONG EnclaveType,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5A2BAA40 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5A2BAA40 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5A2BAA40 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5A2BAA40 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_5A2BAA40: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5A2BAA40 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5A2BAA40] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5A2BAA40 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5A2BAA40: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5A2BAA40: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN HANDLE TransactionHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN NOTIFICATION_MASK NotificationMask,
	IN PVOID EnlistmentKey OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB966CAE1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB966CAE1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB966CAE1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB966CAE1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_B966CAE1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B966CAE1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B966CAE1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B966CAE1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B966CAE1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B966CAE1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB1345FA8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB1345FA8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB1345FA8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB1345FA8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_B1345FA8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B1345FA8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B1345FA8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B1345FA8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B1345FA8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B1345FA8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateIRTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6BD2191E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6BD2191E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6BD2191E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6BD2191E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6BD2191E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6BD2191E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6BD2191E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6BD2191E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6BD2191E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6BD2191E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Count OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9A3ABEA9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9A3ABEA9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9A3ABEA9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9A3ABEA9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_9A3ABEA9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9A3ABEA9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9A3ABEA9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9A3ABEA9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9A3ABEA9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9A3ABEA9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0EB5F9A9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0EB5F9A9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0EB5F9A9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0EB5F9A9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0EB5F9A9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0EB5F9A9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0EB5F9A9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0EB5F9A9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0EB5F9A9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0EB5F9A9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateJobSet(
	IN ULONG NumJob,
	IN PJOB_SET_ARRAY UserJobSet,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x82BE1AB3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x82BE1AB3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x82BE1AB3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x82BE1AB3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_82BE1AB3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_82BE1AB3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_82BE1AB3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_82BE1AB3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_82BE1AB3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_82BE1AB3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	IN HANDLE TransactionHandle,
	OUT PULONG Disposition OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x54DD6A06 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x54DD6A06 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x54DD6A06 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x54DD6A06 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_54DD6A06: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_54DD6A06 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_54DD6A06] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_54DD6A06 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_54DD6A06: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_54DD6A06: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x88138F88 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x88138F88 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x88138F88 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x88138F88 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_88138F88: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_88138F88 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_88138F88] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_88138F88 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_88138F88: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_88138F88: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateLowBoxToken(
	OUT PHANDLE TokenHandle,
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PSID PackageSid,
	IN ULONG CapabilityCount,
	IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
	IN ULONG HandleCount,
	IN HANDLE Handles OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x95B28B1F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x95B28B1F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x95B28B1F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x95B28B1F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_95B28B1F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_95B28B1F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_95B28B1F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_95B28B1F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_95B28B1F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_95B28B1F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateMailslotFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CreateOptions,
	IN ULONG MailslotQuota,
	IN ULONG MaximumMessageSize,
	IN PLARGE_INTEGER ReadTimeout)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2801BA36 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2801BA36 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2801BA36 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2801BA36 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_2801BA36: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2801BA36 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2801BA36] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2801BA36 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2801BA36: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2801BA36: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN BOOLEAN InitialOwner)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFABC19AA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFABC19AA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFABC19AA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFABC19AA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_FABC19AA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FABC19AA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FABC19AA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FABC19AA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FABC19AA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FABC19AA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN NamedPipeType,
	IN BOOLEAN ReadMode,
	IN BOOLEAN CompletionMode,
	IN ULONG MaximumInstances,
	IN ULONG InboundQuota,
	IN ULONG OutboundQuota,
	IN PLARGE_INTEGER DefaultTimeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3EA45474 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3EA45474 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3EA45474 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3EA45474 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xe \n"
	"push_argument_3EA45474: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3EA45474 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3EA45474] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3EA45474 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3EA45474: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3EA45474: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePagingFile(
	IN PUNICODE_STRING PageFileName,
	IN PULARGE_INTEGER MinimumSize,
	IN PULARGE_INTEGER MaximumSize,
	IN ULONG Priority)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x18830030 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x18830030 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x18830030 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x18830030 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_18830030: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_18830030 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_18830030] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_18830030 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_18830030: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_18830030: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG PreferredNode)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7A6C32B7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7A6C32B7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7A6C32B7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7A6C32B7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_7A6C32B7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7A6C32B7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7A6C32B7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7A6C32B7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7A6C32B7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7A6C32B7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x24B13D3C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24B13D3C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24B13D3C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24B13D3C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_24B13D3C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24B13D3C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24B13D3C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24B13D3C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24B13D3C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24B13D3C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PVOID BoundaryDescriptor)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x785E61EB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x785E61EB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x785E61EB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x785E61EB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_785E61EB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_785E61EB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_785E61EB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_785E61EB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_785E61EB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_785E61EB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE6ABCFF7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE6ABCFF7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE6ABCFF7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE6ABCFF7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_E6ABCFF7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E6ABCFF7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E6ABCFF7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E6ABCFF7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E6ABCFF7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E6ABCFF7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProfile(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN ULONG ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN ULONG Affinity)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0FBCD10D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FBCD10D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FBCD10D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FBCD10D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_0FBCD10D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FBCD10D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FBCD10D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FBCD10D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FBCD10D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FBCD10D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProfileEx(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN SIZE_T ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN USHORT GroupCount,
	IN PGROUP_AFFINITY GroupAffinity)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6EAF84CD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6EAF84CD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6EAF84CD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6EAF84CD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_6EAF84CD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6EAF84CD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6EAF84CD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6EAF84CD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6EAF84CD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6EAF84CD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateRegistryTransaction(
	OUT PHANDLE Handle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x10CA7019 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x10CA7019 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x10CA7019 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x10CA7019 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_10CA7019: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_10CA7019 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_10CA7019] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_10CA7019 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_10CA7019: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_10CA7019: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID RmGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F9F3706 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F9F3706 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F9F3706 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F9F3706 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_1F9F3706: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F9F3706 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F9F3706] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F9F3706 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F9F3706: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F9F3706: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LONG InitialCount,
	IN LONG MaximumCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C9AFFF4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C9AFFF4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C9AFFF4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C9AFFF4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0C9AFFF4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C9AFFF4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C9AFFF4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C9AFFF4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C9AFFF4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C9AFFF4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING LinkTarget)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3A170ABB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A170ABB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A170ABB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A170ABB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3A170ABB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A170ABB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A170ABB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A170ABB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A170ABB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A170ABB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8AABCE74 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8AABCE74 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8AABCE74 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8AABCE74 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_8AABCE74: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8AABCE74 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8AABCE74] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8AABCE74 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8AABCE74: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8AABCE74: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x63B78EEC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x63B78EEC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63B78EEC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63B78EEC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_63B78EEC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63B78EEC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63B78EEC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63B78EEC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63B78EEC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63B78EEC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTimer2(
	OUT PHANDLE TimerHandle,
	IN PVOID Reserved1 OPTIONAL,
	IN PVOID Reserved2 OPTIONAL,
	IN ULONG Attributes,
	IN ACCESS_MASK DesiredAccess)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8FD444C2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8FD444C2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8FD444C2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8FD444C2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8FD444C2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8FD444C2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8FD444C2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8FD444C2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8FD444C2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8FD444C2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7BAD92F6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7BAD92F6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7BAD92F6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7BAD92F6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xd \n"
	"push_argument_7BAD92F6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7BAD92F6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7BAD92F6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7BAD92F6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7BAD92F6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7BAD92F6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTokenEx(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
	IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x595C29A7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x595C29A7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x595C29A7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x595C29A7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x11 \n"
	"push_argument_595C29A7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_595C29A7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_595C29A7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_595C29A7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_595C29A7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_595C29A7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1D165FC3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1D165FC3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1D165FC3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1D165FC3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_1D165FC3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1D165FC3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1D165FC3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1D165FC3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1D165FC3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1D165FC3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG CommitStrength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x37201DBC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x37201DBC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x37201DBC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x37201DBC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_37201DBC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_37201DBC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_37201DBC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_37201DBC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_37201DBC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_37201DBC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x27AF2E36 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x27AF2E36 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x27AF2E36 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x27AF2E36 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_27AF2E36: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_27AF2E36 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_27AF2E36] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_27AF2E36 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_27AF2E36: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_27AF2E36: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWaitCompletionPacket(
	OUT PHANDLE WaitCompletionPacketHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x99B2BD22 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x99B2BD22 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x99B2BD22 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x99B2BD22 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_99B2BD22: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_99B2BD22 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_99B2BD22] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_99B2BD22 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_99B2BD22: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_99B2BD22: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWaitablePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE475C5A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE475C5A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE475C5A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE475C5A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E475C5A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E475C5A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E475C5A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E475C5A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E475C5A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E475C5A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWnfStateName(
	OUT PCWNF_STATE_NAME StateName,
	IN WNF_STATE_NAME_LIFETIME NameLifetime,
	IN WNF_DATA_SCOPE DataScope,
	IN BOOLEAN PersistData,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN ULONG MaximumStateSize,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9A346557 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9A346557 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9A346557 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9A346557 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_9A346557: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9A346557 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9A346557] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9A346557 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9A346557: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9A346557: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWorkerFactory(
	OUT PHANDLE WorkerFactoryHandleReturn,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE CompletionPortHandle,
	IN HANDLE WorkerProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartParameter OPTIONAL,
	IN ULONG MaxThreadCount OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04893004 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04893004 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04893004 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04893004 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_04893004: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04893004 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04893004] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04893004 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04893004: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04893004: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3FBC223C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3FBC223C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3FBC223C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3FBC223C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3FBC223C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3FBC223C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3FBC223C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3FBC223C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3FBC223C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3FBC223C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x268B093C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x268B093C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x268B093C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x268B093C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_268B093C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_268B093C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_268B093C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_268B093C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_268B093C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_268B093C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteAtom(
	IN USHORT Atom)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x76FB9262 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x76FB9262 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x76FB9262 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x76FB9262 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_76FB9262: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_76FB9262 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_76FB9262] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_76FB9262 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_76FB9262: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_76FB9262: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteBootEntry(
	IN ULONG Id)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D8A8718 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D8A8718 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D8A8718 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D8A8718 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9D8A8718: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D8A8718 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D8A8718] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D8A8718 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D8A8718: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D8A8718: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteDriverEntry(
	IN ULONG Id)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCB16FFBA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCB16FFBA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB16FFBA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB16FFBA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_CB16FFBA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB16FFBA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB16FFBA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB16FFBA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB16FFBA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB16FFBA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26BCAE9A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26BCAE9A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26BCAE9A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26BCAE9A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_26BCAE9A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26BCAE9A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26BCAE9A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26BCAE9A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26BCAE9A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26BCAE9A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteKey(
	IN HANDLE KeyHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAF1AC0FC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAF1AC0FC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAF1AC0FC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAF1AC0FC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AF1AC0FC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AF1AC0FC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AF1AC0FC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AF1AC0FC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AF1AC0FC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AF1AC0FC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE1BFDD6E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE1BFDD6E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE1BFDD6E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE1BFDD6E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_E1BFDD6E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E1BFDD6E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E1BFDD6E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E1BFDD6E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E1BFDD6E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E1BFDD6E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeletePrivateNamespace(
	IN HANDLE NamespaceHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x15362C95 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x15362C95 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x15362C95 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x15362C95 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_15362C95: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_15362C95 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_15362C95] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_15362C95 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_15362C95: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_15362C95: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5DE14670 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5DE14670 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5DE14670 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5DE14670 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_5DE14670: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5DE14670 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5DE14670] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5DE14670 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5DE14670: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5DE14670: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID ExplicitScope OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3C820018 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3C820018 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3C820018 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3C820018 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3C820018: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3C820018 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3C820018] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3C820018 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3C820018: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3C820018: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteWnfStateName(
	IN PCWNF_STATE_NAME StateName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x36D01913 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36D01913 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36D01913 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36D01913 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_36D01913: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36D01913 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36D01913] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36D01913 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36D01913: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36D01913: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDisableLastKnownGood()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD546E3D4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD546E3D4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD546E3D4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD546E3D4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_D546E3D4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D546E3D4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D546E3D4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D546E3D4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D546E3D4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D546E3D4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDisplayString(
	IN PUNICODE_STRING String)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3E982A20 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3E982A20 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3E982A20 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3E982A20 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3E982A20: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3E982A20 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3E982A20] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3E982A20 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3E982A20: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3E982A20: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDrawText(
	IN PUNICODE_STRING String)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x72CD755E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x72CD755E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x72CD755E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x72CD755E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_72CD755E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_72CD755E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_72CD755E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_72CD755E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_72CD755E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_72CD755E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnableLastKnownGood()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF86B047B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF86B047B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF86B047B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF86B047B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_F86B047B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F86B047B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F86B047B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F86B047B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F86B047B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F86B047B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateBootEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x914CECA4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x914CECA4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x914CECA4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x914CECA4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_914CECA4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_914CECA4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_914CECA4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_914CECA4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_914CECA4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_914CECA4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateDriverEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3E994F65 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3E994F65 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3E994F65 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3E994F65 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3E994F65: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3E994F65 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3E994F65] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3E994F65 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3E994F65: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3E994F65: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateSystemEnvironmentValuesEx(
	IN ULONG InformationClass,
	OUT PVOID Buffer,
	IN OUT PULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x55C899BC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x55C899BC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x55C899BC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x55C899BC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_55C899BC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_55C899BC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_55C899BC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_55C899BC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_55C899BC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_55C899BC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateTransactionObject(
	IN HANDLE RootObjectHandle OPTIONAL,
	IN KTMOBJECT_TYPE QueryType,
	IN OUT PKTMOBJECT_CURSOR ObjectCursor,
	IN ULONG ObjectCursorLength,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C2736A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C2736A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C2736A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C2736A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0C2736A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C2736A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C2736A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C2736A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C2736A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C2736A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtExtendSection(
	IN HANDLE SectionHandle,
	IN OUT PLARGE_INTEGER NewSectionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA49346C3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA49346C3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA49346C3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA49346C3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A49346C3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A49346C3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A49346C3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A49346C3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A49346C3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A49346C3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFilterBootOption(
	IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
	IN ULONG ObjectType,
	IN ULONG ElementType,
	IN PVOID SystemData OPTIONAL,
	IN ULONG DataSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBC37926F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC37926F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC37926F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC37926F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BC37926F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC37926F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC37926F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC37926F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC37926F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC37926F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFilterToken(
	IN HANDLE ExistingTokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	OUT PHANDLE NewTokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x71D44774 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x71D44774 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x71D44774 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x71D44774 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_71D44774: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_71D44774 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_71D44774] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_71D44774 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_71D44774: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_71D44774: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFilterTokenEx(
	IN HANDLE TokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	IN ULONG DisableUserClaimsCount,
	IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
	IN ULONG DisableDeviceClaimsCount,
	IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
	OUT PHANDLE NewTokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x20A3E69D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x20A3E69D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x20A3E69D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x20A3E69D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xe \n"
	"push_argument_20A3E69D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_20A3E69D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_20A3E69D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_20A3E69D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_20A3E69D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_20A3E69D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushBuffersFileEx(
	IN HANDLE FileHandle,
	IN ULONG Flags,
	IN PVOID Parameters,
	IN ULONG ParametersSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC61D00A3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC61D00A3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC61D00A3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC61D00A3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C61D00A3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C61D00A3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C61D00A3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C61D00A3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C61D00A3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C61D00A3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushInstallUILanguage(
	IN LANGID InstallUILanguage,
	IN ULONG SetComittedFlag)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2D8EFC34 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2D8EFC34 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2D8EFC34 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2D8EFC34 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2D8EFC34: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2D8EFC34 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2D8EFC34] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2D8EFC34 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2D8EFC34: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2D8EFC34: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6DB64FFB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6DB64FFB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6DB64FFB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6DB64FFB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_6DB64FFB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6DB64FFB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6DB64FFB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6DB64FFB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6DB64FFB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6DB64FFB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushKey(
	IN HANDLE KeyHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26A43F24 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26A43F24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26A43F24 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26A43F24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_26A43F24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26A43F24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26A43F24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26A43F24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26A43F24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26A43F24: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushProcessWriteBuffers()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x603C64B4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x603C64B4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x603C64B4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x603C64B4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_603C64B4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_603C64B4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_603C64B4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_603C64B4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_603C64B4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_603C64B4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC85AD2DA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC85AD2DA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC85AD2DA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC85AD2DA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C85AD2DA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C85AD2DA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C85AD2DA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C85AD2DA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C85AD2DA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C85AD2DA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushWriteBuffer()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAB33D339 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB33D339 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB33D339 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB33D339 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_AB33D339: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB33D339 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB33D339] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB33D339 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB33D339: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB33D339: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreeUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	IN PULONG UserPfnArray)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x019E3A16 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x019E3A16 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x019E3A16 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x019E3A16 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_019E3A16: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_019E3A16 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_019E3A16] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_019E3A16 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_019E3A16: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_019E3A16: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreezeRegistry(
	IN ULONG TimeOutInSeconds)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x018F353C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x018F353C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x018F353C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x018F353C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_018F353C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_018F353C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_018F353C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_018F353C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_018F353C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_018F353C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreezeTransactions(
	IN PLARGE_INTEGER FreezeTimeout,
	IN PLARGE_INTEGER ThawTimeout)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x79E97D73 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x79E97D73 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x79E97D73 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x79E97D73 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_79E97D73: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_79E97D73 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_79E97D73] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_79E97D73 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_79E97D73: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_79E97D73: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCachedSigningLevel(
	IN HANDLE File,
	OUT PULONG Flags,
	OUT PSE_SIGNING_LEVEL SigningLevel,
	OUT PUCHAR Thumbprint OPTIONAL,
	IN OUT PULONG ThumbprintSize OPTIONAL,
	OUT PULONG ThumbprintAlgorithm OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5E9A5000 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5E9A5000 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5E9A5000 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5E9A5000 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_5E9A5000: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5E9A5000 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5E9A5000] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5E9A5000 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5E9A5000: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5E9A5000: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCompleteWnfStateSubscription(
	IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
	IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
	IN ULONG OldDescriptorEventMask OPTIONAL,
	IN ULONG OldDescriptorStatus OPTIONAL,
	OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
	IN ULONG DescriptorSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB46FD6FF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB46FD6FF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB46FD6FF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB46FD6FF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_B46FD6FF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B46FD6FF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B46FD6FF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B46FD6FF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B46FD6FF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B46FD6FF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x90B4D616 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x90B4D616 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x90B4D616 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x90B4D616 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_90B4D616: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_90B4D616 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_90B4D616] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_90B4D616 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_90B4D616: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_90B4D616: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCurrentProcessorNumber()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1EA37876 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EA37876 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EA37876 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EA37876 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_1EA37876: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EA37876 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EA37876] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EA37876 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EA37876: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EA37876: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCurrentProcessorNumberEx(
	OUT PULONG ProcNumber OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x52D4A0AE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x52D4A0AE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x52D4A0AE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x52D4A0AE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_52D4A0AE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_52D4A0AE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_52D4A0AE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_52D4A0AE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_52D4A0AE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_52D4A0AE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetDevicePowerState(
	IN HANDLE Device,
	OUT PDEVICE_POWER_STATE State)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDC93341C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC93341C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC93341C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC93341C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DC93341C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC93341C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC93341C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC93341C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC93341C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC93341C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetMUIRegistryInfo(
	IN ULONG Flags,
	IN OUT PULONG DataSize,
	OUT PVOID SystemData)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0647DA0B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0647DA0B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0647DA0B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0647DA0B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0647DA0B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0647DA0B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0647DA0B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0647DA0B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0647DA0B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0647DA0B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNextProcess(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFFA71237 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFFA71237 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFFA71237 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFFA71237 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_FFA71237: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FFA71237 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FFA71237] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FFA71237 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FFA71237: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FFA71237: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNextThread(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewThreadHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x74573E80 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x74573E80 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x74573E80 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x74573E80 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_74573E80: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_74573E80 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_74573E80] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_74573E80 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_74573E80: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_74573E80: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNlsSectionPtr(
	IN ULONG SectionType,
	IN ULONG SectionData,
	IN PVOID ContextData,
	OUT PVOID SectionPointer,
	OUT PULONG SectionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBED5BF4A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBED5BF4A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBED5BF4A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBED5BF4A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BED5BF4A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BED5BF4A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BED5BF4A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BED5BF4A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BED5BF4A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BED5BF4A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNotificationResourceManager(
	IN HANDLE ResourceManagerHandle,
	OUT PTRANSACTION_NOTIFICATION TransactionNotification,
	IN ULONG NotificationLength,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL,
	IN ULONG Asynchronous,
	IN ULONG AsynchronousContext OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x07A695BA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x07A695BA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x07A695BA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x07A695BA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_07A695BA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_07A695BA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_07A695BA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_07A695BA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_07A695BA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_07A695BA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetWriteWatch(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG RegionSize,
	OUT PULONG UserAddressArray,
	IN OUT PULONG EntriesInUserAddressArray,
	OUT PULONG Granularity)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x34814E52 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x34814E52 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x34814E52 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x34814E52 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_34814E52: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_34814E52 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_34814E52] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_34814E52 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_34814E52: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_34814E52: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtImpersonateAnonymousToken(
	IN HANDLE ThreadHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2396B097 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2396B097 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2396B097 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2396B097 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2396B097: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2396B097 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2396B097] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2396B097 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2396B097: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2396B097: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtImpersonateThread(
	IN HANDLE ServerThreadHandle,
	IN HANDLE ClientThreadHandle,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x046624F9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x046624F9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x046624F9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x046624F9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_046624F9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_046624F9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_046624F9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_046624F9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_046624F9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_046624F9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitializeEnclave(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x20BD0830 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x20BD0830 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x20BD0830 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x20BD0830 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_20BD0830: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_20BD0830 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_20BD0830] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_20BD0830 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_20BD0830: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_20BD0830: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitializeNlsFiles(
	OUT PVOID BaseAddress,
	OUT PLCID DefaultLocaleId,
	OUT PLARGE_INTEGER DefaultCasingTableSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x81378EB5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x81378EB5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x81378EB5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x81378EB5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_81378EB5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_81378EB5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_81378EB5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_81378EB5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_81378EB5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_81378EB5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitializeRegistry(
	IN USHORT BootCondition)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4C913275 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4C913275 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4C913275 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4C913275 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_4C913275: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4C913275 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4C913275] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4C913275 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4C913275: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4C913275: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitiatePowerAction(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE LightestSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF068107B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF068107B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF068107B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF068107B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F068107B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F068107B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F068107B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F068107B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F068107B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F068107B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtIsSystemResumeAutomatic()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x92C157E6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x92C157E6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x92C157E6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x92C157E6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_92C157E6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_92C157E6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_92C157E6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_92C157E6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_92C157E6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_92C157E6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtIsUILanguageComitted()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1BDD9DC7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1BDD9DC7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1BDD9DC7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1BDD9DC7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_1BDD9DC7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1BDD9DC7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1BDD9DC7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1BDD9DC7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1BDD9DC7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1BDD9DC7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtListenPort(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE ConnectionRequest)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x21332EA8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x21332EA8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x21332EA8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x21332EA8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_21332EA8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_21332EA8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_21332EA8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_21332EA8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_21332EA8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_21332EA8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadDriver(
	IN PUNICODE_STRING DriverServiceName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6EA7065E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6EA7065E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6EA7065E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6EA7065E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_6EA7065E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6EA7065E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6EA7065E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6EA7065E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6EA7065E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6EA7065E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadEnclaveData(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T BufferSize,
	IN ULONG Protect,
	IN PVOID PageInformation,
	IN ULONG PageInformationLength,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
	OUT PULONG EnclaveError OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x74C41618 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x74C41618 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x74C41618 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x74C41618 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_74C41618: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_74C41618 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_74C41618] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_74C41618 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_74C41618: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_74C41618: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadHotPatch(
	IN PUNICODE_STRING HotPatchName,
	IN ULONG LoadFlag)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2C5ED942 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2C5ED942 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2C5ED942 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2C5ED942 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2C5ED942: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2C5ED942 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2C5ED942] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2C5ED942 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2C5ED942: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2C5ED942: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadKey(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7EEF111F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7EEF111F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7EEF111F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7EEF111F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7EEF111F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7EEF111F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7EEF111F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7EEF111F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7EEF111F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7EEF111F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x61918886 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x61918886 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x61918886 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x61918886 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_61918886: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_61918886 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_61918886] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_61918886 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_61918886: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_61918886: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	OUT PHANDLE RootHandle OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatus OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE7F1A32D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE7F1A32D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE7F1A32D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE7F1A32D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_E7F1A32D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E7F1A32D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E7F1A32D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E7F1A32D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E7F1A32D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E7F1A32D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key,
	IN BOOLEAN FailImmediately,
	IN BOOLEAN ExclusiveLock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2CBE5DA8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2CBE5DA8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2CBE5DA8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2CBE5DA8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_2CBE5DA8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2CBE5DA8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2CBE5DA8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2CBE5DA8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2CBE5DA8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2CBE5DA8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockProductActivationKeys(
	IN OUT PULONG pPrivateVer OPTIONAL,
	OUT PULONG pSafeMode OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAF0BB888 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAF0BB888 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAF0BB888 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAF0BB888 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_AF0BB888: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AF0BB888 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AF0BB888] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AF0BB888 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AF0BB888: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AF0BB888: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockRegistryKey(
	IN HANDLE KeyHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD720EA94 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD720EA94 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD720EA94 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD720EA94 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_D720EA94: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D720EA94 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D720EA94] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D720EA94 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D720EA94: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D720EA94: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG RegionSize,
	IN ULONG MapType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x01994F5F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01994F5F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01994F5F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01994F5F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_01994F5F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01994F5F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01994F5F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01994F5F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01994F5F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01994F5F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMakePermanentObject(
	IN HANDLE Handle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9EB1A6FD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9EB1A6FD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9EB1A6FD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9EB1A6FD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9EB1A6FD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9EB1A6FD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9EB1A6FD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9EB1A6FD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9EB1A6FD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9EB1A6FD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMakeTemporaryObject(
	IN HANDLE Handle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8A297B44 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A297B44 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A297B44 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A297B44 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_8A297B44: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A297B44 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A297B44] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A297B44 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A297B44: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A297B44: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtManagePartition(
	IN HANDLE TargetHandle,
	IN HANDLE SourceHandle,
	IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
	IN OUT PVOID PartitionInformation,
	IN ULONG PartitionInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC871F631 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC871F631 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC871F631 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC871F631 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C871F631: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C871F631 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C871F631] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C871F631 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C871F631: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C871F631: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapCMFModule(
	IN ULONG What,
	IN ULONG Index,
	OUT PULONG CacheIndexOut OPTIONAL,
	OUT PULONG CacheFlagsOut OPTIONAL,
	OUT PULONG ViewSizeOut OPTIONAL,
	OUT PVOID BaseAddress OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD678EEFE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD678EEFE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD678EEFE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD678EEFE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_D678EEFE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D678EEFE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D678EEFE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D678EEFE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D678EEFE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D678EEFE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapUserPhysicalPages(
	IN PVOID VirtualAddress,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0BB33438 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BB33438 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BB33438 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BB33438 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0BB33438: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BB33438 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BB33438] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BB33438 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BB33438: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BB33438: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PPVOID BaseAddress,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Protect,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDB5BEFE0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB5BEFE0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB5BEFE0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB5BEFE0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_DB5BEFE0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB5BEFE0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB5BEFE0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB5BEFE0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB5BEFE0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB5BEFE0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtModifyBootEntry(
	IN PBOOT_ENTRY BootEntry)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF955E1F2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF955E1F2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF955E1F2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF955E1F2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_F955E1F2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F955E1F2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F955E1F2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F955E1F2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F955E1F2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F955E1F2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtModifyDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC151D5DC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC151D5DC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC151D5DC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC151D5DC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C151D5DC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C151D5DC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C151D5DC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C151D5DC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C151D5DC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C151D5DC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_NOTIFY_INFORMATION Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x73D95B0C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x73D95B0C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x73D95B0C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x73D95B0C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_73D95B0C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_73D95B0C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_73D95B0C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_73D95B0C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_73D95B0C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_73D95B0C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26D2ECE0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26D2ECE0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26D2ECE0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26D2ECE0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_26D2ECE0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26D2ECE0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26D2ECE0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26D2ECE0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26D2ECE0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26D2ECE0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeKey(
	IN HANDLE KeyHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9DD973BF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9DD973BF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9DD973BF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9DD973BF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_9DD973BF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9DD973BF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9DD973BF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9DD973BF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9DD973BF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9DD973BF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeMultipleKeys(
	IN HANDLE MasterKeyHandle,
	IN ULONG Count OPTIONAL,
	IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4E96553F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4E96553F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4E96553F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4E96553F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xc \n"
	"push_argument_4E96553F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4E96553F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4E96553F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4E96553F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4E96553F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4E96553F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeSession(
	IN HANDLE SessionHandle,
	IN ULONG ChangeSequenceNumber,
	IN PLARGE_INTEGER ChangeTimeStamp,
	IN IO_SESSION_EVENT Event,
	IN IO_SESSION_STATE NewState,
	IN IO_SESSION_STATE PreviousState,
	IN PVOID Payload OPTIONAL,
	IN ULONG PayloadSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8B20AFEA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B20AFEA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B20AFEA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B20AFEA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_8B20AFEA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B20AFEA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B20AFEA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B20AFEA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B20AFEA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B20AFEA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN LPGUID EnlistmentGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6E551C53 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6E551C53 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6E551C53 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6E551C53 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_6E551C53: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6E551C53 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6E551C53] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6E551C53 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6E551C53: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6E551C53: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x223E2CA2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x223E2CA2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x223E2CA2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x223E2CA2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_223E2CA2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_223E2CA2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_223E2CA2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_223E2CA2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_223E2CA2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_223E2CA2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06F067E7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06F067E7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06F067E7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06F067E7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_06F067E7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06F067E7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06F067E7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06F067E7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06F067E7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06F067E7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7AAA5477 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7AAA5477 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7AAA5477 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7AAA5477 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7AAA5477: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7AAA5477 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7AAA5477] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7AAA5477 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7AAA5477: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7AAA5477: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5DEB1738 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5DEB1738 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5DEB1738 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5DEB1738 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_5DEB1738: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5DEB1738 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5DEB1738] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5DEB1738 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5DEB1738: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5DEB1738: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE TransactionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x32BD3002 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x32BD3002 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x32BD3002 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x32BD3002 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_32BD3002: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_32BD3002 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_32BD3002] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_32BD3002 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_32BD3002: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_32BD3002: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyTransactedEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions,
	IN HANDLE TransactionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA6BEF464 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA6BEF464 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA6BEF464 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA6BEF464 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A6BEF464: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A6BEF464 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A6BEF464] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A6BEF464 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A6BEF464: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A6BEF464: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06810112 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06810112 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06810112 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06810112 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_06810112: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06810112 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06810112] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06810112 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06810112: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06810112: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x82886ADD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x82886ADD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x82886ADD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x82886ADD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_82886ADD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_82886ADD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_82886ADD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_82886ADD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_82886ADD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_82886ADD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN ACCESS_MASK GrantedAccess,
	IN PPRIVILEGE_SET Privileges OPTIONAL,
	IN BOOLEAN ObjectCreation,
	IN BOOLEAN AccessGranted,
	OUT PBOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6A96044A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6A96044A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6A96044A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6A96044A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xc \n"
	"push_argument_6A96044A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6A96044A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6A96044A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6A96044A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6A96044A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6A96044A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenPartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDA83E4CF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDA83E4CF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDA83E4CF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDA83E4CF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DA83E4CF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DA83E4CF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DA83E4CF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DA83E4CF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DA83E4CF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DA83E4CF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenPrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PVOID BoundaryDescriptor)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1EB75B17 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EB75B17 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EB75B17 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EB75B17 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1EB75B17: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EB75B17 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EB75B17] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EB75B17 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EB75B17: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EB75B17: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x439D3784 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x439D3784 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x439D3784 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x439D3784 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_439D3784: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_439D3784 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_439D3784] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_439D3784 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_439D3784: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_439D3784: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenRegistryTransaction(
	OUT PHANDLE RegistryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x66CE665D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x66CE665D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x66CE665D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x66CE665D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_66CE665D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_66CE665D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_66CE665D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_66CE665D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_66CE665D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_66CE665D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID ResourceManagerGuid OPTIONAL,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB3A7A92B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB3A7A92B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB3A7A92B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB3A7A92B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_B3A7A92B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B3A7A92B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B3A7A92B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B3A7A92B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B3A7A92B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B3A7A92B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0299D2A4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0299D2A4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0299D2A4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0299D2A4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0299D2A4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0299D2A4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0299D2A4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0299D2A4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0299D2A4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0299D2A4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSession(
	OUT PHANDLE SessionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x481F4E8A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x481F4E8A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x481F4E8A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x481F4E8A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_481F4E8A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_481F4E8A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_481F4E8A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_481F4E8A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_481F4E8A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_481F4E8A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8F231900 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8F231900 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8F231900 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8F231900 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8F231900: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8F231900 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8F231900] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8F231900 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8F231900: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8F231900: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x80AC0586 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x80AC0586 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x80AC0586 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x80AC0586 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_80AC0586: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_80AC0586 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_80AC0586] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_80AC0586 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_80AC0586: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_80AC0586: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0DAD588A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0DAD588A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0DAD588A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0DAD588A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0DAD588A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0DAD588A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0DAD588A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0DAD588A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0DAD588A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0DAD588A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN LPGUID Uow,
	IN HANDLE TmHandle OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF8A3FE33 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF8A3FE33 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF8A3FE33 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF8A3FE33 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_F8A3FE33: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F8A3FE33 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F8A3FE33] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F8A3FE33 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F8A3FE33: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F8A3FE33: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN LPGUID TmIdentity OPTIONAL,
	IN ULONG OpenOptions OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0EB7909F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0EB7909F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0EB7909F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0EB7909F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0EB7909F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0EB7909F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0EB7909F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0EB7909F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0EB7909F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0EB7909F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPlugPlayControl(
	IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
	IN OUT PVOID PnPControlData,
	IN ULONG PnPControlDataLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x825D7E14 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x825D7E14 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x825D7E14 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x825D7E14 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_825D7E14: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_825D7E14 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_825D7E14] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_825D7E14 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_825D7E14: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_825D7E14: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrePrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3AA7D424 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3AA7D424 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3AA7D424 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3AA7D424 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3AA7D424: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3AA7D424 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3AA7D424] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3AA7D424 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3AA7D424: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3AA7D424: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrePrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x195504DF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x195504DF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x195504DF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x195504DF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_195504DF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_195504DF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_195504DF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_195504DF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_195504DF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_195504DF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x67385794 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x67385794 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x67385794 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x67385794 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_67385794: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_67385794 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_67385794] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_67385794 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_67385794: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_67385794: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x89158C83 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x89158C83 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x89158C83 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x89158C83 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_89158C83: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_89158C83 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_89158C83] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_89158C83 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_89158C83: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_89158C83: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrivilegeCheck(
	IN HANDLE ClientToken,
	IN OUT PPRIVILEGE_SET RequiredPrivileges,
	OUT PBOOLEAN Result)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7CA46F1D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7CA46F1D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7CA46F1D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7CA46F1D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7CA46F1D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7CA46F1D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7CA46F1D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7CA46F1D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7CA46F1D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7CA46F1D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrivilegeObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1AA52A28 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1AA52A28 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1AA52A28 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1AA52A28 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1AA52A28: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1AA52A28 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1AA52A28] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1AA52A28 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1AA52A28: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1AA52A28: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrivilegedServiceAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PUNICODE_STRING ServiceName,
	IN HANDLE ClientToken,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x56D25244 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x56D25244 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x56D25244 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x56D25244 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_56D25244: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_56D25244 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_56D25244] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_56D25244 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_56D25244: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_56D25244: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPropagationComplete(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN ULONG BufferLength,
	IN PVOID Buffer)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x45087456 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x45087456 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x45087456 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x45087456 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_45087456: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_45087456 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_45087456] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_45087456 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_45087456: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_45087456: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPropagationFailed(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN NTSTATUS PropStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7ED93A00 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7ED93A00 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7ED93A00 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7ED93A00 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7ED93A00: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7ED93A00 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7ED93A00] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7ED93A00 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7ED93A00: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7ED93A00: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPulseEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1249339C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1249339C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1249339C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1249339C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1249339C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1249339C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1249339C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1249339C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1249339C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1249339C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryAuxiliaryCounterFrequency(
	OUT PULONGLONG lpAuxiliaryCounterFrequency)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7CDBE8C6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7CDBE8C6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7CDBE8C6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7CDBE8C6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_7CDBE8C6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7CDBE8C6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7CDBE8C6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7CDBE8C6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7CDBE8C6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7CDBE8C6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryBootEntryOrder(
	OUT PULONG Ids OPTIONAL,
	IN OUT PULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x98348C56 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x98348C56 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x98348C56 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x98348C56 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_98348C56: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_98348C56 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_98348C56] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_98348C56 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_98348C56: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_98348C56: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryBootOptions(
	OUT PBOOT_OPTIONS BootOptions OPTIONAL,
	IN OUT PULONG BootOptionsLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8B186D73 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B186D73 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B186D73 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B186D73 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_8B186D73: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B186D73 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B186D73] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B186D73 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B186D73: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B186D73: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2CB25C5C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2CB25C5C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2CB25C5C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2CB25C5C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2CB25C5C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2CB25C5C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2CB25C5C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2CB25C5C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2CB25C5C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2CB25C5C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x609BA3E0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x609BA3E0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x609BA3E0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x609BA3E0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_609BA3E0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_609BA3E0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_609BA3E0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_609BA3E0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_609BA3E0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_609BA3E0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAA95BA19 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAA95BA19 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAA95BA19 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAA95BA19 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_AA95BA19: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AA95BA19 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AA95BA19] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AA95BA19 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AA95BA19: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AA95BA19: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDriverEntryOrder(
	IN PULONG Ids OPTIONAL,
	IN OUT PULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x63462593 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x63462593 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63462593 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63462593 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_63462593: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63462593 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63462593] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63462593 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63462593: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63462593: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_FULL_EA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
	IN ULONG EaListLength,
	IN PULONG EaIndex OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4CDDBA40 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4CDDBA40 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4CDDBA40 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4CDDBA40 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_4CDDBA40: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4CDDBA40 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4CDDBA40] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4CDDBA40 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4CDDBA40: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4CDDBA40: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryFullAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x22B80FFE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22B80FFE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22B80FFE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22B80FFE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_22B80FFE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22B80FFE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22B80FFE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22B80FFE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22B80FFE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22B80FFE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationAtom(
	IN USHORT Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x743A68B3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x743A68B3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x743A68B3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x743A68B3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_743A68B3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_743A68B3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_743A68B3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_743A68B3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_743A68B3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_743A68B3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7CD06373 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7CD06373 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7CD06373 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7CD06373 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_7CD06373: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7CD06373 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7CD06373] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7CD06373 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7CD06373: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7CD06373: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	OUT PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F82E0F1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F82E0F1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F82E0F1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F82E0F1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1F82E0F1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F82E0F1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F82E0F1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F82E0F1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F82E0F1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F82E0F1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	OUT PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBC9E2492 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC9E2492 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC9E2492 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC9E2492 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BC9E2492: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC9E2492 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC9E2492] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC9E2492 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC9E2492: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC9E2492: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationPort(
	IN HANDLE PortHandle,
	IN PORT_INFORMATION_CLASS PortInformationClass,
	OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAC32A9AC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAC32A9AC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAC32A9AC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAC32A9AC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_AC32A9AC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AC32A9AC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AC32A9AC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AC32A9AC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AC32A9AC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AC32A9AC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	OUT PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBB232322 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBB232322 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBB232322 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBB232322 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BB232322: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BB232322 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BB232322] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BB232322 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BB232322: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BB232322: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	OUT PVOID TransactionInformation,
	IN ULONG TransactionInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9E09DADB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9E09DADB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9E09DADB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9E09DADB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_9E09DADB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9E09DADB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9E09DADB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9E09DADB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9E09DADB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9E09DADB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
	OUT PVOID TransactionManagerInformation,
	IN ULONG TransactionManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D969F8A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D969F8A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D969F8A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D969F8A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0D969F8A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D969F8A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D969F8A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D969F8A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D969F8A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D969F8A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	OUT PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9A91F676 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9A91F676 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9A91F676 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9A91F676 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_9A91F676: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9A91F676 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9A91F676] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9A91F676 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9A91F676: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9A91F676: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInstallUILanguage(
	OUT PLANGID InstallUILanguageId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3F98DCC4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3F98DCC4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3F98DCC4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3F98DCC4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3F98DCC4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3F98DCC4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3F98DCC4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3F98DCC4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3F98DCC4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3F98DCC4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryIntervalProfile(
	IN KPROFILE_SOURCE ProfileSource,
	OUT PULONG Interval)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C905E24 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C905E24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C905E24 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C905E24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0C905E24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C905E24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C905E24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C905E24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C905E24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C905E24: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	OUT PVOID IoCompletionInformation,
	IN ULONG IoCompletionInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8A906984 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A906984 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A906984 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A906984 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8A906984: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A906984 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A906984] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A906984 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A906984: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A906984: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryLicenseValue(
	IN PUNICODE_STRING ValueName,
	OUT PULONG Type OPTIONAL,
	OUT PVOID SystemData OPTIONAL,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC930B4F3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC930B4F3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC930B4F3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC930B4F3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C930B4F3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C930B4F3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C930B4F3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C930B4F3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C930B4F3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C930B4F3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryMultipleValueKey(
	IN HANDLE KeyHandle,
	IN OUT PKEY_VALUE_ENTRY ValueEntries,
	IN ULONG EntryCount,
	OUT PVOID ValueBuffer,
	IN PULONG BufferLength,
	OUT PULONG RequiredBufferLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAA62D594 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAA62D594 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAA62D594 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAA62D594 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_AA62D594: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AA62D594 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AA62D594] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AA62D594 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AA62D594: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AA62D594: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryMutant(
	IN HANDLE MutantHandle,
	IN MUTANT_INFORMATION_CLASS MutantInformationClass,
	OUT PVOID MutantInformation,
	IN ULONG MutantInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x163359E0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x163359E0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x163359E0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x163359E0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_163359E0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_163359E0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_163359E0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_163359E0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_163359E0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_163359E0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryOpenSubKeys(
	IN POBJECT_ATTRIBUTES TargetKey,
	OUT PULONG HandleCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4A99B9FF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4A99B9FF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4A99B9FF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4A99B9FF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4A99B9FF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4A99B9FF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4A99B9FF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4A99B9FF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4A99B9FF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4A99B9FF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	OUT PVOID Buffer,
	OUT PULONG RequiredSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0B673DD8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0B673DD8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0B673DD8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0B673DD8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0B673DD8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0B673DD8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0B673DD8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0B673DD8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0B673DD8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0B673DD8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryPortInformationProcess()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x772C96B0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x772C96B0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x772C96B0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x772C96B0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_772C96B0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_772C96B0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_772C96B0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_772C96B0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_772C96B0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_772C96B0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
	IN ULONG SidListLength,
	IN PSID StartSid OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x198E5F33 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x198E5F33 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x198E5F33 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x198E5F33 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_198E5F33: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_198E5F33 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_198E5F33] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_198E5F33 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_198E5F33: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_198E5F33: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySecurityAttributesToken(
	IN HANDLE TokenHandle,
	IN PUNICODE_STRING Attributes OPTIONAL,
	IN ULONG NumberOfAttributes,
	OUT PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x05970D0C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x05970D0C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x05970D0C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x05970D0C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_05970D0C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_05970D0C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_05970D0C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_05970D0C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_05970D0C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_05970D0C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySecurityObject(
	IN HANDLE Handle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN ULONG Length,
	OUT PULONG LengthNeeded)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDCC4B4D8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDCC4B4D8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDCC4B4D8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDCC4B4D8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_DCC4B4D8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DCC4B4D8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DCC4B4D8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DCC4B4D8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DCC4B4D8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DCC4B4D8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySecurityPolicy(
	IN ULONG_PTR UnknownParameter1,
	IN ULONG_PTR UnknownParameter2,
	IN ULONG_PTR UnknownParameter3,
	IN ULONG_PTR UnknownParameter4,
	IN ULONG_PTR UnknownParameter5,
	IN ULONG_PTR UnknownParameter6)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8294F568 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8294F568 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8294F568 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8294F568 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8294F568: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8294F568 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8294F568] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8294F568 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8294F568: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8294F568: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySemaphore(
	IN HANDLE SemaphoreHandle,
	IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	OUT PVOID SemaphoreInformation,
	IN ULONG SemaphoreInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38AB0034 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38AB0034 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38AB0034 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38AB0034 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_38AB0034: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38AB0034 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38AB0034] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38AB0034 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38AB0034: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38AB0034: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySymbolicLinkObject(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x88A863D4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x88A863D4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x88A863D4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x88A863D4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_88A863D4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_88A863D4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_88A863D4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_88A863D4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_88A863D4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_88A863D4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	OUT PVOID VariableValue,
	IN ULONG ValueLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6AAD6D02 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6AAD6D02 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6AAD6D02 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6AAD6D02 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_6AAD6D02: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6AAD6D02 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6AAD6D02] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6AAD6D02 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6AAD6D02: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6AAD6D02: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	OUT PVOID Value OPTIONAL,
	IN OUT PULONG ValueLength,
	OUT PULONG Attributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x87AF44EB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x87AF44EB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x87AF44EB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x87AF44EB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_87AF44EB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_87AF44EB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_87AF44EB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_87AF44EB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_87AF44EB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_87AF44EB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemInformationEx(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0092D3C9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0092D3C9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0092D3C9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0092D3C9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0092D3C9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0092D3C9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0092D3C9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0092D3C9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0092D3C9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0092D3C9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryTimerResolution(
	OUT PULONG MaximumTime,
	OUT PULONG MinimumTime,
	OUT PULONG CurrentTime)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4ADC4A4F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4ADC4A4F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4ADC4A4F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4ADC4A4F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_4ADC4A4F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4ADC4A4F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4ADC4A4F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4ADC4A4F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4ADC4A4F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4ADC4A4F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PWNF_CHANGE_STAMP ChangeStamp,
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA3CC955A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA3CC955A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA3CC955A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA3CC955A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_A3CC955A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A3CC955A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A3CC955A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A3CC955A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A3CC955A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A3CC955A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryWnfStateNameInformation(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID NameInfoClass,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PVOID InfoBuffer,
	IN ULONG InfoBufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA643D8A3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA643D8A3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA643D8A3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA643D8A3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A643D8A3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A643D8A3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A643D8A3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A643D8A3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A643D8A3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A643D8A3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN HANDLE UserApcReserveHandle OPTIONAL,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2D35F868 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2D35F868 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2D35F868 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2D35F868 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2D35F868: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2D35F868 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2D35F868] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2D35F868 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2D35F868: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2D35F868: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRaiseException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN BOOLEAN FirstChance)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9E359CA1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9E359CA1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9E359CA1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9E359CA1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_9E359CA1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9E359CA1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9E359CA1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9E359CA1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9E359CA1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9E359CA1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRaiseHardError(
	IN NTSTATUS ErrorStatus,
	IN ULONG NumberOfParameters,
	IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters,
	IN ULONG ValidResponseOptions,
	OUT PULONG Response)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x838EFF65 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x838EFF65 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x838EFF65 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x838EFF65 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_838EFF65: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_838EFF65 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_838EFF65] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_838EFF65 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_838EFF65: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_838EFF65: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadOnlyEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xEFB68865 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEFB68865 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEFB68865 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEFB68865 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_EFB68865: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EFB68865 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EFB68865] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EFB68865 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EFB68865: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EFB68865: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRecoverEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PVOID EnlistmentKey OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x19FF1869 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x19FF1869 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x19FF1869 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x19FF1869 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_19FF1869: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_19FF1869 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_19FF1869] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_19FF1869 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_19FF1869: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_19FF1869: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRecoverResourceManager(
	IN HANDLE ResourceManagerHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA1B03D99 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA1B03D99 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA1B03D99 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA1B03D99 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A1B03D99: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A1B03D99 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A1B03D99] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A1B03D99 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A1B03D99: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A1B03D99: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRecoverTransactionManager(
	IN HANDLE TransactionManagerHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8526B386 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8526B386 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8526B386 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8526B386 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_8526B386: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8526B386 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8526B386] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8526B386 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8526B386: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8526B386: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRegisterProtocolAddressInformation(
	IN HANDLE ResourceManager,
	IN LPGUID ProtocolId,
	IN ULONG ProtocolInformationSize,
	IN PVOID ProtocolInformation,
	IN ULONG CreateOptions OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x64CD6651 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64CD6651 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64CD6651 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64CD6651 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_64CD6651: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64CD6651 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64CD6651] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64CD6651 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64CD6651: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64CD6651: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRegisterThreadTerminatePort(
	IN HANDLE PortHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAAF39BBE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAAF39BBE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAAF39BBE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAAF39BBE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AAF39BBE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AAF39BBE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AAF39BBE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AAF39BBE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AAF39BBE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AAF39BBE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID KeyValue,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x36B83F2C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36B83F2C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36B83F2C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36B83F2C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_36B83F2C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36B83F2C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36B83F2C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36B83F2C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36B83F2C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36B83F2C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseWorkerFactoryWorker(
	IN HANDLE WorkerFactoryHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFB40D590 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFB40D590 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFB40D590 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFB40D590 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_FB40D590: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FB40D590 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FB40D590] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FB40D590 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FB40D590: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FB40D590: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRemoveIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	IN ULONG Count,
	OUT PULONG NumEntriesRemoved,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN BOOLEAN Alertable)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8496C268 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8496C268 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8496C268 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8496C268 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8496C268: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8496C268 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8496C268] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8496C268 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8496C268: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8496C268: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC23E3174 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC23E3174 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC23E3174 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC23E3174 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C23E3174: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C23E3174 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C23E3174] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C23E3174 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C23E3174: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C23E3174: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRenameKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6BF89C80 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6BF89C80 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6BF89C80 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6BF89C80 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6BF89C80: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6BF89C80 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6BF89C80] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6BF89C80 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6BF89C80: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6BF89C80: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRenameTransactionManager(
	IN PUNICODE_STRING LogFileName,
	IN LPGUID ExistingTransactionManagerGuid)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1FDF0F5E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1FDF0F5E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1FDF0F5E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1FDF0F5E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1FDF0F5E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1FDF0F5E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1FDF0F5E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1FDF0F5E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1FDF0F5E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1FDF0F5E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplaceKey(
	IN POBJECT_ATTRIBUTES NewFile,
	IN HANDLE TargetHandle,
	IN POBJECT_ATTRIBUTES OldFile)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1D2F6ED6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1D2F6ED6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1D2F6ED6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1D2F6ED6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1D2F6ED6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1D2F6ED6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1D2F6ED6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1D2F6ED6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1D2F6ED6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1D2F6ED6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplacePartitionUnit(
	IN PUNICODE_STRING TargetInstancePath,
	IN PUNICODE_STRING SpareInstancePath,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38AA0A6C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38AA0A6C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38AA0A6C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38AA0A6C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_38AA0A6C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38AA0A6C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38AA0A6C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38AA0A6C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38AA0A6C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38AA0A6C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyWaitReplyPort(
	IN HANDLE PortHandle,
	IN OUT PPORT_MESSAGE ReplyMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF972FAFD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF972FAFD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF972FAFD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF972FAFD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F972FAFD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F972FAFD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F972FAFD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F972FAFD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F972FAFD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F972FAFD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26B13D3E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26B13D3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26B13D3E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26B13D3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_26B13D3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26B13D3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26B13D3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26B13D3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26B13D3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26B13D3E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x318B241D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x318B241D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x318B241D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x318B241D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_318B241D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_318B241D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_318B241D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_318B241D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_318B241D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_318B241D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResetWriteWatch(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG RegionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04AB784E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04AB784E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04AB784E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04AB784E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_04AB784E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04AB784E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04AB784E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04AB784E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04AB784E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04AB784E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRestoreKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFAEFD945 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFAEFD945 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFAEFD945 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFAEFD945 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FAEFD945: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FAEFD945 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FAEFD945] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FAEFD945 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FAEFD945: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FAEFD945: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResumeProcess(
	IN HANDLE ProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC119E0B4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC119E0B4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC119E0B4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC119E0B4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C119E0B4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C119E0B4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C119E0B4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C119E0B4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C119E0B4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C119E0B4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRevertContainerImpersonation()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E91FC9D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E91FC9D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E91FC9D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E91FC9D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_1E91FC9D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E91FC9D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E91FC9D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E91FC9D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E91FC9D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E91FC9D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x769380C0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x769380C0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x769380C0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x769380C0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_769380C0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_769380C0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_769380C0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_769380C0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_769380C0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_769380C0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x20BD3F3E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x20BD3F3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x20BD3F3E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x20BD3F3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_20BD3F3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_20BD3F3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_20BD3F3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_20BD3F3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_20BD3F3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_20BD3F3E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7CA1600B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7CA1600B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7CA1600B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7CA1600B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7CA1600B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7CA1600B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7CA1600B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7CA1600B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7CA1600B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7CA1600B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F97FF05 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F97FF05 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F97FF05 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F97FF05 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1F97FF05: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F97FF05 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F97FF05] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F97FF05 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F97FF05: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F97FF05: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollforwardTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1C216EC2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C216EC2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C216EC2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C216EC2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1C216EC2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C216EC2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C216EC2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C216EC2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C216EC2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C216EC2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSaveKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7DCB5C50 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7DCB5C50 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7DCB5C50 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7DCB5C50 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7DCB5C50: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7DCB5C50 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7DCB5C50] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7DCB5C50 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7DCB5C50: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7DCB5C50: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSaveKeyEx(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Format)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5B99176C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5B99176C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5B99176C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5B99176C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_5B99176C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5B99176C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5B99176C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5B99176C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5B99176C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5B99176C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSaveMergedKeys(
	IN HANDLE HighPrecedenceKeyHandle,
	IN HANDLE LowPrecedenceKeyHandle,
	IN HANDLE FileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x79C57246 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x79C57246 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x79C57246 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x79C57246 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_79C57246: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_79C57246 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_79C57246] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_79C57246 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_79C57246: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_79C57246: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSecureConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26375DB8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26375DB8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26375DB8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26375DB8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_26375DB8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26375DB8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26375DB8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26375DB8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26375DB8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26375DB8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSerializeBoot()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x52C25459 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x52C25459 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x52C25459 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x52C25459 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_52C25459: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_52C25459 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_52C25459] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_52C25459 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_52C25459: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_52C25459: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetBootEntryOrder(
	IN PULONG Ids,
	IN ULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x950B7619 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x950B7619 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x950B7619 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x950B7619 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_950B7619: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_950B7619 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_950B7619] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_950B7619 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_950B7619: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_950B7619: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetBootOptions(
	IN PBOOT_OPTIONS BootOptions,
	IN ULONG FieldsToChange)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x059D0B05 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x059D0B05 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x059D0B05 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x059D0B05 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_059D0B05: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_059D0B05 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_059D0B05] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_059D0B05 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_059D0B05: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_059D0B05: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetCachedSigningLevel(
	IN ULONG Flags,
	IN SE_SIGNING_LEVEL InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF271F6EE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF271F6EE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF271F6EE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF271F6EE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_F271F6EE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F271F6EE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F271F6EE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F271F6EE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F271F6EE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F271F6EE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetCachedSigningLevel2(
	IN ULONG Flags,
	IN ULONG InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL,
	IN PVOID LevelInformation OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1C83B518 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C83B518 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C83B518 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C83B518 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1C83B518: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C83B518 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C83B518] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C83B518 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C83B518: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C83B518: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF45F3A0D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF45F3A0D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF45F3A0D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF45F3A0D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F45F3A0D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F45F3A0D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F45F3A0D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F45F3A0D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F45F3A0D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F45F3A0D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFE552C6A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFE552C6A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFE552C6A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFE552C6A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FE552C6A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FE552C6A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FE552C6A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FE552C6A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FE552C6A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FE552C6A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDefaultHardErrorPort(
	IN HANDLE PortHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA1332629 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA1332629 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA1332629 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA1332629 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A1332629: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A1332629 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A1332629] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A1332629 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A1332629: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A1332629: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDefaultLocale(
	IN BOOLEAN UserProfile,
	IN LCID DefaultLocaleId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE1BE9369 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE1BE9369 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE1BE9369 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE1BE9369 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E1BE9369: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E1BE9369 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E1BE9369] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E1BE9369 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E1BE9369: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E1BE9369: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDefaultUILanguage(
	IN LANGID DefaultUILanguageId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAF8C98DC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAF8C98DC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAF8C98DC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAF8C98DC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AF8C98DC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AF8C98DC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AF8C98DC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AF8C98DC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AF8C98DC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AF8C98DC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDriverEntryOrder(
	IN PULONG Ids,
	IN PULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8F8D9D01 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8F8D9D01 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8F8D9D01 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8F8D9D01 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_8F8D9D01: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8F8D9D01 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8F8D9D01] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8F8D9D01 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8F8D9D01: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8F8D9D01: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_FULL_EA_INFORMATION EaBuffer,
	IN ULONG EaBufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA8E351B7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA8E351B7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA8E351B7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA8E351B7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_A8E351B7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A8E351B7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A8E351B7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A8E351B7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A8E351B7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A8E351B7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetHighEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x421E4C82 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x421E4C82 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x421E4C82 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x421E4C82 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_421E4C82: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_421E4C82 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_421E4C82] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_421E4C82 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_421E4C82: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_421E4C82: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetHighWaitLowEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x36114AE3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36114AE3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36114AE3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36114AE3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_36114AE3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36114AE3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36114AE3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36114AE3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36114AE3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36114AE3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIRTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x80106C43 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x80106C43 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x80106C43 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x80106C43 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_80106C43: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_80106C43 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_80106C43] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_80106C43 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_80106C43: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_80106C43: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationDebugObject(
	IN HANDLE DebugObject,
	IN DEBUGOBJECTINFOCLASS InformationClass,
	IN PVOID Information,
	IN ULONG InformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x08AA3009 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08AA3009 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08AA3009 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08AA3009 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_08AA3009: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08AA3009 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08AA3009] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08AA3009 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08AA3009: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08AA3009: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	IN PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x973CAE91 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x973CAE91 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x973CAE91 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x973CAE91 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_973CAE91: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_973CAE91 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_973CAE91] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_973CAE91 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_973CAE91: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_973CAE91: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	IN PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3D16099D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3D16099D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3D16099D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3D16099D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3D16099D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3D16099D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3D16099D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3D16099D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3D16099D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3D16099D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationKey(
	IN HANDLE KeyHandle,
	IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	IN PVOID KeySetInformation,
	IN ULONG KeySetInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x77D24E61 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x77D24E61 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x77D24E61 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x77D24E61 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_77D24E61: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_77D24E61 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_77D24E61] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_77D24E61 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_77D24E61: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_77D24E61: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	IN PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0F2E1F8D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0F2E1F8D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0F2E1F8D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0F2E1F8D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0F2E1F8D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0F2E1F8D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0F2E1F8D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0F2E1F8D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0F2E1F8D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0F2E1F8D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationSymbolicLink(
	IN HANDLE Handle,
	IN ULONG Class,
	IN PVOID Buffer,
	IN ULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6EFD4C64 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6EFD4C64 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6EFD4C64 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6EFD4C64 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_6EFD4C64: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6EFD4C64 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6EFD4C64] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6EFD4C64 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6EFD4C64: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6EFD4C64: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID TokenInformation,
	IN ULONG TokenInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC96C3F64 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC96C3F64 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC96C3F64 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC96C3F64 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C96C3F64: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C96C3F64 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C96C3F64] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C96C3F64 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C96C3F64: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C96C3F64: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x32AB543B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x32AB543B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x32AB543B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x32AB543B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_32AB543B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_32AB543B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_32AB543B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_32AB543B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_32AB543B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_32AB543B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationTransactionManager(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x19AC6B20 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x19AC6B20 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x19AC6B20 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x19AC6B20 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_19AC6B20: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_19AC6B20 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_19AC6B20] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_19AC6B20 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_19AC6B20: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_19AC6B20: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationVirtualMemory(
	IN HANDLE ProcessHandle,
	IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	IN ULONG_PTR NumberOfEntries,
	IN PMEMORY_RANGE_ENTRY VirtualAddresses,
	IN PVOID VmInformation,
	IN ULONG VmInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x27962F17 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x27962F17 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x27962F17 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x27962F17 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_27962F17: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_27962F17 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_27962F17] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_27962F17 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_27962F17: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_27962F17: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	IN PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06177AD2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06177AD2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06177AD2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06177AD2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_06177AD2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06177AD2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06177AD2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06177AD2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06177AD2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06177AD2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIntervalProfile(
	IN ULONG Interval,
	IN KPROFILE_SOURCE Source)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFEBEE13A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFEBEE13A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFEBEE13A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFEBEE13A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FEBEE13A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FEBEE13A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FEBEE13A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FEBEE13A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FEBEE13A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FEBEE13A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN ULONG CompletionKey,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN NTSTATUS CompletionStatus,
	IN ULONG NumberOfBytesTransfered)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E065CAB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E065CAB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E065CAB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E065CAB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1E065CAB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E065CAB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E065CAB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E065CAB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E065CAB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E065CAB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	IN HANDLE IoCompletionPacketHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x56AD6516 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x56AD6516 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x56AD6516 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x56AD6516 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_56AD6516: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_56AD6516 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_56AD6516] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_56AD6516 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_56AD6516: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_56AD6516: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetLdtEntries(
	IN ULONG Selector0,
	IN ULONG Entry0Low,
	IN ULONG Entry0Hi,
	IN ULONG Selector1,
	IN ULONG Entry1Low,
	IN ULONG Entry1Hi)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDD1F86D4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDD1F86D4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDD1F86D4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDD1F86D4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_DD1F86D4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DD1F86D4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DD1F86D4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DD1F86D4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DD1F86D4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DD1F86D4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetLowEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD458D0C9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD458D0C9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD458D0C9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD458D0C9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_D458D0C9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D458D0C9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D458D0C9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D458D0C9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D458D0C9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D458D0C9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetLowWaitHighEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x08B03C31 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08B03C31 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08B03C31 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08B03C31 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_08B03C31: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08B03C31 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08B03C31] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08B03C31 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08B03C31: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08B03C31: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x32E5BDF6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x32E5BDF6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x32E5BDF6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x32E5BDF6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_32E5BDF6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_32E5BDF6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_32E5BDF6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_32E5BDF6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_32E5BDF6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_32E5BDF6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformationClass,
	IN PSECURITY_DESCRIPTOR DescriptorBuffer)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE45E7C72 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE45E7C72 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE45E7C72 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE45E7C72 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_E45E7C72: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E45E7C72 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E45E7C72] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E45E7C72 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E45E7C72: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E45E7C72: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	IN PUNICODE_STRING Value)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1C9C8BA0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C9C8BA0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C9C8BA0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C9C8BA0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1C9C8BA0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C9C8BA0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C9C8BA0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C9C8BA0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C9C8BA0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C9C8BA0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	IN PVOID Value OPTIONAL,
	IN ULONG ValueLength,
	IN ULONG Attributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x073D4180 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x073D4180 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x073D4180 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x073D4180 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_073D4180: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_073D4180 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_073D4180] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_073D4180 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_073D4180: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_073D4180: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDA53E09F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDA53E09F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDA53E09F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDA53E09F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DA53E09F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DA53E09F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DA53E09F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DA53E09F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DA53E09F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DA53E09F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemPowerState(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE21CECF8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE21CECF8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE21CECF8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE21CECF8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_E21CECF8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E21CECF8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E21CECF8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E21CECF8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E21CECF8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E21CECF8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemTime(
	IN PLARGE_INTEGER SystemTime,
	OUT PLARGE_INTEGER PreviousTime OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE37D17F6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE37D17F6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE37D17F6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE37D17F6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E37D17F6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E37D17F6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E37D17F6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E37D17F6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E37D17F6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E37D17F6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetThreadExecutionState(
	IN EXECUTION_STATE ExecutionState,
	OUT PEXECUTION_STATE PreviousExecutionState)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E35448A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E35448A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E35448A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E35448A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1E35448A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E35448A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E35448A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E35448A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E35448A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E35448A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimer2(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PLARGE_INTEGER Period OPTIONAL,
	IN PT2_SET_PARAMETERS Parameters)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD05B75CC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD05B75CC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD05B75CC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD05B75CC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_D05B75CC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D05B75CC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D05B75CC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D05B75CC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D05B75CC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D05B75CC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimerEx(
	IN HANDLE TimerHandle,
	IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
	IN OUT PVOID TimerSetInformation OPTIONAL,
	IN ULONG TimerSetInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x168CDC3E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x168CDC3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x168CDC3E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x168CDC3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_168CDC3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_168CDC3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_168CDC3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_168CDC3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_168CDC3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_168CDC3E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimerResolution(
	IN ULONG DesiredResolution,
	IN BOOLEAN SetResolution,
	OUT PULONG CurrentResolution)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4ADC4A43 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4ADC4A43 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4ADC4A43 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4ADC4A43 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_4ADC4A43: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4ADC4A43 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4ADC4A43] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4ADC4A43 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4ADC4A43: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4ADC4A43: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetUuidSeed(
	IN PUCHAR Seed)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1AA38499 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1AA38499 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1AA38499 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1AA38499 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1AA38499: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1AA38499 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1AA38499] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1AA38499 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1AA38499: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1AA38499: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileSystemInformation,
	IN ULONG Length,
	IN FSINFOCLASS FileSystemInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB4313212 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB4313212 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB4313212 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB4313212 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_B4313212: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B4313212 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B4313212] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B4313212 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B4313212: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B4313212: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetWnfProcessNotificationEvent(
	IN HANDLE NotificationEvent)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA238A7A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA238A7A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA238A7A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA238A7A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A238A7A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A238A7A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A238A7A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A238A7A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A238A7A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A238A7A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtShutdownSystem(
	IN SHUTDOWN_ACTION Action)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02E05B44 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02E05B44 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02E05B44 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02E05B44 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_02E05B44: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02E05B44 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02E05B44] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02E05B44 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02E05B44: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02E05B44: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtShutdownWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN OUT PLONG PendingWorkerCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0756F830 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0756F830 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0756F830 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0756F830 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0756F830: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0756F830 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0756F830] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0756F830 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0756F830: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0756F830: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSignalAndWaitForSingleObject(
	IN HANDLE hObjectToSignal,
	IN HANDLE hObjectToWaitOn,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER dwMilliseconds OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x03212B85 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x03212B85 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x03212B85 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x03212B85 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_03212B85: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_03212B85 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_03212B85] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_03212B85 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_03212B85: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_03212B85: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSinglePhaseReject(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAB0993A4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB0993A4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB0993A4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB0993A4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_AB0993A4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB0993A4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB0993A4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB0993A4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB0993A4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB0993A4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtStartProfile(
	IN HANDLE ProfileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1495C9D0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1495C9D0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1495C9D0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1495C9D0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1495C9D0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1495C9D0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1495C9D0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1495C9D0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1495C9D0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1495C9D0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtStopProfile(
	IN HANDLE ProfileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7B38406E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7B38406E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7B38406E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7B38406E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_7B38406E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7B38406E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7B38406E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7B38406E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7B38406E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7B38406E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName,
	IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
	IN ULONG EventMask,
	OUT PLARGE_INTEGER SubscriptionId OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x62A51774 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x62A51774 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x62A51774 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x62A51774 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_62A51774: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_62A51774 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_62A51774] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_62A51774 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_62A51774: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_62A51774: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSuspendProcess(
	IN HANDLE ProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x851D8490 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x851D8490 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x851D8490 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x851D8490 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_851D8490: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_851D8490 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_851D8490] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_851D8490 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_851D8490: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_851D8490: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x684FE75D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x684FE75D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x684FE75D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x684FE75D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_684FE75D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_684FE75D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_684FE75D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_684FE75D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_684FE75D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_684FE75D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSystemDebugControl(
	IN DEBUG_CONTROL_CODE Command,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1743D515 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1743D515 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1743D515 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1743D515 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1743D515: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1743D515 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1743D515] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1743D515 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1743D515: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1743D515: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateEnclave(
	IN PVOID BaseAddress,
	IN BOOLEAN WaitForThread)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDC32E0A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC32E0A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC32E0A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC32E0A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DC32E0A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC32E0A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC32E0A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC32E0A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC32E0A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC32E0A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateJobObject(
	IN HANDLE JobHandle,
	IN NTSTATUS ExitStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4B5437AB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4B5437AB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4B5437AB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4B5437AB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4B5437AB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4B5437AB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4B5437AB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4B5437AB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4B5437AB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4B5437AB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTestAlert()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38A2313E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38A2313E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38A2313E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38A2313E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_38A2313E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38A2313E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38A2313E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38A2313E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38A2313E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38A2313E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtThawRegistry()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0A890207 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0A890207 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0A890207 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0A890207 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_0A890207: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0A890207 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0A890207] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0A890207 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0A890207: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0A890207: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtThawTransactions()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC99E31F5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC99E31F5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC99E31F5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC99E31F5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_C99E31F5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C99E31F5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C99E31F5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C99E31F5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C99E31F5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C99E31F5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTraceControl(
	IN ULONG FunctionCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFB88292E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFB88292E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFB88292E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFB88292E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_FB88292E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FB88292E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FB88292E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FB88292E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FB88292E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FB88292E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTranslateFilePath(
	IN PFILE_PATH InputFilePath,
	IN ULONG OutputType,
	OUT PFILE_PATH OutputFilePath OPTIONAL,
	IN OUT PULONG OutputFilePathLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x942CB060 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x942CB060 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x942CB060 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x942CB060 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_942CB060: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_942CB060 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_942CB060] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_942CB060 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_942CB060: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_942CB060: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUmsThreadYield(
	IN PVOID SchedulerParam)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCB98DA2C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCB98DA2C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB98DA2C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB98DA2C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_CB98DA2C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB98DA2C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB98DA2C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB98DA2C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB98DA2C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB98DA2C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadDriver(
	IN PUNICODE_STRING DriverServiceName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF89E6BBF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF89E6BBF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF89E6BBF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF89E6BBF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_F89E6BBF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F89E6BBF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F89E6BBF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F89E6BBF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F89E6BBF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F89E6BBF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadKey(
	IN POBJECT_ATTRIBUTES DestinationKeyName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x78F24D7F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x78F24D7F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x78F24D7F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x78F24D7F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_78F24D7F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_78F24D7F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_78F24D7F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_78F24D7F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_78F24D7F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_78F24D7F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x078AC912 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x078AC912 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x078AC912 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x078AC912 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_078AC912: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_078AC912 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_078AC912] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_078AC912 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_078AC912: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_078AC912: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN HANDLE Event OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x238CF7D0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x238CF7D0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x238CF7D0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x238CF7D0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_238CF7D0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_238CF7D0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_238CF7D0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_238CF7D0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_238CF7D0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_238CF7D0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnlockFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E8E1E30 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E8E1E30 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E8E1E30 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E8E1E30 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0E8E1E30: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E8E1E30 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E8E1E30] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E8E1E30 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E8E1E30: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E8E1E30: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnlockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID * BaseAddress,
	IN PSIZE_T NumberOfBytesToUnlock,
	IN ULONG LockType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F8D050E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F8D050E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F8D050E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F8D050E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1F8D050E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F8D050E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F8D050E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F8D050E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F8D050E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F8D050E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnmapViewOfSectionEx(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E9DD1CA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E9DD1CA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E9DD1CA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E9DD1CA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0E9DD1CA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E9DD1CA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E9DD1CA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E9DD1CA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E9DD1CA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E9DD1CA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnsubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB423A59A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB423A59A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB423A59A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB423A59A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_B423A59A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B423A59A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B423A59A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B423A59A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B423A59A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B423A59A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUpdateWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID Buffer OPTIONAL,
	IN ULONG Length OPTIONAL,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	IN WNF_CHANGE_STAMP MatchingChangeStamp,
	IN ULONG CheckStamp)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x63C3F7F7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x63C3F7F7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63C3F7F7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63C3F7F7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_63C3F7F7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63C3F7F7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63C3F7F7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63C3F7F7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63C3F7F7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63C3F7F7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtVdmControl(
	IN VDMSERVICECLASS Service,
	IN OUT PVOID ServiceData)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4D919FD7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4D919FD7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4D919FD7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4D919FD7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4D919FD7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4D919FD7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4D919FD7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4D919FD7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4D919FD7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4D919FD7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForAlertByThreadId(
	IN HANDLE Handle,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE0B0FE0A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE0B0FE0A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE0B0FE0A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE0B0FE0A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E0B0FE0A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E0B0FE0A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E0B0FE0A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E0B0FE0A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E0B0FE0A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E0B0FE0A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PVOID WaitStateChange)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7EB8ACFE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7EB8ACFE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7EB8ACFE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7EB8ACFE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_7EB8ACFE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7EB8ACFE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7EB8ACFE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7EB8ACFE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7EB8ACFE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7EB8ACFE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID Key,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB0339BA4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB0339BA4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB0339BA4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB0339BA4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_B0339BA4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B0339BA4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B0339BA4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B0339BA4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B0339BA4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B0339BA4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForWorkViaWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	OUT PVOID MiniPacket)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x584374E6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x584374E6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x584374E6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x584374E6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_584374E6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_584374E6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_584374E6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_584374E6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_584374E6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_584374E6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitHighEventPair(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x44D3989D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x44D3989D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x44D3989D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x44D3989D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_44D3989D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_44D3989D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_44D3989D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_44D3989D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_44D3989D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_44D3989D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitLowEventPair(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAE304429 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAE304429 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAE304429 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAE304429 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AE304429: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AE304429 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AE304429] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AE304429 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AE304429: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AE304429: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAcquireCMFViewOwnership(
	OUT BOOLEAN TimeStamp,
	OUT BOOLEAN TokenTaken,
	IN BOOLEAN ReplaceExisting)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x37AC3D37 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x37AC3D37 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x37AC3D37 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x37AC3D37 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_37AC3D37: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_37AC3D37 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_37AC3D37] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_37AC3D37 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_37AC3D37: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_37AC3D37: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelDeviceWakeupRequest(
	IN HANDLE DeviceHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC06F3903 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC06F3903 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC06F3903 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC06F3903 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C06F3903: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C06F3903 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C06F3903] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C06F3903 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C06F3903: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C06F3903: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClearAllSavepointsTransaction(
	IN HANDLE TransactionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00A8263D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00A8263D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00A8263D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00A8263D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_00A8263D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00A8263D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00A8263D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00A8263D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00A8263D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00A8263D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClearSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1254F104 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1254F104 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1254F104 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1254F104 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1254F104: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1254F104 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1254F104] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1254F104 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1254F104: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1254F104: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x98D0764C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x98D0764C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x98D0764C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x98D0764C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_98D0764C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_98D0764C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_98D0764C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_98D0764C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_98D0764C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_98D0764C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Flag,
	OUT ULONG SavePointId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFC6FE6C3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFC6FE6C3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFC6FE6C3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFC6FE6C3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FC6FE6C3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FC6FE6C3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FC6FE6C3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FC6FE6C3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FC6FE6C3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FC6FE6C3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSavepointComplete(
	IN HANDLE TransactionHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF4A913E5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF4A913E5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF4A913E5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF4A913E5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F4A913E5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F4A913E5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F4A913E5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F4A913E5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F4A913E5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F4A913E5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSectionEx(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL,
	IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
	IN ULONG ExtendedParametersCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x44D28997 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x44D28997 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x44D28997 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x44D28997 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_44D28997: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_44D28997 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_44D28997] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_44D28997 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_44D28997: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_44D28997: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateCrossVmEvent()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4370FB5C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4370FB5C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4370FB5C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4370FB5C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_4370FB5C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4370FB5C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4370FB5C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4370FB5C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4370FB5C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4370FB5C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetPlugPlayEvent(
	IN HANDLE EventHandle,
	IN PVOID Context OPTIONAL,
	OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
	IN ULONG EventBufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x48AB2B5C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48AB2B5C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x48AB2B5C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x48AB2B5C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_48AB2B5C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_48AB2B5C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_48AB2B5C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_48AB2B5C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_48AB2B5C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_48AB2B5C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtListTransactions()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x015625FD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x015625FD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x015625FD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x015625FD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_015625FD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_015625FD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_015625FD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_015625FD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_015625FD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_015625FD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMarshallTransaction()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3690283D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3690283D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3690283D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3690283D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_3690283D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3690283D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3690283D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3690283D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3690283D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3690283D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPullTransaction()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x104CD01F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x104CD01F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x104CD01F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x104CD01F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_104CD01F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_104CD01F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_104CD01F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_104CD01F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_104CD01F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_104CD01F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseCMFViewOwnership()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1A8D021A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A8D021A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1A8D021A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1A8D021A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_1A8D021A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1A8D021A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1A8D021A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1A8D021A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1A8D021A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1A8D021A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForWnfNotifications()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC7D72744 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC7D72744 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC7D72744 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC7D72744 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_C7D72744: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C7D72744 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C7D72744] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C7D72744 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C7D72744: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C7D72744: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtStartTm()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0585C7BA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0585C7BA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0585C7BA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0585C7BA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_0585C7BA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0585C7BA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0585C7BA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0585C7BA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0585C7BA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0585C7BA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x832D88B2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x832D88B2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x832D88B2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x832D88B2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_832D88B2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_832D88B2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_832D88B2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_832D88B2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_832D88B2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_832D88B2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestDeviceWakeup(
	IN HANDLE DeviceHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7FE41B70 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7FE41B70 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7FE41B70 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7FE41B70 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_7FE41B70: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7FE41B70 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7FE41B70] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7FE41B70 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7FE41B70: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7FE41B70: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestWakeupLatency(
	IN ULONG LatencyTime)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x889B66CF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x889B66CF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x889B66CF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x889B66CF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_889B66CF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_889B66CF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_889B66CF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_889B66CF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_889B66CF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_889B66CF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x28B12711 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x28B12711 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x28B12711 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x28B12711 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_28B12711: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_28B12711 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_28B12711] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_28B12711 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_28B12711: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_28B12711: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtManageHotPatch(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x70AC7C18 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x70AC7C18 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x70AC7C18 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x70AC7C18 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_70AC7C18: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_70AC7C18 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_70AC7C18] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_70AC7C18 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_70AC7C18: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_70AC7C18: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtContinueEx(
	IN PCONTEXT ContextRecord,
	IN PKCONTINUE_ARGUMENT ContinueArgument)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x938AC756 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x938AC756 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x938AC756 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x938AC756 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_938AC756: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_938AC756 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_938AC756] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_938AC756 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_938AC756: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_938AC756: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

#endif