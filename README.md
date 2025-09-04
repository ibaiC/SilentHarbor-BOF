# SilentHarbor-BOF

[SafeHarbor](https://github.com/ibaiC/SafeHarbor-BOF/) BOF enhanced with direct syscalls for EDR evasion using InlineWhispers3.

## Overview

SilentHarbor is a syscall-enabled version of the original [SafeHarbor](https://github.com/ibaiC/SafeHarbor-BOF/) BOF that bypasses userland EDR hooks by making direct system calls to the Windows kernel. This implementation uses InlineWhispers3 to convert high-level Windows API calls into their corresponding `NtXxx` syscall equivalents.

## Key Features

- **Direct syscalls** for critical APIs: `OpenProcess`, `VirtualAlloc`, `VirtualFree`, `VirtualQueryEx`, `OpenProcessToken`, `GetTokenInformation`, `CloseHandle`, and `EnumProcesses`
- **EDR evasion** by bypassing userland API hooks
- **TrustedSec BOF format** for compatibility with InlineWhispers3
- **x64 only** - simplified for modern environments

## Syscall Conversions

| Original API | Syscall Equivalent |
|--------------|-------------------|
| `OpenProcess` | `Sw3NtOpenProcess` |
| `VirtualAlloc` | `Sw3NtAllocateVirtualMemory` |
| `VirtualFree` | `Sw3NtFreeVirtualMemory` |
| `VirtualQueryEx` | `Sw3NtQueryVirtualMemory` |
| `OpenProcessToken` | `Sw3NtOpenProcessToken` |
| `GetTokenInformation` | `Sw3NtQueryInformationToken` |
| `CloseHandle` | `Sw3NtClose` |

## Building

Requires MinGW with `-masm=intel` flag for inline assembly compatibility.

```bash
make
```

## Usage

Load and execute the BOF through your C2 framework as you would any standard BOF.

## OPSEC Notes

- Bypasses userland API hooks but may still be detected by kernel-level monitoring
- Combine with other evasion techniques for maximum effectiveness
- Modern EDRs are implementing syscall detection mechanisms, this is not a one-shot holy grail

## Credits

- [InlineWhispers3](https://github.com/radman404/InlineWhispers3)
- [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
