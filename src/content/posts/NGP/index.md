---
title: NGP
published: 2025-10-20
description: NGP - Native Gadget Programming | New Shellcode Execution Method
tags: [research, malware, shellcode, c, python]
category: Malware Research
draft: false
lang: en
---

# NGP - Native Gadget Programming | New Shellcode Execution Method

## Youtube
<iframe width="100%" height="468" src="https://youtu.be/1r0l6spXKCI" title="YouTube video player" frameborder="0" allowfullscreen></iframe>

## GitHub Repo
::github{repo="therustymate/NGP"}

## NGP PoC
The NGP repository contains **ngp.py** (a shellcode compiler) and **NGP Dropper.cpp** (a shellcode loader).

`ngp.py` scans all EXE, DLL, and SYS files inside a user-specified folder and searches those files for so-called “gadgets” — chunks that match parts of the shellcode. Using these, the shellcode loader avoids containing the actual shellcode; it instead automatically loads those gadgets (or chunks) so as to evade static analysis by AV software.

Below is how to produce actual shellcode metadata.

1. First, generate and save the shellcode you plan to load using `msfvenom` or another C2 framework (Havoc, Mythic, etc.).
2. If you are not using a Windows host, copy random DLL, EXE, and SYS files from a Windows system into a specific directory, or run the compiler inside a Windows VM. On Windows you can use the System32 folder or other third-party programs.
3. Compile the shellcode into metadata with `ngp.py` using a command like:
   `python3 ngp.py -t "shellcode.bin" -p "C:\Windows\System32" -o "output.json"`.
   Here `shellcode.bin` should be the binary shellcode produced by an external C2 framework. `C:\Windows\System32` can be replaced with another folder. The `-o` option specifies where to save the output.
4. If the hash of the original shellcode matches the hash in the metadata, you have successfully generated shellcode metadata. Now compile `NGP Dropper.cpp` and provide the output JSON file as an argument to the binary — it will regenerate the shellcode automatically.

The NGP compiler is highly sensitive to program versions. If the version of the files used by the metadata changes, it may fail to work correctly. However, this also forces a malware analyst to analyze 100% identical file versions in order to fully analyze the malware.

So far, we successfully mapped the default Meterpreter shellcode produced by `msfvenom` into System32, and tested memory loading and hooking successfully. In theory, DLL files can also be mapped in addition to shellcode. Finally, we successfully generated shellcode metadata using an unspecified version of WeChat. This experimentally demonstrates that gadgets from system files as well as from other third-party software can be used to load shellcode.