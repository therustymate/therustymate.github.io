---
title: NGP - Native Gadget Programming
published: 2025-10-20
description: NGP - Native Gadget Programming | New Shellcode Execution Method
tags: [research, malware, shellcode, c, python]
category: Malware Research
draft: false
lang: en
---

# NGP - Native Gadget Programming | New Shellcode Execution Method

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

## NGP Operation Principle

**NGP**, or **Native Gadget Programming**, is a novel technique designed to execute shellcode without embedding the actual shellcode within the shellcode dropper.
This technology leverages byte fragments from binaries already present on the system to **reconstruct and execute shellcode in memory**, effectively evading antivirus detection.

## Youtube
<iframe width="100%" height="468" src="https://www.youtube.com/embed/1r0l6spXKCI?si=RlLyCoK1j8hqoAE9" title="YouTube video player" frameborder="0"  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## GitHub Repo
::github{repo="therustymate/NGP"}

## NGP PoC
The NGP repository contains **ngp.py** (a shellcode compiler) and **NGP Dropper.cpp** (a shellcode loader).

`ngp.py` scans all EXE, DLL, and SYS files inside a user-specified folder and searches those files for so-called “gadgets” — chunks that match parts of the shellcode. Using these, the shellcode loader avoids containing the actual shellcode; it instead automatically loads those gadgets (or chunks) so as to evade static analysis by AV software.

Below is how to produce actual shellcode metadata.

1. First, generate and save the shellcode you plan to load using `msfvenom` or another C2 framework (Havoc, Mythic, etc.).
2. If you are not using a Windows host, copy random DLL, EXE, and SYS files from a Windows system into a specific directory, or run the compiler inside a Windows VM. On Windows you can use the System32 folder or other third-party programs.
3. Compile the shellcode into metadata with `ngp.py` using a command like:

   ```bash
   python3 ngp.py -t "shellcode.bin" -p "C:\Windows\System32" -o "output.json"
   ```
   Here `shellcode.bin` should be the binary shellcode produced by an external C2 framework. `C:\Windows\System32` can be replaced with another folder. The `-o` option specifies where to save the output.
4. If the hash of the original shellcode matches the hash in the metadata, you have successfully generated shellcode metadata. Now compile `NGP Dropper.cpp` and provide the output JSON file as an argument to the binary — it will regenerate the shellcode automatically.

The NGP compiler is highly sensitive to program versions. If the version of the files used by the metadata changes, it may fail to work correctly. However, this also forces a malware analyst to analyze 100% identical file versions in order to fully analyze the malware.

So far, we successfully mapped the default Meterpreter shellcode produced by `msfvenom` into System32, and tested memory loading and remote host connecting successfully. In theory, DLL files can also be mapped in addition to shellcode. Finally, we successfully generated shellcode metadata using an unspecified version of WeChat. This experimentally demonstrates that gadgets from system files as well as from other third-party software can be used to load shellcode.