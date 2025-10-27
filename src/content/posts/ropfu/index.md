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

I give up today because my back bones are gone because of this. I will have to see a doctor soon. I will come back tomorrow. (I spent 7-8 hours)

## Exploit
```python

```