---
title: ionchad's Simple crackme
published: 2025-06-15
description: ionchad's Simple crackme
tags: [analysis, c]
category: Crackmes
draft: false
lang: en
---

# ionchad's Simple crackme

## Entry Point
```c
int64_t main()          // Binary Ninja
void FUN_140001540()    // Ghidra
int __fastcall main()   // Hex-Rays
```

## Static Analysis
The code below displays a message box indicating success or failure based on the value of the `flag` variable:
```c
if (!flag)
{
    lpCaption = "Error";
    lpText = "Invalid License";
}
else
{
    lpCaption = "Success";
    lpText = "License Accepted!";
}

MessageBoxA(nullptr, lpText, lpCaption, MB_OK);
```

The variable `flag`, which is of type `bool`, is assigned its value in the following section of the code:
```c
if (count != possible_code_size)
    flag = 0;
else if (count)
    flag = !memcmp(possible_input_buffer, buffer2, count); // Core comparsion
else
    flag = 1;
```

As seen in the code, the variables `possible_input_buffer` and `buffer2` are compared using `memcmp()` (for readability, the variable names have been renamed).

The code below is responsible for setting the value of `possible_input_buffer`.

```c
int128_t* possible_input_buffer = possible_input_var;
```

The code below is responsible for setting the value of `possible_input_var`.
```c
int128_t* possible_input_var = sub_140001350(&possible_input_type, &possible_input_char); // Possible input (fgets, gets, etc)
```

The above function, `sub_140001350()`, is presumed to be a user input function similar to `fgets()` or `gets()`, as it appears to read input from the user.

The code below is responsible for setting the value of `buffer2`.
```c
if (var_80 > 0xf)
    buffer2 = moved_code_buffer;
```

The code below is responsible for setting the value of `moved_code_buffer`.
```c
int128_t* moved_code_buffer = s;
```

The code below is responsible for setting the value of `s`.
```c
sub_140001220(&s, &possible_code_buffer); // Possible variable data transfer (&possible_code_buffer -> &s)
```

The above function, `sub_140001220()`, is presumed to be a variable transfer function, as it appears to move the data inside the variable `possible_code_buffer` to `s`.

The code below is responsible for setting the value of `possible_code_buffer`.
```c
strncpy(&possible_code_buffer, "KIWZ", 5);
```

Therefore, the expected program flag is as follows: `KIWZ`

## Dynamic Analysis
As expected, the program operates by prompting the user to enter a license, as shown below:

![init](./init.png)

After entering `KIWZ`, a message box appeared confirming that the license was successfully accepted, as shown below.

![result](./result.png)

## Flag
Therefore, the final flag of this program is as follows: `KIWZ`