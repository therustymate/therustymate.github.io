---
title: MarcusHindey's Crackme protect
published: 2025-06-15
description: MarcusHindey's Crackme protect
tags: [analysis, csharp, dotnet, debug]
category: Crackmes
draft: false
lang: en
---

::github{repo="therustymate/crackmes"}

# MarcusHindey's Crackme protect

Since `ILSpy` failed to decompile the code, I will proceed with dynamic analysis using `dnSpy`.

![decompile_failed](./decompile_failed.png)

## Entry Point
Since `ILSpy` failed to fully decompile the application, a clear entry point could not be identified. Therefore, I will perform dynamic analysis using a **Windows 10 virtual machine and `dnSpy`**.

However, I was able to <u>identify a working portion of the code</u> that includes a class of the **Form** type. This confirms that the application is a `WinForms` program developed using a specific IDE. Additionally, it has been confirmed that the code involves <u>string encryption and obfuscation techniques</u>.

```cs
namespace crackme
{
    public class CrackMarcu za_002DProtect_002D9DD71ADEL2 : Form
    {
        ...
    }
}
```

## Dynamic Analysis
As a result of attempting decompilation and debugging using `dnSpy` on a Windows 10 virtual machine in `VirtualBox`, I discovered a new variable named `flag` (`bool`) that was not visible in `ILSpy`.

`CrackMarcuza-Protect-9DD71ADEL2.cs`
```cs
private void Cra...(object CrackMarc..., EventArgs CrackMa...)
{
    ...
    bool flag = CrackMarcuza-Protect-9DD71ADEL2.CrackM...
    ...
}
```

This variable stores the result of comparing the string entered by the user in `CrackMarcuza-Protect-2E9E89G659` (`TextBox`) with a value processed using the `CrackMarcuza-Protect-224C999FHE` method from the `CrackMarcuza-Protect-9DD71ADEL2` class.

```cs
bool flag = CrackMarcuza-Protect-9DD71ADEL2.CrackMarcuza-Protect-224C999FHE(
    this.CrackMarcuza-Protect-2E9E89G659.Text,
    CrackMarcuza-Protect-0L69ACE66B.CrackMarcuza-Protect-4G3C3EA4G0(
        CrackMarcuza-Protect-0L69ACE66B.VaultVM-Protect-HEA399LELD,
        CrackMarcuza-Protect-0L69ACE66B.VaultVM-Protect-DC9G166B72
    )
);
```

First, when decompiling the `CrackMarcuza-Protect-224C999FHE` function, the following code is obtained:
```cs
public static bool CrackMarcuza-Protect-224C999FHE(string A_0, string A_1)
{
    return A_0 == A_1;
}
```

This function performs a simple equality check, similar to the `Equals()` method or the `==` operator in C#. It compares `param1` (`A_0`) and `param2` (`A_1`), returning `true` if they are equal and `false` if they are not.

This means that when the actual variables are compared in memory, **the encrypted string is decrypted at runtime** before the comparison takes place, and the result is then processed accordingly.

Therefore, I will set a **breakpoint** in the function `CrackMarcuza-Protect-4G3C3EA4G0`, which processes the second argument (`A_1`), in an attempt to capture the actual flag at runtime.

```cs
public static string CrackMarcuza-Protect-4G3C3EA4G0(string A_0, int A_1)
{
    if (Assembly.GetExecutingAssembly().FullName == Assembly.GetCallingAssembly().FullName)
    {
        StringBuilder stringBuilder = new StringBuilder();
        foreach (char c in A_0)
        {
            stringBuilder.Append((char)((int)((ulong)((ushort)((short)c))) ^ A_1));
        }
        return stringBuilder.ToString(); // Breakpoint
    }
    return null;
}
```

![breakpoint](./breakpoint.png)

By inspecting the actual value returned by the `CrackMarcuza-Protect-4G3C3EA4G0` function, which returns a `StringBuilder` object, the result is as follows:

![debug_result](./debug_result.png)

It can be confirmed that the `stringBuilder` object contains the value `{m4rcuzCrack}`.

## Flag
Therefore, the final flag of this program is as follows: `m4rcuzCrack`