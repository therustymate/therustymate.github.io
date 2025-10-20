---
title: MAL-250610-01-01
published: 2025-06-10
description: QuasarRAT
tags: [analysis, csharp, dotnet]
category: Malware Analysis
draft: false
lang: en
---

::github{repo="therustymate/Malware-Analysis"}

# MAL-250610-01-01

| Metadata           | Information                 |
|:-------------------|:----------------------------|
| Report ID          | MAL-250610-01-01            |
| Incident Date      | Unknown                     |
| Report Date        | 2025-06/10                  |
| Malware Name       | QuasarRAT                   |
| Version            | 01                          |
| Analyst            | @therustymate               |
| Organization       | Private                     |
| Severity           | Critical                    |
| Status             | Public/Draft                |
| Malware Type       | RAT                         |
| Detection Date     | 2025-06-10 00:20:15 UTC     |
| Affected Systems   | Windows/Home                |
| CVE                | N/A                         |
| Tags               | Backdoor                    |

## Incident Metadata
| Metadata                      | Information                                               |
|:------------------------------|:----------------------------------------------------------|
| Command & Control (C2) Server | 185.244.29[.]181:1604                                     |
| Indicators of Compromise      | 185.244.29[.]181:1604                                     |
| Infection Vector              | Download                                                  |
| Persistence Mechanisms        | NYA                                                       |
| Payload Description           | Backdoor                                                  |
| Network Behavior              | C2 Connection & Communcation                              |

## File Names
| File Name                                 | Size          |
|:------------------------------------------|:--------------|
| edf5ee6173907a5c75650016186ea5a8.exe      | 514'048 bytes |

## Hashes
| File Name                             | Hash Type   | Hash                                                              |
|:--------------------------------------|:------------|:------------------------------------------------------------------|
| edf5ee6173907a5c75650016186ea5a8.exe  | MD5         | edf5ee6173907a5c75650016186ea5a8 |
|                                       | SHA1        | 8dabd536d13a57364812eb9c8d413c50b8788b8e |
|                                       | SHA256      | cd425ba34aa2ac7f31b6c498b09780cd7bacb7d7826cdc119fd6a35e95ee8700  |
|                                       |             |                           |

## References
**!!!WARNING!!!** Some references may not be fully reliable.
| Title                 | Link                                  |
|:----------------------|:--------------------------------------|
| MalwareBazaar         | [here](https://bazaar.abuse.ch/sample/cd425ba34aa2ac7f31b6c498b09780cd7bacb7d7826cdc119fd6a35e95ee8700/) |

# Blackbox Analysis
Anyrun URL: [https://app.any.run/tasks/7fcb71c2-1a6c-4bfd-99e1-9aaaaa2490bd](https://app.any.run/tasks/7fcb71c2-1a6c-4bfd-99e1-9aaaaa2490bd)

```x86asm
0047e7ae    int32_t _CorExeMain()
0047e7ae  return _CorExeMain() __tailcall
```

I confirmed the presence of a tailcall to `_CorExeMain()` at the program’s entry point using `Binary Ninja`.
Therefore, I will use `ILSpy` to decompile the binary.

## `csproj` File Contents

```xml
<Project Sdk="Microsoft.NET.Sdk.WindowsDesktop">
  <PropertyGroup>
    <AssemblyName>Client</AssemblyName>
    <GenerateAssemblyInfo>False</GenerateAssemblyInfo>
    <OutputType>WinExe</OutputType>
    <UseWindowsForms>True</UseWindowsForms>
    <TargetFramework>net452</TargetFramework>
  </PropertyGroup>
  <PropertyGroup>
    <LangVersion>12.0</LangVersion>
    <AllowUnsafeBlocks>True</AllowUnsafeBlocks>
  </PropertyGroup>
  <PropertyGroup>
    <ApplicationManifest>app.manifest</ApplicationManifest>
    <RootNamespace />
  </PropertyGroup>
  <ItemGroup>
    <None Remove="ILRepack.List" />
    <EmbeddedResource Include="ILRepack.List" LogicalName="ILRepack.List" />
  </ItemGroup>
  <ItemGroup>
    <Reference Include="System.Core" />
    <Reference Include="System.Xml" />
    <Reference Include="System.Security" />
    <Reference Include="System.Runtime.Serialization" />
    <Reference Include="System.Web" />
    <Reference Include="System.Management" />
    <Reference Include="System.ServiceModel" />
  </ItemGroup>
</Project>
```

| Field                             | Value                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------- |
| **Project Type**                  | .NET SDK-style Windows Forms Desktop Application                                            |
| **Target Framework**              | .NET Framework 4.5.2 (`net452`)                                                             |
| **Output Type**                   | `WinExe` (Graphical executable, no console window)                                          |
| **Assembly Name**                 | `Client`                                                                                    |
| **Language Version**              | C# 12.0                                                                                     |
| **Unsafe Code Allowed**           | Yes (`AllowUnsafeBlocks=True`)                                                              |
| **Windows Forms Enabled**         | Yes (`UseWindowsForms=True`)                                                                |
| **Auto Assembly Info Generation** | Disabled (`GenerateAssemblyInfo=False`)                                                     |
| **Manifest File**                 | `app.manifest`                                                                              |
| **Embedded Resource**             | `ILRepack.List`                                                                             |
| **Referenced Libraries**          | `System.Core`, `System.Xml`, `System.Web`, `System.Management`, `System.ServiceModel`, etc. |

## `AssemblyInfo.cs` File Contents

```cs
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Permissions;

[assembly: AssemblyDescription("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyProduct("Quasar")]
[assembly: AssemblyCopyright("Copyright © MaxXor 2020")]
[assembly: AssemblyTrademark("")]
[assembly: InternalsVisibleTo("Client.Tests")]
[assembly: ComVisible(false)]
[assembly: AssemblyFileVersion("1.4.0")]
[assembly: AssemblyTitle("Quasar Client")]
[assembly: AssemblyVersion("1.4.0.0")]
```

| Attribute              | Value                                      |
| ---------------------- | ------------------------------------------ |
| **Title**              | `Quasar Client`                            |
| **Product**            | `Quasar`                                   |
| **Company**            | *(Empty)*                                  |
| **Copyright**          | `© MaxXor 2020`                            |
| **File Version**       | `1.4.0`                                    |
| **Assembly Version**   | `1.4.0.0`                                  |
| **ComVisible**         | `false` *(not visible to COM components)*  |
| **InternalsVisibleTo** | `Client.Tests` *(likely for unit testing)* |

**MaxXor** is the original author of Quasar RAT.

## `ThisAssembly.cs` File Contents

```cs
internal sealed class ThisAssembly
{
	internal const string AssemblyVersion = "2.4.0.0";

	internal const string AssemblyFileVersion = "2.4.6.0";

	internal const string AssemblyInformationalVersion = "2.4.6+g43df102394";

	internal const string AssemblyName = "protobuf-net";

	internal const string AssemblyTitle = "protobuf-net";

	internal const string AssemblyConfiguration = "Release";

	internal const string PublicKey = "002400000480000094000000060200000024000052534131000400000100010009ed9caa457bfc205716c3d4e8b255a63ddf71c9e53b1b5f574ab6ffdba11e80ab4b50be9c46d43b75206280070ddba67bd4c830f93f0317504a76ba6a48243c36d2590695991164592767a7bbc4453b34694e31e20815a096e4483605139a32a76ec2fef196507487329c12047bf6a68bca8ee9354155f4d01daf6eec5ff6bc";

	internal const string PublicKeyToken = "257b51d87d2e4d67";

	internal const string RootNamespace = "ProtoBuf";

	private ThisAssembly()
	{
	}
}
```

| **Field**                 | **Value**                                                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| **Assembly Version**      | `2.4.0.0`                                                                                      |
| **File Version**          | `2.4.6.0`                                                                                      |
| **Informational Version** | `2.4.6+g43df102394`                                                                            |
| **Assembly Name**         | `protobuf-net`                                                                                 |
| **Title**                 | `protobuf-net`                                                                                 |
| **Configuration**         | `Release`                                                                                      |
| **Public Key**            | `002400000480000094000000060200000024000052534131000400000100010009ed9caa457bfc205716c3d4e8b255a63ddf71c9e53b1b5f574ab6ffdba11e80ab4b50be9c46d43b75206280070ddba67bd4c830f93f0317504a76ba6a48243c36d2590695991164592767a7bbc4453b34694e31e20815a096e4483605139a32a76ec2fef196507487329c12047bf6a68bca8ee9354155f4d01daf6eec5ff6bc` |
| **Public Key Token**      | `257b51d87d2e4d67`                                                                             |
| **Root Namespace**        | `ProtoBuf`                                                                                     |

## Deobfuscation
Approximately 60% of the obfuscated code has been successfully recovered. The command structure and operational behavior have now been clearly identified. Below is the confirmed command structure:

| File                          | Command                   | Action                          |
|:------------------------------|:--------------------------|:--------------------------------|
|`IMessage_ClientUninstall.cs`  | ClientUninstall           | Uninstall QuasarRAT             |
|`IMessage_CloseConnection.cs`  | CloseConnection           | Close C2 Server Connection      |
|`IMessage_GetSystemInfo.cs  `  | GetSystemInfo             | Get System Information          |
|`IMessage_Keylogger.cs      `  | Keylogger                 | Log Keystrokes                  |
|`IMessage_PasswordStealer.cs`  | PasswordStealer           | Parse Passwords from Browsers   |
|`IMessage_Process.cs        `  | Process                   | Add/Delete/Modify Processes     |
|`IMessage_Registry.cs       `  | Registry                  | Add/Delete/Modify Registry      |
|`IMessage_ReverseProxy.cs   `  | ReverseProxy              | Spawn a Reverse Proxy           |
|`IMessage_ShellExecute.cs   `  | ShellExecute              | Execute a Shell Command         |
|`IMessage_ShowMessageBox.cs `  | ShowMessageBox            | Show a Messagebox               |
|`IMessage_Shutdown.cs       `  | Shutdown                  | Shutdown the Device             |
|`IMessage_StartupItem.cs    `  | StartupItem               | Add/Delete/Modify Startup Items |
|`IMessage_VisitWebsite.cs   `  | VisitWebsite              | Open a Website Link             |

`QuasarRAT` communicates with its C2 server through an object called `IMessage`. This IMessage object encapsulates various payloads capable of performing tasks such as keylogging, command execution, and password theft.

Below is a list of the Windows API functions utilized by QuasarRAT during its operation:
| File                        | API                         | DLL                       |
|:----------------------------|:----------------------------|:--------------------------|
| `API_Windows.cs`            | LoadLibrary                 | `kernel32.dll`            |
| `API_Windows.cs`            | FreeLibrary                 | `kernel32.dll`            |
| `API_Windows.cs`            | GetProcAddress              | `kernel32.dll`            |
| `API_Windows.cs`            | QueryFullProcessImageName   | `kernel32.dll`            |
| `API_Windows.cs`            | BitBlt                      | `gdi32.dll`               |
| `API_Windows.cs`            | CreateDC                    | `gdi32.dll`               |
| `API_Windows.cs`            | DeleteDC                    | `gdi32.dll`               |
| `API_Windows.cs`            | GetLastInputInfo            | `user32.dll`              |
| `API_Windows.cs`            | SetCursorPos                | `user32.dll`              |
| `API_Windows.cs`            | SendInput                   | `user32.dll`              |
| `API_Windows.cs`            | SystemParametersInfo        | `user32.dll`              |
| `API_Windows.cs`            | PostMessage                 | `user32.dll`              |
| `API_Windows.cs`            | OpenDesktop                 | `user32.dll`              |
| `API_Windows.cs`            | CloseDesktop                | `user32.dll`              |
| `API_Windows.cs`            | EnumDesktopWindows          | `user32.dll`              |
| `API_Windows.cs`            | IsWindowVisible             | `user32.dll`              |
| `API_Windows.cs`            | GetForegroundWindow         | `user32.dll`              |
| `API_Windows.cs`            | GetWindowText               | `user32.dll`              |
| `API_Windows.cs`            | GetExtendedTcpTable         | `iphlpapi.dll`            |
| `API_Windows.cs`            | SetTcpEntry                 | `iphlpapi.dll`            |
|                             |                             |                           |
| `API_Windows_FileAPIs.cs`   | DeleteFile                  | `kernel32.dll`            |
|                             |                             |                           |
| `API_Unknown6.cs`           | UrlCanonicalize             | `shlwapi.dll`             |
| `API_Unknown6.cs`           | FileTimeToSystemTime        | `kernel32.dll`            |
| `API_Unknown6.cs`           | SystemTimeToFileTime        | `kernel32.dll`            |
| `API_Unknown6.cs`           | CompareFileTime             | `kernel32.dll`            |
| `API_Unknown6.cs`           | SHGetFileInfo               | `shell32.dll`             |
|                             |                             |                           |

Below is the list of password in applications that `QuasarRAT` is capable of parsing:

| Application Name            | File                            |
|:----------------------------|:--------------------------------|
| Chrome                      | `Parser_ChromeLoginData.cs`     |
| Opera                       | `Parser_OperaLoginData.cs`      |
| Yandex                      | `Parser_YandexLoginData.cs`     |
| Firefox                     | `Parser_FirefoxLoginData.cs`    |
| IE (Internet Explorer)      | `Parser_IELoginData.cs`         |
| FileZilla                   | `Parser_FileZillaLoginData.cs`  |
| WinSCP                      | `Parser_WinSCPLoginData.cs`     |