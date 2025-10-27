from pwn import *

shellcode = asm(shellcraft.i386.linux.sh())

fp = open("shellcode.bin", "wb")
fp.write(shellcode)
fp.close()